//! Proof of Stake system.
//!
//! TODO: We might need to storage both active and total validator set voting
//! power. For consensus, we only consider active validator set voting power,
//! but for other activities in which inactive validators can participate (e.g.
//! voting on a protocol parameter changes, upgrades, default VP changes) we
//! should use the total validator set voting power.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

pub mod btree_set;
pub mod epoched;
pub mod epoched_new;
pub mod parameters;
pub mod storage;
pub mod types;
pub mod validation;

#[cfg(test)]
mod tests;

use core::fmt::Debug;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::convert::TryFrom;
use std::num::TryFromIntError;

use epoched::{
    DynEpochOffset, EpochOffset, Epoched, EpochedDelta, OffsetPipelineLen,
};
use namada_core::ledger::storage_api::collections::lazy_map::{
    NestedSubKey, SubKey,
};
use namada_core::ledger::storage_api::collections::LazyCollection;
use namada_core::ledger::storage_api::token::credit_tokens;
use namada_core::ledger::storage_api::{
    self, OptionExt, StorageRead, StorageWrite,
};
use namada_core::types::address::{self, Address, InternalAddress};
use namada_core::types::key::{common, tm_consensus_key_raw_hash};
pub use namada_core::types::storage::Epoch;
use namada_core::types::token;
use once_cell::unsync::Lazy;
use parameters::PosParams;
use rust_decimal::Decimal;
use storage::{
    bonds_for_source_prefix, get_validator_address_from_bond,
    into_tm_voting_power, num_active_validators_key, params_key,
    validator_address_raw_hash_key, validator_max_commission_rate_change_key,
    ReverseOrdTokenAmount, WeightedValidatorNew,
};
use thiserror::Error;
use types::{
    ActiveValidator, ActiveValidatorSetNew, ActiveValidatorSetsNew, Bonds,
    BondsNew, CommissionRates, CommissionRatesNew, GenesisValidator,
    InactiveValidatorSetNew, InactiveValidatorSetsNew, Position, Slash,
    SlashNew, SlashType, Slashes, SlashesNew, TotalDeltas, TotalDeltasNew,
    Unbond, UnbondNew, Unbonds, ValidatorConsensusKeys,
    ValidatorConsensusKeysNew, ValidatorDeltas, ValidatorDeltasNew,
    ValidatorPositionAddressesNew, ValidatorSet, ValidatorSetPositionsNew,
    ValidatorSetUpdate, ValidatorSets, ValidatorState, ValidatorStates,
    ValidatorStatesNew,
};

use crate::btree_set::BTreeSetShims;
use crate::types::{
    decimal_mult_i128, decimal_mult_u64, Bond, BondId, WeightedValidator,
};

/// Address of the PoS account implemented as a native VP
pub const ADDRESS: Address = Address::Internal(InternalAddress::PoS);

/// Address of the PoS slash pool account
pub const SLASH_POOL_ADDRESS: Address =
    Address::Internal(InternalAddress::PosSlashPool);

/// Address of the staking token (NAM)
pub fn staking_token_address() -> Address {
    address::nam()
}

/// Read-only part of the PoS system
pub trait PosReadOnly {
    /// Address of the PoS account
    const POS_ADDRESS: Address;

    /// Address of the staking token
    fn staking_token_address(&self) -> Address;

    /// Read PoS parameters.
    fn read_pos_params(&self) -> Result<PosParams, storage_api::Error>;
    /// Read PoS validator's consensus key (used for signing block votes).
    fn read_validator_consensus_key(
        &self,
        key: &Address,
    ) -> Result<Option<ValidatorConsensusKeys>, storage_api::Error>;
    /// Read PoS validator's state.
    fn read_validator_state(
        &self,
        key: &Address,
    ) -> Result<Option<ValidatorStates>, storage_api::Error>;
    /// Read PoS validator's total deltas of their bonds (validator self-bonds
    /// and delegations).
    fn read_validator_deltas(
        &self,
        key: &Address,
    ) -> Result<Option<ValidatorDeltas>, storage_api::Error>;

    /// Read PoS slashes applied to a validator.
    fn read_validator_slashes(
        &self,
        key: &Address,
    ) -> Result<Vec<Slash>, storage_api::Error>;
    /// Read PoS validator's commission rate for delegation rewards
    fn read_validator_commission_rate(
        &self,
        key: &Address,
    ) -> Result<Option<CommissionRates>, storage_api::Error>;
    /// Read PoS validator's maximum change in the commission rate for
    /// delegation rewards
    fn read_validator_max_commission_rate_change(
        &self,
        key: &Address,
    ) -> Result<Option<Decimal>, storage_api::Error>;
    /// Read PoS bond (validator self-bond or a delegation).
    fn read_bond(
        &self,
        key: &BondId,
    ) -> Result<Option<Bonds>, storage_api::Error>;
    /// Read PoS unbond (unbonded tokens from validator self-bond or a
    /// delegation).
    fn read_unbond(
        &self,
        key: &BondId,
    ) -> Result<Option<Unbonds>, storage_api::Error>;
    /// Read PoS validator set (active and inactive).
    fn read_validator_set(&self) -> Result<ValidatorSets, storage_api::Error>;
    /// Read PoS total deltas for all validators (active and inactive)
    fn read_total_deltas(&self) -> Result<TotalDeltas, storage_api::Error>;

    /// Check if the given address is a validator by checking that it has some
    /// state.
    fn is_validator(
        &self,
        address: &Address,
    ) -> Result<bool, storage_api::Error> {
        let state = self.read_validator_state(address)?;
        Ok(state.is_some())
    }

    /// Get the total bond amount for the given bond ID at the given epoch.
    fn bond_amount(
        &self,
        bond_id: &BondId,
        epoch: Epoch,
    ) -> Result<token::Amount, storage_api::Error> {
        // TODO new slash logic
        let slashes = self.read_validator_slashes(&bond_id.validator)?;
        // TODO apply rewards, if any
        let bonds = self.read_bond(bond_id)?;
        Ok(bonds
            .and_then(|bonds| {
                bonds.get(epoch).map(|bond| {
                    let mut total: u64 = 0;
                    // Find the sum of the bonds
                    for (start_epoch, delta) in bond.pos_deltas.into_iter() {
                        let delta: u64 = delta.into();
                        total += delta;
                        // Apply slashes if any
                        for slash in slashes.iter() {
                            if slash.epoch <= start_epoch {
                                let current_slashed =
                                    decimal_mult_u64(slash.rate, delta);
                                total -= current_slashed;
                            }
                        }
                    }
                    let neg_deltas: u64 = bond.neg_deltas.into();
                    token::Amount::from(total - neg_deltas)
                })
            })
            .unwrap_or_default())
    }

    /// Get all the validator known addresses. These validators may be in any
    /// state, e.g. active, inactive or jailed.
    fn validator_addresses(
        &self,
        epoch: Epoch,
    ) -> Result<HashSet<Address>, storage_api::Error> {
        let validator_sets = self.read_validator_set()?;
        let validator_set = validator_sets.get(epoch).unwrap();

        Ok(validator_set
            .active
            .union(&validator_set.inactive)
            .map(|validator| validator.address.clone())
            .collect())
    }

    /// Get the total stake of a validator at the given epoch or current when
    /// `None`. The total stake is a sum of validator's self-bonds and
    /// delegations to their address.
    fn validator_stake(
        &self,
        validator: &Address,
        epoch: Epoch,
    ) -> Result<token::Amount, storage_api::Error> {
        let deltas = self.read_validator_deltas(validator)?;
        let total_stake = deltas.and_then(|deltas| deltas.get(epoch)).and_then(
            |total_stake| {
                let sum: i128 = total_stake;
                let sum: u64 = sum.try_into().ok()?;
                Some(sum.into())
            },
        );
        Ok(total_stake.unwrap_or_default())
    }

    /// Get the total stake in PoS system at the given epoch or current when
    /// `None`.
    fn total_stake(
        &self,
        epoch: Epoch,
    ) -> Result<token::Amount, storage_api::Error> {
        let epoch = epoch;
        // TODO read total stake from storage once added
        self.validator_addresses(epoch)?
            .into_iter()
            .try_fold(token::Amount::default(), |acc, validator| {
                Ok(acc + self.validator_stake(&validator, epoch)?)
            })
    }
}

/// PoS system trait to be implemented in integration that can read and write
/// PoS data.
pub trait PosActions: PosReadOnly {
    /// Write PoS parameters.
    fn write_pos_params(
        &mut self,
        params: &PosParams,
    ) -> Result<(), storage_api::Error>;
    /// Write PoS validator's raw hash of its consensus key.
    fn write_validator_address_raw_hash(
        &mut self,
        address: &Address,
        consensus_key: &common::PublicKey,
    ) -> Result<(), storage_api::Error>;
    /// Write PoS validator's consensus key (used for signing block votes).
    fn write_validator_consensus_key(
        &mut self,
        key: &Address,
        value: ValidatorConsensusKeys,
    ) -> Result<(), storage_api::Error>;
    /// Write PoS validator's state.
    fn write_validator_state(
        &mut self,
        key: &Address,
        value: ValidatorStates,
    ) -> Result<(), storage_api::Error>;
    /// Write PoS validator's commission rate for delegator rewards
    fn write_validator_commission_rate(
        &mut self,
        key: &Address,
        value: CommissionRates,
    ) -> Result<(), storage_api::Error>;
    /// Write PoS validator's maximum change in the commission rate per epoch
    fn write_validator_max_commission_rate_change(
        &mut self,
        key: &Address,
        value: Decimal,
    ) -> Result<(), storage_api::Error>;
    /// Write PoS validator's total deltas of their bonds (validator self-bonds
    /// and delegations).
    fn write_validator_deltas(
        &mut self,
        key: &Address,
        value: ValidatorDeltas,
    ) -> Result<(), storage_api::Error>;

    /// Write PoS bond (validator self-bond or a delegation).
    fn write_bond(
        &mut self,
        key: &BondId,
        value: Bonds,
    ) -> Result<(), storage_api::Error>;
    /// Write PoS unbond (unbonded tokens from validator self-bond or a
    /// delegation).
    fn write_unbond(
        &mut self,
        key: &BondId,
        value: Unbonds,
    ) -> Result<(), storage_api::Error>;
    /// Write PoS validator set (active and inactive).
    fn write_validator_set(
        &mut self,
        value: ValidatorSets,
    ) -> Result<(), storage_api::Error>;
    /// Write PoS total deltas of all validators (active and inactive).
    fn write_total_deltas(
        &mut self,
        value: TotalDeltas,
    ) -> Result<(), storage_api::Error>;
    /// Delete an emptied PoS bond (validator self-bond or a delegation).
    fn delete_bond(&mut self, key: &BondId) -> Result<(), storage_api::Error>;
    /// Delete an emptied PoS unbond (unbonded tokens from validator self-bond
    /// or a delegation).
    fn delete_unbond(&mut self, key: &BondId)
    -> Result<(), storage_api::Error>;

    /// Transfer tokens from the `src` to the `dest`.
    fn transfer(
        &mut self,
        token: &Address,
        amount: token::Amount,
        src: &Address,
        dest: &Address,
    ) -> Result<(), storage_api::Error>;

    /// Attempt to update the given account to become a validator.
    fn become_validator(
        &mut self,
        address: &Address,
        consensus_key: &common::PublicKey,
        current_epoch: Epoch,
        commission_rate: Decimal,
        max_commission_rate_change: Decimal,
    ) -> Result<(), storage_api::Error> {
        let params = self.read_pos_params()?;
        let mut validator_set = self.read_validator_set()?;
        if self.is_validator(address)? {
            return Err(BecomeValidatorError::AlreadyValidator(
                address.clone(),
            )
            .into());
        }
        let consensus_key_clone = consensus_key.clone();
        let BecomeValidatorData {
            consensus_key,
            state,
            deltas,
            commission_rate,
            max_commission_rate_change,
        } = become_validator(
            &params,
            address,
            consensus_key,
            &mut validator_set,
            current_epoch,
            commission_rate,
            max_commission_rate_change,
        );
        self.write_validator_consensus_key(address, consensus_key)?;
        self.write_validator_state(address, state)?;
        self.write_validator_set(validator_set)?;
        self.write_validator_address_raw_hash(address, &consensus_key_clone)?;
        self.write_validator_deltas(address, deltas)?;
        self.write_validator_max_commission_rate_change(
            address,
            max_commission_rate_change,
        )?;

        let commission_rates =
            Epoched::init(commission_rate, current_epoch, &params);
        self.write_validator_commission_rate(address, commission_rates)?;

        // Do we need to write the total deltas of all validators?
        Ok(())
    }

    /// Self-bond tokens to a validator when `source` is `None` or equal to
    /// the `validator` address, or delegate tokens from the `source` to the
    /// `validator`.
    fn bond_tokens(
        &mut self,
        source: Option<&Address>,
        validator: &Address,
        amount: token::Amount,
        current_epoch: Epoch,
    ) -> Result<(), storage_api::Error> {
        if let Some(source) = source {
            if source != validator && self.is_validator(source)? {
                return Err(BondError::SourceMustNotBeAValidator(
                    source.clone(),
                )
                .into());
            }
        }
        let params = self.read_pos_params()?;
        let validator_state = self.read_validator_state(validator)?;
        let source = source.unwrap_or(validator);
        let bond_id = BondId {
            source: source.clone(),
            validator: validator.clone(),
        };
        let bond = self.read_bond(&bond_id)?;
        let validator_deltas = self.read_validator_deltas(validator)?;
        let mut total_deltas = self.read_total_deltas()?;
        let mut validator_set = self.read_validator_set()?;

        let BondData {
            bond,
            validator_deltas,
        } = bond_tokens(
            &params,
            validator_state,
            &bond_id,
            bond,
            amount,
            validator_deltas,
            &mut total_deltas,
            &mut validator_set,
            current_epoch,
        )?;
        self.write_bond(&bond_id, bond)?;
        self.write_validator_deltas(validator, validator_deltas)?;
        self.write_total_deltas(total_deltas)?;
        self.write_validator_set(validator_set)?;

        // Transfer the bonded tokens from the source to PoS
        self.transfer(
            &self.staking_token_address(),
            amount,
            source,
            &Self::POS_ADDRESS,
        )?;
        Ok(())
    }

    /// Unbond self-bonded tokens from a validator when `source` is `None` or
    /// equal to the `validator` address, or unbond delegated tokens from
    /// the `source` to the `validator`.
    fn unbond_tokens(
        &mut self,
        source: Option<&Address>,
        validator: &Address,
        amount: token::Amount,
        current_epoch: Epoch,
    ) -> Result<(), storage_api::Error> {
        let params = self.read_pos_params()?;
        let source = source.unwrap_or(validator);
        let bond_id = BondId {
            source: source.clone(),
            validator: validator.clone(),
        };
        let mut bond = match self.read_bond(&bond_id)? {
            Some(val) => val,
            None => return Err(UnbondError::NoBondFound.into()),
        };
        let unbond = self.read_unbond(&bond_id)?;
        let mut validator_deltas =
            self.read_validator_deltas(validator)?.ok_or_else(|| {
                UnbondError::ValidatorHasNoBonds(validator.clone())
            })?;
        let slashes = self.read_validator_slashes(validator)?;
        let mut total_deltas = self.read_total_deltas()?;
        let mut validator_set = self.read_validator_set()?;

        let UnbondData { unbond } = unbond_tokens(
            &params,
            &bond_id,
            &mut bond,
            unbond,
            amount,
            slashes,
            &mut validator_deltas,
            &mut total_deltas,
            &mut validator_set,
            current_epoch,
        )?;

        let total_bonds = bond.get_at_offset(
            current_epoch,
            DynEpochOffset::PipelineLen,
            &params,
        );
        match total_bonds {
            Some(total_bonds) if total_bonds.sum() != 0.into() => {
                self.write_bond(&bond_id, bond)?;
            }
            _ => {
                // If the bond is left empty, delete it
                self.delete_bond(&bond_id)?
            }
        }
        self.write_unbond(&bond_id, unbond)?;
        self.write_validator_deltas(validator, validator_deltas)?;
        self.write_total_deltas(total_deltas)?;
        self.write_validator_set(validator_set)?;

        Ok(())
    }

    /// Withdraw unbonded tokens from a self-bond to a validator when `source`
    /// is `None` or equal to the `validator` address, or withdraw unbonded
    /// tokens delegated to the `validator` to the `source`.
    fn withdraw_tokens(
        &mut self,
        source: Option<&Address>,
        validator: &Address,
        current_epoch: Epoch,
    ) -> Result<token::Amount, storage_api::Error> {
        let params = self.read_pos_params()?;
        let source = source.unwrap_or(validator);
        let bond_id = BondId {
            source: source.clone(),
            validator: validator.clone(),
        };

        let unbond = self.read_unbond(&bond_id)?;
        let slashes = self.read_validator_slashes(&bond_id.validator)?;

        let WithdrawData {
            unbond,
            withdrawn,
            slashed,
        } = withdraw_unbonds(
            &params,
            &bond_id,
            unbond,
            slashes,
            current_epoch,
        )?;

        let total_unbonds = unbond.get_at_offset(
            current_epoch,
            DynEpochOffset::UnbondingLen,
            &params,
        );
        match total_unbonds {
            Some(total_unbonds) if total_unbonds.sum() != 0.into() => {
                self.write_unbond(&bond_id, unbond)?;
            }
            _ => {
                // If the unbond is left empty, delete it
                self.delete_unbond(&bond_id)?
            }
        }

        // Transfer the tokens from PoS back to the source
        self.transfer(
            &self.staking_token_address(),
            withdrawn,
            &Self::POS_ADDRESS,
            source,
        )?;

        Ok(slashed)
    }

    /// Change the commission rate of a validator
    fn change_validator_commission_rate(
        &mut self,
        validator: &Address,
        new_rate: Decimal,
        current_epoch: Epoch,
    ) -> Result<(), storage_api::Error> {
        if new_rate < Decimal::ZERO {
            return Err(CommissionRateChangeError::NegativeRate(
                new_rate,
                validator.clone(),
            )
            .into());
        }

        let max_change = self
            .read_validator_max_commission_rate_change(validator)
            .map_err(|_| {
                CommissionRateChangeError::NoMaxSetInStorage(validator.clone())
            })?
            .ok_or_else(|| {
                CommissionRateChangeError::CannotRead(validator.clone())
            })?;
        let mut commission_rates =
            match self.read_validator_commission_rate(validator) {
                Ok(Some(rates)) => rates,
                _ => {
                    return Err(CommissionRateChangeError::CannotRead(
                        validator.clone(),
                    )
                    .into());
                }
            };
        let params = self.read_pos_params()?;
        let rate_at_pipeline = *commission_rates
            .get_at_offset(current_epoch, DynEpochOffset::PipelineLen, &params)
            .expect("Could not find a rate in given epoch");

        // Return early with no further changes if there is no rate change
        // instead of returning an error
        if new_rate == rate_at_pipeline {
            return Ok(());
        }

        let rate_before_pipeline = *commission_rates
            .get_at_offset(
                current_epoch,
                DynEpochOffset::PipelineLenMinusOne,
                &params,
            )
            .expect("Could not find a rate in given epoch");
        let change_from_prev = new_rate - rate_before_pipeline;
        if change_from_prev.abs() > max_change {
            return Err(CommissionRateChangeError::RateChangeTooLarge(
                change_from_prev,
                validator.clone(),
            )
            .into());
        }
        commission_rates.update_from_offset(
            |val, _epoch| {
                *val = new_rate;
            },
            current_epoch,
            DynEpochOffset::PipelineLen,
            &params,
        );
        self.write_validator_commission_rate(validator, commission_rates)
            .map_err(|_| {
                CommissionRateChangeError::CannotWrite(validator.clone())
            })?;

        Ok(())
    }
}

/// PoS system base trait for system initialization on genesis block, updating
/// the validator on a new epoch and applying slashes.
pub trait PosBase {
    /// Address of the PoS account
    const POS_ADDRESS: Address;
    /// Address of the staking token
    fn staking_token_address(&self) -> Address;
    /// Address of the slash pool, into which slashed tokens are transferred.
    const POS_SLASH_POOL_ADDRESS: Address;

    /// Read PoS parameters.
    fn read_pos_params(&self) -> PosParams;
    /// Read PoS raw hash of validator's consensus key.
    fn read_validator_address_raw_hash(
        &self,
        raw_hash: impl AsRef<str>,
    ) -> Option<Address>;
    /// Read PoS validator's consensus key (used for signing block votes).
    fn read_validator_consensus_key(
        &self,
        key: &Address,
    ) -> Option<ValidatorConsensusKeys>;
    /// Read PoS validator's state.
    fn read_validator_state(&self, key: &Address) -> Option<ValidatorStates>;
    /// Read PoS validator's total deltas of their bonds (validator self-bonds
    /// and delegations).
    fn read_validator_deltas(&self, key: &Address) -> Option<ValidatorDeltas>;

    /// Read PoS slashes applied to a validator.
    fn read_validator_slashes(&self, key: &Address) -> Slashes;
    /// Read PoS validator's commission rate
    fn read_validator_commission_rate(&self, key: &Address) -> CommissionRates;
    /// Read PoS validator's maximum commission rate change per epoch
    fn read_validator_max_commission_rate_change(
        &self,
        key: &Address,
    ) -> Decimal;
    /// Read PoS validator set (active and inactive).
    fn read_validator_set(&self) -> ValidatorSets;
    /// Read PoS total deltas of all validators (active and inactive).
    fn read_total_deltas(&self) -> TotalDeltas;
    /// Read the number of active validators.
    fn read_num_active_validators(&self) -> u64;

    /// Write PoS parameters.
    fn write_pos_params(&mut self, params: &PosParams);
    /// Write PoS validator's raw hash of its consensus key.
    fn write_validator_address_raw_hash(
        &mut self,
        address: &Address,
        consensus_key: &common::PublicKey,
    );
    /// Write PoS validator's consensus key (used for signing block votes).
    fn write_validator_consensus_key(
        &mut self,
        key: &Address,
        value: &ValidatorConsensusKeys,
    );
    /// Write PoS validator's state.
    fn write_validator_state(&mut self, key: &Address, value: &ValidatorStates);
    /// Write PoS validator's total deltas of their bonds (validator self-bonds
    /// and delegations).
    fn write_validator_deltas(
        &mut self,
        key: &Address,
        value: &ValidatorDeltas,
    );
    /// Write PoS validator's commission rate.
    fn write_validator_commission_rate(
        &mut self,
        key: &Address,
        value: &CommissionRates,
    );
    /// Write PoS validator's maximum change in the commission rate.
    fn write_validator_max_commission_rate_change(
        &mut self,
        key: &Address,
        value: &Decimal,
    );
    /// Write (append) PoS slash applied to a validator.
    fn write_validator_slash(&mut self, validator: &Address, value: Slash);
    /// Write PoS bond (validator self-bond or a delegation).
    fn write_bond(&mut self, key: &BondId, value: &Bonds);
    /// Write PoS validator set (active and inactive).
    fn write_validator_set(&mut self, value: &ValidatorSets);
    /// Write total deltas in PoS for all validators (active and inactive)
    fn write_total_deltas(&mut self, value: &TotalDeltas);
    /// Write number of active validators.
    fn write_num_active_validators(&mut self, value: &u64);

    /// Credit tokens to the `target` account. This should only be used at
    /// genesis.
    fn credit_tokens(
        &mut self,
        token: &Address,
        target: &Address,
        amount: token::Amount,
    );
    /// Transfer tokens from the `src` to the `dest`.
    fn transfer(
        &mut self,
        token: &Address,
        amount: token::Amount,
        src: &Address,
        dest: &Address,
    );

    /// Initialize the PoS system storage data in the genesis block for the
    /// given PoS parameters and initial validator set. The validators'
    /// tokens will be put into self-bonds. The given PoS parameters are written
    /// with the [`PosBase::write_pos_params`] method.
    fn init_genesis<'a>(
        &mut self,
        params: &'a PosParams,
        validators: impl Iterator<Item = &'a GenesisValidator> + Clone + 'a,
        current_epoch: Epoch,
    ) -> Result<(), GenesisError> {
        self.write_pos_params(params);

        let GenesisData {
            validators,
            validator_set,
            total_deltas,
            total_bonded_balance,
        } = init_genesis(params, validators, current_epoch)?;

        for res in validators {
            let GenesisValidatorData {
                ref address,
                consensus_key,
                commission_rate,
                max_commission_rate_change,
                state,
                deltas,
                bond: (bond_id, bond),
            } = res?;
            self.write_validator_address_raw_hash(
                address,
                consensus_key
                    .get(current_epoch)
                    .expect("Consensus key must be set"),
            );
            self.write_validator_consensus_key(address, &consensus_key);
            self.write_validator_state(address, &state);
            self.write_validator_deltas(address, &deltas);
            self.write_bond(&bond_id, &bond);
            self.write_validator_commission_rate(address, &commission_rate);
            self.write_validator_max_commission_rate_change(
                address,
                &max_commission_rate_change,
            );
        }
        self.write_validator_set(&validator_set);
        self.write_total_deltas(&total_deltas);

        // TODO: write total_staked_tokens (Amount) to storage?

        // Credit the bonded tokens to the PoS account
        self.credit_tokens(
            &self.staking_token_address(),
            &Self::POS_ADDRESS,
            total_bonded_balance,
        );
        Ok(())
    }

    /// Calls a closure on each validator update element.
    fn validator_set_update(
        &self,
        current_epoch: Epoch,
        f: impl FnMut(ValidatorSetUpdate),
    ) {
        let current_epoch: Epoch = current_epoch;
        let current_epoch_u64: u64 = current_epoch.into();
        // INVARIANT: We can only access the previous epochs data, because
        // this function is called on a beginning of a new block, before
        // anything else could be updated (in epoched data updates, the old
        // epochs data are merged with the current one).
        let previous_epoch: Option<Epoch> = if current_epoch_u64 == 0 {
            None
        } else {
            Some(Epoch::from(current_epoch_u64 - 1))
        };
        let validators = self.read_validator_set();
        let cur_validators = validators.get(current_epoch).unwrap();
        let prev_validators =
            previous_epoch.and_then(|epoch| validators.get(epoch));

        // If the validator has never been active before and it doesn't have
        // more than 0 voting power, we should not tell Tendermint to
        // update it until it does. Tendermint uses 0 voting power as a
        // way to signal that a validator has been removed from the
        // validator set, but fails if we attempt to give it a new
        // validator with 0 voting power.
        // For active validators, this would only ever happen until all the
        // validator slots are filled with non-0 voting power validators, but we
        // still need to guard against it.
        let active_validators = cur_validators.active.iter().filter_map(
            |validator: &WeightedValidator| {
                // If the validators set from previous epoch contains the same
                // validator, it means its voting power hasn't changed and hence
                // doesn't need to updated.
                if let (Some(prev_epoch), Some(prev_validators)) =
                    (previous_epoch, prev_validators)
                {
                    if prev_validators.active.contains(validator) {
                        println!(
                            "skipping validator update, still the same {}",
                            validator.address
                        );
                        return None;
                    }
                    // TODO: WILL BE DEPRECATED SO JUST PUTTING INACTIVE TO
                    // COMPILE
                    if validator.bonded_stake == 0 {
                        // If the validator was `Pending` in the previous epoch,
                        // it means that it just was just added to validator
                        // set. We have to skip it, because it's 0.
                        if let Some(state) =
                            self.read_validator_state(&validator.address)
                        {
                            if let Some(ValidatorState::Inactive) =
                                state.get(prev_epoch)
                            {
                                println!(
                                    "skipping validator update, it's new {}",
                                    validator.address
                                );
                                return None;
                            }
                        }
                    }
                }
                let consensus_key = self
                    .read_validator_consensus_key(&validator.address)
                    .unwrap()
                    .get(current_epoch)
                    .unwrap()
                    .clone();
                Some(ValidatorSetUpdate::Active(ActiveValidator {
                    consensus_key,
                    bonded_stake: validator.bonded_stake,
                }))
            },
        );
        let inactive_validators = cur_validators.inactive.iter().filter_map(
            |validator: &WeightedValidator| {
                // If the validators set from previous epoch contains the same
                // validator, it means its voting power hasn't changed and hence
                // doesn't need to updated.
                if let (Some(prev_epoch), Some(prev_validators)) =
                    (previous_epoch, prev_validators)
                {
                    if prev_validators.inactive.contains(validator) {
                        return None;
                    }
                    // TODO: WILL BE DEPRECATED SO JUST PUTTING INACTIVE TO
                    // COMPILE
                    if validator.bonded_stake == 0 {
                        // If the validator was `Pending` in the previous epoch,
                        // it means that it just was just added to validator
                        // set. We have to skip it, because it's 0.
                        if let Some(state) =
                            self.read_validator_state(&validator.address)
                        {
                            if let Some(ValidatorState::Inactive) =
                                state.get(prev_epoch)
                            {
                                return None;
                            }
                        }
                    }
                }
                let consensus_key = self
                    .read_validator_consensus_key(&validator.address)
                    .unwrap()
                    .get(current_epoch)
                    .unwrap()
                    .clone();
                Some(ValidatorSetUpdate::Deactivated(consensus_key))
            },
        );
        active_validators.chain(inactive_validators).for_each(f)
    }

    /// Apply a slash to a byzantine validator for the given evidence.
    fn slash(
        &mut self,
        params: &PosParams,
        current_epoch: Epoch,
        evidence_epoch: Epoch,
        evidence_block_height: impl Into<u64>,
        slash_type: SlashType,
        validator: &Address,
    ) -> Result<(), SlashError> {
        let evidence_epoch = evidence_epoch;
        let rate = slash_type.get_slash_rate(params);
        let validator_slash = Slash {
            epoch: evidence_epoch,
            r#type: slash_type,
            rate,
            block_height: evidence_block_height.into(),
        };

        let mut deltas =
            self.read_validator_deltas(validator).ok_or_else(|| {
                SlashError::ValidatorHasNoTotalDeltas(validator.clone())
            })?;
        let mut validator_set = self.read_validator_set();
        let mut total_deltas = self.read_total_deltas();

        let slashed_change = slash(
            params,
            current_epoch,
            validator,
            &validator_slash,
            &mut deltas,
            &mut validator_set,
            &mut total_deltas,
        )?;
        let slashed_change: i128 = slashed_change;
        let slashed_amount = u64::try_from(slashed_change)
            .map_err(|_err| SlashError::InvalidSlashChange(slashed_change))?;
        let slashed_amount = token::Amount::from(slashed_amount);

        self.write_validator_deltas(validator, &deltas);
        self.write_validator_slash(validator, validator_slash);
        self.write_validator_set(&validator_set);
        self.write_total_deltas(&total_deltas);

        // TODO: write total staked tokens (Amount) to storage?

        // Transfer the slashed tokens to the PoS slash pool
        self.transfer(
            &self.staking_token_address(),
            slashed_amount,
            &Self::POS_ADDRESS,
            &Self::POS_SLASH_POOL_ADDRESS,
        );
        Ok(())
    }
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum GenesisError {
    #[error("Voting power overflow: {0}")]
    VotingPowerOverflow(TryFromIntError),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum BecomeValidatorError {
    #[error("The given address {0} is already a validator")]
    AlreadyValidator(Address),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum BondError {
    #[error("The given address {0} is not a validator address")]
    NotAValidator(Address),
    #[error(
        "The given source address {0} is a validator address. Validators may \
         not delegate."
    )]
    SourceMustNotBeAValidator(Address),
    #[error("The given validator address {0} is inactive")]
    InactiveValidator(Address),
    #[error("Voting power overflow: {0}")]
    VotingPowerOverflow(TryFromIntError),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum UnbondError {
    #[error("No bond could be found")]
    NoBondFound,
    #[error(
        "Trying to withdraw more tokens ({0}) than the amount bonded ({0})"
    )]
    UnbondAmountGreaterThanBond(token::Amount, token::Amount),
    #[error("No bonds found for the validator {0}")]
    ValidatorHasNoBonds(Address),
    #[error("Voting power not found for the validator {0}")]
    ValidatorHasNoVotingPower(Address),
    #[error("Voting power overflow: {0}")]
    VotingPowerOverflow(TryFromIntError),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum WithdrawError {
    #[error("No unbond could be found for {0}")]
    NoUnbondFound(BondId),
    #[error("No unbond may be withdrawn yet for {0}")]
    NoWithdrawableUnbond(BondId),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum SlashError {
    #[error("The validator {0} has no total deltas value")]
    ValidatorHasNoTotalDeltas(Address),
    #[error("The validator {0} has no voting power")]
    ValidatorHasNoVotingPower(Address),
    #[error("Unexpected slash token change")]
    InvalidSlashChange(i128),
    #[error("Voting power overflow: {0}")]
    VotingPowerOverflow(TryFromIntError),
    #[error("Unexpected negative stake {0} for validator {1}")]
    NegativeStake(i128, Address),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum CommissionRateChangeError {
    #[error("Unexpected negative commission rate {0} for validator {1}")]
    NegativeRate(Decimal, Address),
    #[error("Rate change of {0} is too large for validator {1}")]
    RateChangeTooLarge(Decimal, Address),
    #[error(
        "There is no maximum rate change written in storage for validator {0}"
    )]
    NoMaxSetInStorage(Address),
    #[error("Cannot write to storage for validator {0}")]
    CannotWrite(Address),
    #[error("Cannot read storage for validator {0}")]
    CannotRead(Address),
}

struct GenesisData<Validators>
where
    Validators: Iterator<Item = Result<GenesisValidatorData, GenesisError>>,
{
    validators: Validators,
    /// Active and inactive validator sets
    validator_set: ValidatorSets,
    /// The sum of all active and inactive validators' bonded deltas
    total_deltas: TotalDeltas,
    /// The sum of all active and inactive validators' bonded tokens
    total_bonded_balance: token::Amount,
}
struct GenesisValidatorData {
    address: Address,
    consensus_key: ValidatorConsensusKeys,
    commission_rate: CommissionRates,
    max_commission_rate_change: Decimal,
    state: ValidatorStates,
    deltas: ValidatorDeltas,
    bond: (BondId, Bonds),
}

/// A function that returns genesis data created from the initial validator set.
fn init_genesis<'a>(
    params: &'a PosParams,
    validators: impl Iterator<Item = &'a GenesisValidator> + Clone + 'a,
    current_epoch: Epoch,
) -> Result<
    GenesisData<
        impl Iterator<Item = Result<GenesisValidatorData, GenesisError>> + 'a,
    >,
    GenesisError,
> {
    // Accumulate the validator set and total bonded token balance
    let mut active: BTreeSet<WeightedValidator> = BTreeSet::default();
    let mut total_bonded_delta = token::Change::default();
    let mut total_bonded_balance = token::Amount::default();
    for GenesisValidator {
        address, tokens, ..
    } in validators.clone()
    {
        total_bonded_balance += *tokens;
        // is some extra error handling needed here for casting the delta as
        // i64? (token::Change)
        let delta = token::Change::from(*tokens);
        total_bonded_delta += delta;
        active.insert(WeightedValidator {
            bonded_stake: (*tokens).into(),
            address: address.clone(),
        });
    }
    // Pop the smallest validators from the active set until its size is under
    // the limit and insert them into the inactive set
    let mut inactive: BTreeSet<WeightedValidator> = BTreeSet::default();
    while active.len() > params.max_validator_slots as usize {
        match active.pop_first_shim() {
            Some(first) => {
                inactive.insert(first);
            }
            None => break,
        }
    }
    let validator_set = ValidatorSet { active, inactive };
    let validator_set = Epoched::init_at_genesis(validator_set, current_epoch);
    let total_bonded_delta =
        EpochedDelta::init_at_genesis(total_bonded_delta, current_epoch);

    // Adapt the genesis validators data to PoS data
    let validators = validators.map(
        move |GenesisValidator {
                  address,
                  tokens,
                  consensus_key,
                  commission_rate,
                  max_commission_rate_change,
              }| {
            let consensus_key =
                Epoched::init_at_genesis(consensus_key.clone(), current_epoch);
            let commission_rate =
                Epoched::init_at_genesis(*commission_rate, current_epoch);
            // WILL BE DEPRECATED SO JUST PUTTING INACTIVE TO GET TO COMPILE
            let state = Epoched::init_at_genesis(
                ValidatorState::Inactive,
                current_epoch,
            );
            let token_delta = token::Change::from(*tokens);
            let deltas =
                EpochedDelta::init_at_genesis(token_delta, current_epoch);
            let bond_id = BondId {
                source: address.clone(),
                validator: address.clone(),
            };
            let mut pos_deltas = HashMap::default();
            pos_deltas.insert(current_epoch, *tokens);
            let bond = EpochedDelta::init_at_genesis(
                Bond {
                    pos_deltas,
                    neg_deltas: Default::default(),
                },
                current_epoch,
            );
            Ok(GenesisValidatorData {
                address: address.clone(),
                consensus_key,
                commission_rate,
                max_commission_rate_change: *max_commission_rate_change,
                state,
                deltas,
                bond: (bond_id, bond),
            })
        },
    );

    // TODO: include total_tokens here, think abt where to write to storage
    Ok(GenesisData {
        validators,
        validator_set,
        total_deltas: total_bonded_delta,
        total_bonded_balance,
    })
}

/// A function to apply a slash to byzantine validator.
#[allow(clippy::too_many_arguments)]
fn slash(
    params: &PosParams,
    current_epoch: Epoch,
    validator: &Address,
    slash: &Slash,
    validator_deltas: &mut ValidatorDeltas,
    validator_set: &mut ValidatorSets,
    total_deltas: &mut TotalDeltas,
) -> Result<token::Change, SlashError> {
    let current_stake: token::Change =
        validator_deltas.get(current_epoch).unwrap_or_default();
    if current_stake < token::Change::default() {
        return Err(SlashError::NegativeStake(
            current_stake,
            validator.clone(),
        ));
    }
    let raw_current_stake: i128 = current_stake;
    let slashed_amount: token::Change =
        decimal_mult_i128(slash.rate, raw_current_stake);
    let token_change = -slashed_amount;

    // Apply slash at pipeline offset
    let update_offset = DynEpochOffset::PipelineLen;

    // Update validator set. This has to be done before we update the
    // `validator_deltas`, because we need to look-up the validator with
    // its voting power before the change.
    update_validator_set(
        params,
        validator,
        token_change,
        update_offset,
        validator_set,
        Some(validator_deltas),
        current_epoch,
    );

    // Update validator's deltas
    validator_deltas.add_at_offset(
        token_change,
        current_epoch,
        update_offset,
        params,
    );

    // Update total deltas of all validators
    total_deltas.add_at_offset(
        token_change,
        current_epoch,
        update_offset,
        params,
    );

    Ok(slashed_amount)
}

struct BecomeValidatorData {
    consensus_key: ValidatorConsensusKeys,
    state: ValidatorStates,
    deltas: ValidatorDeltas,
    commission_rate: Decimal,
    max_commission_rate_change: Decimal,
}

/// A function that initialized data for a new validator.
fn become_validator(
    params: &PosParams,
    address: &Address,
    consensus_key: &common::PublicKey,
    validator_set: &mut ValidatorSets,
    current_epoch: Epoch,
    commission_rate: Decimal,
    max_commission_rate_change: Decimal,
) -> BecomeValidatorData {
    let consensus_key =
        Epoched::init(consensus_key.clone(), current_epoch, params);

    // WILL BE DEPRECATED BUT PUTTING A VAL HERE TO COMPILE CODE
    let state =
        Epoched::init_at_genesis(ValidatorState::Inactive, current_epoch);
    // state.set(ValidatorState::Candidate, current_epoch, params);

    let deltas = EpochedDelta::init_at_offset(
        Default::default(),
        current_epoch,
        DynEpochOffset::PipelineLen,
        params,
    );

    validator_set.update_from_offset(
        |validator_set, _epoch| {
            let validator = WeightedValidator {
                bonded_stake: 0,
                address: address.clone(),
            };
            if validator_set.active.len() < params.max_validator_slots as usize
            {
                validator_set.active.insert(validator);
            } else {
                validator_set.inactive.insert(validator);
            }
        },
        current_epoch,
        DynEpochOffset::PipelineLen,
        params,
    );

    BecomeValidatorData {
        consensus_key,
        state,
        deltas,
        commission_rate,
        max_commission_rate_change,
    }
}

struct BondData {
    pub bond: Bonds,
    pub validator_deltas: ValidatorDeltas,
}

/// Bond tokens to a validator (self-bond or delegation).
#[allow(clippy::too_many_arguments)]
fn bond_tokens(
    params: &PosParams,
    validator_state: Option<ValidatorStates>,
    bond_id: &BondId,
    current_bond: Option<Bonds>,
    amount: token::Amount,
    validator_deltas: Option<ValidatorDeltas>,
    total_deltas: &mut TotalDeltas,
    validator_set: &mut ValidatorSets,
    current_epoch: Epoch,
) -> Result<BondData, BondError> {
    // Check the validator state
    match validator_state {
        None => {
            return Err(BondError::NotAValidator(bond_id.validator.clone()));
        }
        Some(validator_state) => {
            // Check that it's not inactive anywhere from the current epoch
            // to the pipeline offset
            for epoch in
                current_epoch.iter_range(OffsetPipelineLen::value(params))
            {
                if let Some(ValidatorState::Inactive) =
                    validator_state.get(epoch)
                {
                    return Err(BondError::InactiveValidator(
                        bond_id.validator.clone(),
                    ));
                }
            }
        }
    }

    // Update or create the bond
    //
    let mut value = Bond {
        pos_deltas: HashMap::default(),
        neg_deltas: token::Amount::default(),
    };
    // Initialize the bond at the pipeline offset
    let update_offset = DynEpochOffset::PipelineLen;
    value
        .pos_deltas
        .insert(current_epoch + update_offset.value(params), amount);
    let bond = match current_bond {
        None => EpochedDelta::init_at_offset(
            value,
            current_epoch,
            update_offset,
            params,
        ),
        Some(mut bond) => {
            bond.add_at_offset(value, current_epoch, update_offset, params);
            bond
        }
    };

    // Update validator set. This has to be done before we update the
    // `validator_deltas`, because we need to look-up the validator with
    // its voting power before the change.
    let token_change = token::Change::from(amount);
    update_validator_set(
        params,
        &bond_id.validator,
        token_change,
        update_offset,
        validator_set,
        validator_deltas.as_ref(),
        current_epoch,
    );

    // Update validator's total deltas and total staked token deltas
    let delta = token::Change::from(amount);
    let validator_deltas = match validator_deltas {
        Some(mut validator_deltas) => {
            validator_deltas.add_at_offset(
                delta,
                current_epoch,
                update_offset,
                params,
            );
            validator_deltas
        }
        None => EpochedDelta::init_at_offset(
            delta,
            current_epoch,
            update_offset,
            params,
        ),
    };

    total_deltas.add_at_offset(delta, current_epoch, update_offset, params);

    Ok(BondData {
        bond,
        validator_deltas,
    })
}

struct UnbondData {
    pub unbond: Unbonds,
}

/// Unbond tokens from a validator's bond (self-bond or delegation).
#[allow(clippy::too_many_arguments)]
fn unbond_tokens(
    params: &PosParams,
    bond_id: &BondId,
    bond: &mut Bonds,
    unbond: Option<Unbonds>,
    amount: token::Amount,
    slashes: Slashes,
    validator_deltas: &mut ValidatorDeltas,
    total_deltas: &mut TotalDeltas,
    validator_set: &mut ValidatorSets,
    current_epoch: Epoch,
) -> Result<UnbondData, UnbondError> {
    // We can unbond tokens that are bonded for a future epoch (not yet
    // active), hence we check the total at the pipeline offset
    let unbondable_amount = bond
        .get_at_offset(current_epoch, DynEpochOffset::PipelineLen, params)
        .unwrap_or_default()
        .sum();
    if amount > unbondable_amount {
        return Err(UnbondError::UnbondAmountGreaterThanBond(
            amount,
            unbondable_amount,
        ));
    }

    let mut unbond = match unbond {
        Some(unbond) => unbond,
        None => EpochedDelta::init(Unbond::default(), current_epoch, params),
    };

    let update_offset = DynEpochOffset::UnbondingLen;
    let mut to_unbond = amount;
    let to_unbond = &mut to_unbond;
    let mut slashed_amount = token::Amount::default();
    // Decrement the bond deltas starting from the rightmost value (a bond in a
    // future-most epoch) until whole amount is decremented
    bond.rev_while(
        |bonds, _epoch| {
            for (epoch_start, bond_delta) in bonds.pos_deltas.iter() {
                if *to_unbond == 0.into() {
                    return true;
                }
                let mut unbonded = HashMap::default();
                let unbond_end =
                    current_epoch + update_offset.value(params) - 1;
                // We need to accumulate the slashed delta for multiple
                // slashes applicable to a bond, where
                // each slash should be calculated from
                // the delta reduced by the previous slash.
                let applied_delta = if *to_unbond > *bond_delta {
                    unbonded.insert((*epoch_start, unbond_end), *bond_delta);
                    *to_unbond -= *bond_delta;
                    *bond_delta
                } else {
                    unbonded.insert((*epoch_start, unbond_end), *to_unbond);
                    let applied_delta = *to_unbond;
                    *to_unbond = 0.into();
                    applied_delta
                };
                // Calculate how much the bond delta would be after slashing
                let mut slashed_bond_delta = applied_delta;
                for slash in &slashes {
                    if slash.epoch >= *epoch_start {
                        let raw_delta: u64 = slashed_bond_delta.into();
                        let raw_slashed_delta =
                            decimal_mult_u64(slash.rate, raw_delta);
                        let slashed_delta =
                            token::Amount::from(raw_slashed_delta);
                        slashed_bond_delta -= slashed_delta;
                    }
                }
                slashed_amount += slashed_bond_delta;

                // For each decremented bond value write a new unbond
                unbond.add(Unbond { deltas: unbonded }, current_epoch, params);
            }
            // Stop the update once all the tokens are unbonded
            *to_unbond != 0.into()
        },
        current_epoch,
        params,
    );

    bond.add_at_offset(
        Bond {
            pos_deltas: Default::default(),
            neg_deltas: amount,
        },
        current_epoch,
        update_offset,
        params,
    );

    // Update validator set. This has to be done before we update the
    // `validator_deltas`, because we need to look-up the validator with
    // its voting power before the change.
    let token_change = -token::Change::from(slashed_amount);
    update_validator_set(
        params,
        &bond_id.validator,
        token_change,
        update_offset,
        validator_set,
        Some(validator_deltas),
        current_epoch,
    );

    // Update validator's deltas
    validator_deltas.add(token_change, current_epoch, params);

    // Update the total deltas of all validators.
    // TODO: provide some error handling that was maybe here before?
    total_deltas.add(token_change, current_epoch, params);

    Ok(UnbondData { unbond })
}

/// Update validator set when a validator's receives a new bond and when its
/// bond is unbonded (self-bond or delegation).
fn update_validator_set(
    params: &PosParams,
    validator: &Address,
    token_change: token::Change,
    change_offset: DynEpochOffset,
    validator_set: &mut ValidatorSets,
    validator_deltas: Option<&ValidatorDeltas>,
    current_epoch: Epoch,
) {
    validator_set.update_from_offset(
        |validator_set, epoch| {
            // Find the validator's bonded stake at the epoch that's being
            // updated from its total deltas
            let tokens_pre = validator_deltas
                .and_then(|d| d.get(epoch))
                .unwrap_or_default();
            let tokens_post = tokens_pre + token_change;
            let tokens_pre: i128 = tokens_pre;
            let tokens_post: i128 = tokens_post;
            let tokens_pre: u64 = TryFrom::try_from(tokens_pre).unwrap();
            let tokens_post: u64 = TryFrom::try_from(tokens_post).unwrap();

            if tokens_pre != tokens_post {
                let validator_pre = WeightedValidator {
                    bonded_stake: tokens_pre,
                    address: validator.clone(),
                };
                let validator_post = WeightedValidator {
                    bonded_stake: tokens_post,
                    address: validator.clone(),
                };

                if validator_set.inactive.contains(&validator_pre) {
                    let min_active_validator =
                        validator_set.active.first_shim();
                    let min_bonded_stake = min_active_validator
                        .map(|v| v.bonded_stake)
                        .unwrap_or_default();
                    if tokens_post > min_bonded_stake {
                        let deactivate_min =
                            validator_set.active.pop_first_shim();
                        let popped =
                            validator_set.inactive.remove(&validator_pre);
                        debug_assert!(popped);
                        validator_set.active.insert(validator_post);
                        if let Some(deactivate_min) = deactivate_min {
                            validator_set.inactive.insert(deactivate_min);
                        }
                    } else {
                        validator_set.inactive.remove(&validator_pre);
                        validator_set.inactive.insert(validator_post);
                    }
                } else {
                    debug_assert!(
                        validator_set.active.contains(&validator_pre)
                    );
                    let max_inactive_validator =
                        validator_set.inactive.last_shim();
                    let max_bonded_stake = max_inactive_validator
                        .map(|v| v.bonded_stake)
                        .unwrap_or_default();
                    if tokens_post < max_bonded_stake {
                        let activate_max =
                            validator_set.inactive.pop_last_shim();
                        let popped =
                            validator_set.active.remove(&validator_pre);
                        debug_assert!(popped);
                        validator_set.inactive.insert(validator_post);
                        if let Some(activate_max) = activate_max {
                            validator_set.active.insert(activate_max);
                        }
                    } else {
                        validator_set.active.remove(&validator_pre);
                        validator_set.active.insert(validator_post);
                    }
                }
            }
        },
        current_epoch,
        change_offset,
        params,
    )
}

struct WithdrawData {
    pub unbond: Unbonds,
    pub withdrawn: token::Amount,
    pub slashed: token::Amount,
}

/// Withdraw tokens from unbonds of self-bonds or delegations.
fn withdraw_unbonds(
    params: &PosParams,
    bond_id: &BondId,
    unbond: Option<Unbonds>,
    slashes: Vec<Slash>,
    current_epoch: Epoch,
) -> Result<WithdrawData, WithdrawError> {
    let mut unbond =
        unbond.ok_or_else(|| WithdrawError::NoUnbondFound(bond_id.clone()))?;
    let withdrawable_unbond = unbond
        .get(current_epoch)
        .ok_or_else(|| WithdrawError::NoWithdrawableUnbond(bond_id.clone()))?;
    let mut slashed = token::Amount::default();
    let withdrawn_amount = withdrawable_unbond.deltas.iter().fold(
        token::Amount::default(),
        |sum, ((epoch_start, epoch_end), delta)| {
            let mut delta = *delta;
            // Check and apply slashes, if any
            for slash in &slashes {
                if slash.epoch >= *epoch_start && slash.epoch <= *epoch_end {
                    let raw_delta: u64 = delta.into();
                    let current_slashed = token::Amount::from(
                        decimal_mult_u64(slash.rate, raw_delta),
                    );
                    slashed += current_slashed;
                    delta -= current_slashed;
                }
            }
            sum + delta
        },
    );
    unbond.delete_current(current_epoch, params);
    Ok(WithdrawData {
        unbond,
        withdrawn: withdrawn_amount,
        slashed,
    })
}

// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------

impl From<BecomeValidatorError> for storage_api::Error {
    fn from(err: BecomeValidatorError) -> Self {
        Self::new(err)
    }
}

impl From<BondError> for storage_api::Error {
    fn from(err: BondError) -> Self {
        Self::new(err)
    }
}

impl From<UnbondError> for storage_api::Error {
    fn from(err: UnbondError) -> Self {
        Self::new(err)
    }
}

impl From<WithdrawError> for storage_api::Error {
    fn from(err: WithdrawError) -> Self {
        Self::new(err)
    }
}

impl From<CommissionRateChangeError> for storage_api::Error {
    fn from(err: CommissionRateChangeError) -> Self {
        Self::new(err)
    }
}

/// Get the storage handle to the epoched active validator set
pub fn active_validator_set_handle() -> ActiveValidatorSetsNew {
    let key = storage::active_validator_set_key();
    ActiveValidatorSetsNew::open(key)
}

/// Get the storage handle to the epoched inactive validator set
pub fn inactive_validator_set_handle() -> InactiveValidatorSetsNew {
    let key = storage::inactive_validator_set_key();
    InactiveValidatorSetsNew::open(key)
}

/// Get the storage handle to a PoS validator's consensus key (used for
/// signing block votes).
pub fn validator_consensus_key_handle(
    validator: &Address,
) -> ValidatorConsensusKeysNew {
    let key = storage::validator_consensus_key_key(validator);
    ValidatorConsensusKeysNew::open(key)
}

/// Get the storage handle to a PoS validator's state
pub fn validator_state_handle(validator: &Address) -> ValidatorStatesNew {
    let key = storage::validator_state_key(validator);
    ValidatorStatesNew::open(key)
}

/// Get the storage handle to a PoS validator's deltas
pub fn validator_deltas_handle(validator: &Address) -> ValidatorDeltasNew {
    let key = storage::validator_deltas_key(validator);
    ValidatorDeltasNew::open(key)
}

/// Get the storage handle to the total deltas
pub fn total_deltas_handle() -> TotalDeltasNew {
    let key = storage::total_deltas_key();
    TotalDeltasNew::open(key)
}

/// Get the storage handle to a PoS validator's commission rate
pub fn validator_commission_rate_handle(
    validator: &Address,
) -> CommissionRatesNew {
    let key = storage::validator_commission_rate_key(validator);
    CommissionRatesNew::open(key)
}

/// Get the storage handle to a bond
/// TODO: remove `get_remaining` and the unused storage (maybe just call it
/// `storage::bond_key`)
pub fn bond_handle(source: &Address, validator: &Address) -> BondsNew {
    let bond_id = BondId {
        source: source.clone(),
        validator: validator.clone(),
    };
    let key = storage::bond_key(&bond_id);
    BondsNew::open(key)
}

/// Get the storage handle to an unbond
pub fn unbond_handle(source: &Address, validator: &Address) -> UnbondNew {
    let bond_id = BondId {
        source: source.clone(),
        validator: validator.clone(),
    };
    let key = storage::unbond_key(&bond_id);
    UnbondNew::open(key)
}

/// Get the storage handle to a PoS validator's deltas
pub fn validator_set_positions_handle() -> ValidatorSetPositionsNew {
    let key = storage::validator_set_positions_key();
    ValidatorSetPositionsNew::open(key)
}

/// Get the storage handle to a PoS validator's slashes
pub fn validator_slashes_handle(validator: &Address) -> SlashesNew {
    let key = storage::validator_slashes_key(validator);
    SlashesNew::open(key)
}

/// new init genesis
pub fn init_genesis_new<S>(
    storage: &mut S,
    params: &PosParams,
    validators: impl Iterator<Item = GenesisValidator> + Clone,
    current_epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    tracing::debug!("Initializing PoS genesis");
    write_pos_params(storage, params.clone())?;

    let mut total_bonded = token::Amount::default();
    active_validator_set_handle().init(storage, current_epoch)?;
    // Initialize inactive set even if don't fill the active set
    inactive_validator_set_handle().init(storage, current_epoch)?;
    validator_set_positions_handle().init(storage, current_epoch)?;

    for GenesisValidator {
        address,
        tokens,
        consensus_key,
        commission_rate,
        max_commission_rate_change,
    } in validators
    {
        total_bonded += tokens;

        // Insert the validator into a validator set and write its epoched
        // validator data
        // TODO: ValidatorState inside of here
        insert_validator_into_validator_set(
            storage,
            params,
            &address,
            tokens,
            current_epoch,
            0,
        )?;

        // Write other validator data to storage
        write_validator_address_raw_hash(storage, &address, &consensus_key)?;
        write_validator_max_commission_rate_change(
            storage,
            &address,
            max_commission_rate_change,
        )?;
        validator_consensus_key_handle(&address).init_at_genesis(
            storage,
            consensus_key,
            current_epoch,
        )?;
        let delta = token::Change::from(tokens);
        validator_deltas_handle(&address).init_at_genesis(
            storage,
            delta,
            current_epoch,
        )?;
        bond_handle(&address, &address).init_at_genesis(
            storage,
            delta,
            current_epoch,
        )?;
        validator_commission_rate_handle(&address).init_at_genesis(
            storage,
            commission_rate,
            current_epoch,
        )?;
    }
    // Write total deltas to storage
    total_deltas_handle().init_at_genesis(
        storage,
        token::Change::from(total_bonded),
        current_epoch,
    )?;
    // Credit bonded token amount to the PoS account
    credit_tokens(storage, &staking_token_address(), &ADDRESS, total_bonded)?;
    // Copy the genesis validator set into the pipeline epoch as well
    for epoch in (current_epoch.next()).iter_range(params.pipeline_len) {
        copy_validator_sets_and_positions(
            storage,
            current_epoch,
            epoch,
            &active_validator_set_handle(),
            &inactive_validator_set_handle(),
        )?;
    }

    println!("FINISHED GENESIS\n");

    Ok(())
}

/// Read PoS parameters
pub fn read_pos_params<S>(storage: &S) -> storage_api::Result<PosParams>
where
    S: StorageRead,
{
    // let value = storage.read_bytes(&params_key())?.unwrap();
    // Ok(decode(value).unwrap())
    storage
        .read(&params_key())
        .transpose()
        .expect("PosParams should always exist in storage after genesis")
}

/// Write PoS parameters
pub fn write_pos_params<S>(
    storage: &mut S,
    params: PosParams,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = params_key();
    storage.write(&key, params)
}

/// Get the validator address given the raw hash of the Tendermint consensus key
pub fn find_validator_by_raw_hash<S>(
    storage: &S,
    raw_hash: impl AsRef<str>,
) -> storage_api::Result<Option<Address>>
where
    S: StorageRead,
{
    let key = validator_address_raw_hash_key(raw_hash);
    storage.read(&key)
}

/// Write PoS validator's address raw hash.
pub fn write_validator_address_raw_hash<S>(
    storage: &mut S,
    validator: &Address,
    consensus_key: &common::PublicKey,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let raw_hash = tm_consensus_key_raw_hash(consensus_key);
    storage.write(&validator_address_raw_hash_key(raw_hash), validator)
}

/// Read PoS validator's max commission rate change.
pub fn read_validator_max_commission_rate_change<S>(
    storage: &S,
    validator: &Address,
) -> storage_api::Result<Option<Decimal>>
where
    S: StorageRead,
{
    let key = validator_max_commission_rate_change_key(validator);
    storage.read(&key)
}

/// Write PoS validator's max commission rate change.
pub fn write_validator_max_commission_rate_change<S>(
    storage: &mut S,
    validator: &Address,
    change: Decimal,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = validator_max_commission_rate_change_key(validator);
    storage.write(&key, change)
}

/// Read number of active PoS validators.
pub fn read_num_active_validators<S>(storage: &S) -> storage_api::Result<u64>
where
    S: StorageRead,
{
    Ok(storage
        .read(&num_active_validators_key())?
        .unwrap_or_default())
}

/// Read number of active PoS validators.
pub fn write_num_active_validators<S>(
    storage: &mut S,
    new_num: u64,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = num_active_validators_key();
    storage.write(&key, new_num)
}

/// Read PoS validator's delta value.
pub fn read_validator_delta_value<S>(
    storage: &S,
    params: &PosParams,
    validator: &Address,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<Option<token::Change>>
where
    S: StorageRead,
{
    let handle = validator_deltas_handle(validator);
    handle.get_delta_val(storage, epoch, params)
}

/// Read PoS validator's stake (sum of deltas).
/// Returns `None` when the given address is not a validator address. For a
/// validator with `0` stake, this returns `Ok(token::Amount::default())`.
pub fn read_validator_stake<S>(
    storage: &S,
    params: &PosParams,
    validator: &Address,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<Option<token::Amount>>
where
    S: StorageRead,
{
    // println!("\nREAD VALIDATOR STAKE AT EPOCH {}", epoch);
    let handle = validator_deltas_handle(validator);
    let amount = handle
        .get_sum(storage, epoch, params)?
        .map(token::Amount::from_change);
    Ok(amount)
}

/// Write PoS validator's consensus key (used for signing block votes).
/// Note: for EpochedDelta, write the value to change storage by
pub fn update_validator_deltas<S>(
    storage: &mut S,
    params: &PosParams,
    validator: &Address,
    delta: token::Change,
    current_epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let handle = validator_deltas_handle(validator);
    let offset = OffsetPipelineLen::value(params);
    let val = handle
        .get_delta_val(storage, current_epoch + offset, params)?
        .unwrap_or_default();
    handle.set(storage, val + delta, current_epoch, offset)
}

/// Read PoS total stake (sum of deltas).
pub fn read_total_stake<S>(
    storage: &S,
    params: &PosParams,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead,
{
    let handle = total_deltas_handle();
    let amnt = handle
        .get_sum(storage, epoch, params)?
        .map(token::Amount::from_change)
        .unwrap_or_default();
    Ok(amnt)
}

/// Read all addresses from active validator set.
pub fn read_active_validator_set_addresses<S>(
    storage: &S,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<HashSet<Address>>
where
    S: StorageRead,
{
    active_validator_set_handle()
        .at(&epoch)
        .iter(storage)?
        .map(|res| res.map(|(_sub_key, address)| address))
        .collect()
}

/// Read all addresses from inactive validator set.
pub fn read_inactive_validator_set_addresses<S>(
    storage: &S,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<HashSet<Address>>
where
    S: StorageRead,
{
    inactive_validator_set_handle()
        .at(&epoch)
        .iter(storage)?
        .map(|res| res.map(|(_sub_key, address)| address))
        .collect()
}

/// Read all addresses from active validator set with their stake.
pub fn read_active_validator_set_addresses_with_stake<S>(
    storage: &S,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<HashSet<WeightedValidatorNew>>
where
    S: StorageRead,
{
    active_validator_set_handle()
        .at(&epoch)
        .iter(storage)?
        .map(|res| {
            res.map(
                |(
                    NestedSubKey::Data {
                        key: bonded_stake,
                        nested_sub_key: _,
                    },
                    address,
                )| {
                    WeightedValidatorNew {
                        address,
                        bonded_stake,
                    }
                },
            )
        })
        .collect()
}

/// Read all addresses from inactive validator set with their stake.
pub fn read_inactive_validator_set_addresses_with_stake<S>(
    storage: &S,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<HashSet<WeightedValidatorNew>>
where
    S: StorageRead,
{
    inactive_validator_set_handle()
        .at(&epoch)
        .iter(storage)?
        .map(|res| {
            res.map(
                |(
                    NestedSubKey::Data {
                        key: ReverseOrdTokenAmount(bonded_stake),
                        nested_sub_key: _,
                    },
                    address,
                )| {
                    WeightedValidatorNew {
                        address,
                        bonded_stake,
                    }
                },
            )
        })
        .collect()
}

/// Read all validator addresses.
pub fn read_all_validator_addresses<S>(
    storage: &S,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<HashSet<Address>>
where
    S: StorageRead,
{
    let mut addresses = read_active_validator_set_addresses(storage, epoch)?;
    let inactive_addresses =
        read_inactive_validator_set_addresses(storage, epoch)?;
    addresses.extend(inactive_addresses.into_iter());
    Ok(addresses)
}

/// Update PoS total deltas.
/// Note: for EpochedDelta, write the value to change storage by
pub fn update_total_deltas<S>(
    storage: &mut S,
    params: &PosParams,
    delta: token::Change,
    current_epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let handle = total_deltas_handle();
    let offset = OffsetPipelineLen::value(params);
    let val = handle
        .get_delta_val(storage, current_epoch + offset, params)?
        .unwrap_or_default();
    handle.set(storage, val + delta, current_epoch, offset)
}

/// Check if the provided address is a validator address
pub fn is_validator<S>(
    storage: &S,
    address: &Address,
    params: &PosParams,
    epoch: namada_core::types::storage::Epoch,
) -> storage_api::Result<bool>
where
    S: StorageRead + StorageWrite,
{
    let state = validator_state_handle(address).get(storage, epoch, params)?;
    Ok(state.is_some())
}

/// NEW: Self-bond tokens to a validator when `source` is `None` or equal to
/// the `validator` address, or delegate tokens from the `source` to the
/// `validator`.
pub fn bond_tokens_new<S>(
    storage: &mut S,
    source: Option<&Address>,
    validator: &Address,
    amount: token::Amount,
    current_epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let amount = amount.change();
    println!("BONDING TOKEN AMOUNT {}\n", amount);
    let params = read_pos_params(storage)?;
    let pipeline_epoch = current_epoch + params.pipeline_len;
    if let Some(source) = source {
        if source != validator
            && is_validator(storage, source, &params, pipeline_epoch)?
        {
            return Err(
                BondError::SourceMustNotBeAValidator(source.clone()).into()
            );
        }
    }
    // TODO: what happens if an address used to be a validator but no longer is?
    // Think if the 'get' here needs to be amended.
    let state = validator_state_handle(validator).get(
        storage,
        pipeline_epoch,
        &params,
    )?;
    if state.is_none() {
        return Err(BondError::NotAValidator(validator.clone()).into());
    }

    let validator_state_handle = validator_state_handle(validator);
    let source = source.unwrap_or(validator);
    let bond_handle = bond_handle(source, validator);

    // Check that validator is not inactive at anywhere between the current
    // epoch and pipeline offset
    for epoch in current_epoch.iter_range(params.pipeline_len) {
        if let Some(ValidatorState::Inactive) =
            validator_state_handle.get(storage, epoch, &params)?
        {
            return Err(BondError::InactiveValidator(validator.clone()).into());
        }
    }

    // Initialize or update the bond at the pipeline offset
    let offset = params.pipeline_len;
    // TODO: ensure that this method of checking if the bond exists works

    if !bond_handle.get_data_handler().is_empty(storage)? {
        println!("BOND EXISTS TO BEGIN WITH\n");
        let cur_remain = bond_handle
            .get_delta_val(storage, current_epoch + offset, &params)?
            .unwrap_or_default();
        // println!(
        //     "Bond remain at offset epoch {}: {}\n",
        //     current_epoch + offset,
        //     cur_remain
        // );
        bond_handle.set(storage, cur_remain + amount, current_epoch, offset)?;
    } else {
        println!("BOND DOESNT EXIST YET\n");
        bond_handle.init(storage, amount, current_epoch, offset)?;
    }

    println!("\nUPDATING VALIDATOR SET NOW\n");

    // Update the validator set
    update_validator_set_new(
        storage,
        &params,
        validator,
        amount,
        current_epoch,
    )?;
    println!("UPDATING VALIDATOR DELTAS NOW\n");

    // Update the validator and total deltas
    update_validator_deltas(
        storage,
        &params,
        validator,
        amount,
        current_epoch,
    )?;

    update_total_deltas(storage, &params, amount, current_epoch)?;

    // Transfer the bonded tokens from the source to PoS
    transfer_tokens(
        storage,
        &staking_token_address(),
        token::Amount::from_change(amount),
        source,
        &ADDRESS,
    )?;
    println!("END BOND_TOKENS_NEW\n");

    Ok(())
}

/// Insert the new validator into the right validator set (depending on its
/// stake)
fn insert_validator_into_validator_set<S>(
    storage: &mut S,
    params: &PosParams,
    address: &Address,
    stake: token::Amount,
    current_epoch: Epoch,
    offset: u64,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let target_epoch = current_epoch + offset;
    let active_set = &active_validator_set_handle().at(&target_epoch);
    let inactive_set = &inactive_validator_set_handle().at(&target_epoch);
    // TODO make epoched
    let num_active_validators = read_num_active_validators(storage)?;
    if num_active_validators < params.max_validator_slots {
        insert_validator_into_set(
            &active_set.at(&stake),
            storage,
            &target_epoch,
            address,
        )?;
        validator_state_handle(address).init(
            storage,
            ValidatorState::Consensus,
            current_epoch,
            offset,
        )?;
        write_num_active_validators(storage, num_active_validators + 1)?;
    } else {
        // Check to see if the current genesis validator should replace one
        // already in the active set
        let min_active_amount =
            get_min_active_validator_amount(active_set, storage)?;
        if stake > min_active_amount {
            // Swap this genesis validator in and demote the last min active
            // validator
            let min_active_handle = active_set.at(&min_active_amount);
            // Remove last min active validator
            let last_min_active_position =
                find_last_position(&min_active_handle, storage)?.expect(
                    "There must be always be at least 1 active validator",
                );
            let removed = min_active_handle
                .remove(storage, &last_min_active_position)?
                .expect("There must be always be at least 1 active validator");
            // Insert last min active validator into the inactive set
            insert_validator_into_set(
                &inactive_set.at(&min_active_amount.into()),
                storage,
                &target_epoch,
                &removed,
            )?;
            validator_state_handle(&removed).set(
                storage,
                ValidatorState::BelowCapacity,
                current_epoch,
                offset,
            )?;
            // Insert the current genesis validator into the active set
            insert_validator_into_set(
                &active_set.at(&stake),
                storage,
                &target_epoch,
                address,
            )?;
            validator_state_handle(address).init(
                storage,
                ValidatorState::Consensus,
                current_epoch,
                offset,
            )?;
            // Update and set the validator states
        } else {
            // Insert the current genesis validator into the inactive set
            insert_validator_into_set(
                &inactive_set.at(&stake.into()),
                storage,
                &target_epoch,
                address,
            )?;
            validator_state_handle(address).init(
                storage,
                ValidatorState::BelowCapacity,
                current_epoch,
                offset,
            )?;
        }
    }
    Ok(())
}

/// NEW: Update validator set when a validator receives a new bond and when
/// its bond is unbonded (self-bond or delegation).
fn update_validator_set_new<S>(
    storage: &mut S,
    params: &PosParams,
    validator: &Address,
    token_change: token::Change,
    current_epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    if token_change == 0_i128 {
        return Ok(());
    }
    let epoch = current_epoch + params.pipeline_len;
    println!(
        "Update epoch for validator set: {epoch}, validator: {validator}\n"
    );
    let active_validator_set = active_validator_set_handle();
    let inactive_validator_set = inactive_validator_set_handle();

    // Validator sets at the pipeline offset. If these are empty, then we need
    // to copy over the most recent filled validator set into this epoch first
    let active_val_handle = active_validator_set.at(&epoch);
    let inactive_val_handle = inactive_validator_set.at(&epoch);

    let tokens_pre = read_validator_stake(storage, params, validator, epoch)?
        .unwrap_or_default();

    // println!("VALIDATOR STAKE BEFORE UPDATE: {}\n", tokens_pre);

    let tokens_post = tokens_pre.change() + token_change;
    // TODO: handle overflow or negative vals perhaps with TryFrom
    let tokens_post = token::Amount::from_change(tokens_post);

    // let position =
    // validator_set_positions_handle().at(&current_epoch).get(storage,
    // validator)

    // TODO: The position is only set when the validator is in active or
    // inactive set (consensus or below_capacity in the new names, but not
    // in below_threshold set)
    let position =
        read_validator_set_position(storage, validator, epoch, params)?
            .ok_or_err_msg(
                "Validator must have a stored validator set position",
            )?;
    // dbg!(&position);
    // for ep in Epoch::default().iter_range(params.unbonding_len) {
    //     println!(
    //         "Epoch {ep}: is val set empty? {}",
    //         active_validator_set.at(&ep).is_empty(storage)?
    //     );
    // }

    let active_vals_pre = active_val_handle.at(&tokens_pre);

    if active_vals_pre.contains(storage, &position)? {
        println!("\nTARGET VALIDATOR IS ACTIVE\n");
        // It's initially active
        // let val_address = active_validator_set.get_validator(
        //     storage,
        //     epoch,
        //     &tokens_pre,
        //     &position,
        //     params,
        // )?;
        let val_address = active_vals_pre.get(storage, &position)?;
        // debug_assert!(val_address.is_some());
        assert!(val_address.is_some());

        // dbg!(active_vals_pre.is_empty(storage).unwrap());
        active_vals_pre.remove(storage, &position)?;
        // dbg!(active_vals_pre.is_empty(storage).unwrap());

        let max_inactive_validator_amount =
            get_max_inactive_validator_amount(&inactive_val_handle, storage)?;

        if tokens_post < max_inactive_validator_amount {
            println!("NEED TO SWAP VALIDATORS\n");
            // Place the validator into the inactive set and promote the
            // lowest position max inactive validator.

            // Remove the max inactive validator first
            let inactive_vals_max =
                inactive_val_handle.at(&max_inactive_validator_amount.into());
            let lowest_position =
                find_first_position(&inactive_vals_max, storage)?.unwrap();
            let removed_max_inactive =
                inactive_vals_max.remove(storage, &lowest_position)?;
            debug_assert!(removed_max_inactive.is_some());

            // Insert the previous max inactive validator into the active set
            insert_validator_into_set(
                &active_val_handle.at(&max_inactive_validator_amount),
                storage,
                &epoch,
                &removed_max_inactive.unwrap(),
            )?;
            // Insert the current validator into the inactive set
            insert_validator_into_set(
                &inactive_val_handle.at(&tokens_post.into()),
                storage,
                &epoch,
                validator,
            )?;
        } else {
            println!("VALIDATOR REMAINS IN ACTIVE SET\n");
            // The current validator should remain in the active set - place it
            // into a new position
            insert_validator_into_set(
                &active_val_handle.at(&tokens_post),
                storage,
                &epoch,
                validator,
            )?;
        }
    } else {
        // TODO: handle the new third set - below threshold

        // It's initially inactive
        let inactive_vals_pre = inactive_val_handle.at(&tokens_pre.into());
        let removed = inactive_vals_pre.remove(storage, &position)?;
        debug_assert!(removed.is_some());
        debug_assert_eq!(&removed.unwrap(), validator);

        let min_active_validator_amount =
            get_min_active_validator_amount(&active_val_handle, storage)?;

        if tokens_post > min_active_validator_amount {
            // Place the validator into the active set and demote the last
            // position min active validator to the inactive set

            // Remove the min active validator first
            let active_vals_min =
                active_val_handle.at(&min_active_validator_amount);
            let last_position_of_min_active_vals =
                find_last_position(&active_vals_min, storage)?.expect(
                    "There must be always be at least 1 active validator",
                );
            let removed_min_active = active_vals_min
                .remove(storage, &last_position_of_min_active_vals)?
                .expect("There must be always be at least 1 active validator");

            // Insert the min active validator into the inactive set
            insert_validator_into_set(
                &inactive_val_handle.at(&min_active_validator_amount.into()),
                storage,
                &epoch,
                &removed_min_active,
            )?;

            // Insert the current validator into the active set
            insert_validator_into_set(
                &active_val_handle.at(&tokens_post),
                storage,
                &epoch,
                validator,
            )?;
        } else {
            // The current validator should remain in the inactive set
            insert_validator_into_set(
                &inactive_val_handle.at(&tokens_post.into()),
                storage,
                &epoch,
                validator,
            )?;
        }
    }
    Ok(())
}

/// Validator sets and positions copying into a future epoch
/// TODO: do we need to copy positions?
pub fn copy_validator_sets_and_positions<S>(
    storage: &mut S,
    current_epoch: Epoch,
    target_epoch: Epoch,
    active_validator_set: &ActiveValidatorSetsNew,
    inactive_validator_set: &InactiveValidatorSetsNew,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    // TODO: need some logic to determine if the inactive validator set even
    // needs to be copied (it may truly be empty after having one time contained
    // validators in the past)

    let prev_epoch = target_epoch - 1;
    let (active, inactive) = (
        active_validator_set.at(&prev_epoch),
        inactive_validator_set.at(&prev_epoch),
    );
    debug_assert!(!active.is_empty(storage)?);
    // debug_assert!(!inactive.is_empty(storage)?);

    // Need to copy into memory here to avoid borrowing a ref
    // simultaneously as immutable and mutable
    let mut active_in_mem: HashMap<(token::Amount, Position), Address> =
        HashMap::new();
    let mut inactive_in_mem: HashMap<
        (ReverseOrdTokenAmount, Position),
        Address,
    > = HashMap::new();

    for val in active.iter(storage)? {
        let (
            NestedSubKey::Data {
                key: stake,
                nested_sub_key: SubKey::Data(position),
            },
            address,
        ) = val?;
        active_in_mem.insert((stake, position), address);
    }
    for val in inactive.iter(storage)? {
        let (
            NestedSubKey::Data {
                key: stake,
                nested_sub_key: SubKey::Data(position),
            },
            address,
        ) = val?;
        inactive_in_mem.insert((stake, position), address);
    }
    // dbg!(&search_epoch);
    // dbg!(&active_in_mem);

    for ((val_stake, val_position), val_address) in active_in_mem.into_iter() {
        active_validator_set
            .at(&target_epoch)
            .at(&val_stake)
            .insert(storage, val_position, val_address)?;
    }
    for ((val_stake, val_position), val_address) in inactive_in_mem.into_iter()
    {
        inactive_validator_set
            .at(&target_epoch)
            .at(&val_stake)
            .insert(storage, val_position, val_address)?;
    }

    // Copy validator positions
    let mut positions = HashMap::<Address, Position>::default();
    let positions_handle = validator_set_positions_handle().at(&prev_epoch);
    for result in positions_handle.iter(storage)? {
        let (validator, position) = result?;
        positions.insert(validator, position);
    }
    let new_positions_handle =
        validator_set_positions_handle().at(&target_epoch);
    for (validator, position) in positions {
        let prev = new_positions_handle.insert(storage, validator, position)?;
        debug_assert!(prev.is_none());
    }
    validator_set_positions_handle().set_last_update(storage, current_epoch)?;

    Ok(())
}

/// Read the position of the validator in the subset of validators that have the
/// same bonded stake. This information is held in its own epoched structure in
/// addition to being inside the validator sets.
fn read_validator_set_position<S>(
    storage: &S,
    validator: &Address,
    epoch: Epoch,
    params: &PosParams,
) -> storage_api::Result<Option<Position>>
where
    S: StorageRead,
{
    let handle = validator_set_positions_handle();
    handle.get_position(storage, &epoch, validator, params)
}

/// Find the first (lowest) position in a validator set if it is not empty
fn find_first_position<S>(
    handle: &ValidatorPositionAddressesNew,
    storage: &S,
) -> storage_api::Result<Option<Position>>
where
    S: StorageRead,
{
    let lowest_position = handle
        .iter(storage)?
        .next()
        .transpose()?
        .map(|(position, _addr)| position);
    Ok(lowest_position)
}

/// Find the last (greatest) position in a validator set if it is not empty
fn find_last_position<S>(
    handle: &ValidatorPositionAddressesNew,
    storage: &S,
) -> storage_api::Result<Option<Position>>
where
    S: StorageRead,
{
    let position = handle
        .iter(storage)?
        .last()
        .transpose()?
        .map(|(position, _addr)| position);
    Ok(position)
}

/// Find next position in a validator set or 0 if empty
fn find_next_position<S>(
    handle: &ValidatorPositionAddressesNew,
    storage: &S,
) -> storage_api::Result<Position>
where
    S: StorageRead,
{
    let position_iter = handle.iter(storage)?;
    let next = position_iter
        .last()
        .transpose()?
        .map(|(position, _address)| position.next())
        .unwrap_or_default();
    Ok(next)
}

fn get_min_active_validator_amount<S>(
    handle: &ActiveValidatorSetNew,
    storage: &S,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead,
{
    Ok(handle
        .iter(storage)?
        .next()
        .transpose()?
        .map(|(subkey, _address)| match subkey {
            NestedSubKey::Data {
                key,
                nested_sub_key: _,
            } => key,
        })
        .unwrap_or_default())
}

fn get_max_inactive_validator_amount<S>(
    handle: &InactiveValidatorSetNew,
    storage: &S,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead,
{
    Ok(handle
        .iter(storage)?
        .next()
        .transpose()?
        .map(|(subkey, _address)| match subkey {
            NestedSubKey::Data {
                key,
                nested_sub_key: _,
            } => key,
        })
        .unwrap_or_default()
        .into())
}

fn insert_validator_into_set<S>(
    handle: &ValidatorPositionAddressesNew,
    storage: &mut S,
    epoch: &Epoch,
    address: &Address,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let next_position = find_next_position(handle, storage)?;
    println!(
        "Inserting validator {} into position {:?} at epoch {}\n",
        address.clone(),
        next_position.clone(),
        epoch.clone()
    );
    handle.insert(storage, next_position, address.clone())?;
    validator_set_positions_handle().at(epoch).insert(
        storage,
        address.clone(),
        next_position,
    )?;
    Ok(())
}

/// NEW: Unbond.
pub fn unbond_tokens_new<S>(
    storage: &mut S,
    source: Option<&Address>,
    validator: &Address,
    amount: token::Amount,
    current_epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let amount = amount.change();
    println!("UNBONDING TOKEN AMOUNT {amount} at epoch {current_epoch}\n");
    let params = read_pos_params(storage)?;
    let pipeline_epoch = current_epoch + params.pipeline_len;
    println!(
        "Current validator stake at pipeline: {}",
        read_validator_stake(storage, &params, validator, pipeline_epoch)?
            .unwrap_or_default()
    );

    if let Some(source) = source {
        if source != validator
            && is_validator(storage, source, &params, pipeline_epoch)?
        {
            return Err(
                BondError::SourceMustNotBeAValidator(source.clone()).into()
            );
        }
    }
    if !is_validator(storage, validator, &params, pipeline_epoch)? {
        return Err(BondError::NotAValidator(validator.clone()).into());
    }

    // Should be able to unbond inactive validators, but we'll need to prevent
    // jailed unbonding with slashing

    // Check that validator is not inactive at anywhere between the current
    // epoch and pipeline offset
    // let validator_state_handle = validator_state_handle(validator);
    // for epoch in current_epoch.iter_range(params.pipeline_len) {
    //     if let Some(ValidatorState::Inactive) =
    //         validator_state_handle.get(storage, epoch, &params)?
    //     {
    //         return
    // Err(BondError::InactiveValidator(validator.clone()).into());     }
    // }

    let source = source.unwrap_or(validator);
    let _bond_amount_handle = bond_handle(source, validator);
    let bond_remain_handle = bond_handle(source, validator);

    // Make sure there are enough tokens left in the bond at the pipeline offset
    let pipeline_epoch = current_epoch + params.pipeline_len;
    let remaining_at_pipeline = bond_remain_handle
        .get_sum(storage, pipeline_epoch, &params)?
        .unwrap_or_default();
    if amount > remaining_at_pipeline {
        return Err(UnbondError::UnbondAmountGreaterThanBond(
            token::Amount::from_change(amount),
            token::Amount::from_change(remaining_at_pipeline),
        )
        .into());
    }

    // Iterate thru this, find non-zero delta entries starting from most recent,
    // then just start decrementing those values For every delta val that
    // gets decremented down to 0, need a unique unbond object to have a clear
    // start epoch

    // TODO: do we want to apply slashing here? (It is done here previously)

    let unbond_handle = unbond_handle(source, validator);
    let withdrawable_epoch =
        current_epoch + params.pipeline_len + params.unbonding_len;
    let mut to_decrement = token::Amount::from_change(amount);

    // We read all matched bonds into memory to do reverse iteration
    #[allow(clippy::needless_collect)]
    let bonds: Vec<Result<_, _>> = bond_remain_handle
        .get_data_handler()
        .iter(storage)?
        .collect();
    // println!("\nBonds before decrementing:");
    // for ep in Epoch::default().iter_range(params.unbonding_len * 3) {
    //     println!(
    //         "bond delta at epoch {}: {}",
    //         ep,
    //         bond_remain_handle
    //             .get_delta_val(storage, ep, &params)?
    //             .unwrap_or_default()
    //     )
    // }
    let mut bond_iter = bonds.into_iter().rev();

    // Map: { bond start epoch, (new bond value, unbond value) }
    let mut new_bond_values_map =
        HashMap::<Epoch, (token::Amount, token::Amount)>::new();

    while to_decrement > token::Amount::default() {
        let bond = bond_iter.next().transpose()?;
        if bond.is_none() {
            continue;
        }
        let (bond_epoch, bond_amnt) = bond.unwrap();
        let bond_amnt = token::Amount::from_change(bond_amnt);

        if to_decrement < bond_amnt {
            // Decrement the amount in this bond and create the unbond object
            // with amount `to_decrement` and starting epoch `bond_epoch`
            let new_bond_amnt = bond_amnt - to_decrement;
            new_bond_values_map
                .insert(bond_epoch, (new_bond_amnt, to_decrement));
            to_decrement = token::Amount::default();
        } else {
            // Set the bond remaining delta to 0 then continue decrementing
            new_bond_values_map
                .insert(bond_epoch, (token::Amount::default(), bond_amnt));
            to_decrement -= bond_amnt;
        }
    }
    drop(bond_iter);

    // Write the in-memory bond and unbond values back to storage
    for (bond_epoch, (new_bond_amnt, unbond_amnt)) in
        new_bond_values_map.into_iter()
    {
        bond_remain_handle.set(storage, new_bond_amnt.into(), bond_epoch, 0)?;
        update_unbond(
            &unbond_handle,
            storage,
            &withdrawable_epoch,
            &bond_epoch,
            unbond_amnt,
        )?;
    }

    // println!("\nBonds after decrementing:");
    // for ep in Epoch::default().iter_range(params.unbonding_len * 3) {
    //     println!(
    //         "bond delta at epoch {}: {}",
    //         ep,
    //         bond_remain_handle
    //             .get_delta_val(storage, ep, &params)?
    //             .unwrap_or_default()
    //     )
    // }

    println!("Updating validator set for unbonding");
    // Update the validator set at the pipeline offset
    update_validator_set_new(
        storage,
        &params,
        validator,
        -amount,
        current_epoch,
    )?;

    // Update the validator and total deltas at the pipeline offset
    update_validator_deltas(
        storage,
        &params,
        validator,
        -amount,
        current_epoch,
    )?;
    update_total_deltas(storage, &params, -amount, current_epoch)?;

    Ok(())
}

fn update_unbond<S>(
    handle: &UnbondNew,
    storage: &mut S,
    withdraw_epoch: &Epoch,
    start_epoch: &Epoch,
    amount: token::Amount,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let current = handle
        .at(withdraw_epoch)
        .get(storage, start_epoch)?
        .unwrap_or_default();
    handle.at(withdraw_epoch).insert(
        storage,
        *start_epoch,
        current + amount,
    )?;
    Ok(())
}

/// NEW: Initialize data for a new validator.
/// TODO: should this still happen at pipeline if it is occurring with 0 bonded
/// stake
pub fn become_validator_new<S>(
    storage: &mut S,
    params: &PosParams,
    address: &Address,
    consensus_key: &common::PublicKey,
    current_epoch: Epoch,
    commission_rate: Decimal,
    max_commission_rate_change: Decimal,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    // Non-epoched validator data
    write_validator_address_raw_hash(storage, address, consensus_key)?;
    write_validator_max_commission_rate_change(
        storage,
        address,
        max_commission_rate_change,
    )?;

    // Epoched validator data
    validator_consensus_key_handle(address).init(
        storage,
        consensus_key.clone(),
        current_epoch,
        params.pipeline_len,
    )?;
    validator_commission_rate_handle(address).init(
        storage,
        commission_rate,
        current_epoch,
        params.pipeline_len,
    )?;
    validator_deltas_handle(address).init(
        storage,
        token::Change::default(),
        current_epoch,
        params.pipeline_len,
    )?;

    let stake = token::Amount::default();

    // TODO: need to set the validator state inside of this function
    insert_validator_into_validator_set(
        storage,
        params,
        address,
        stake,
        current_epoch,
        params.pipeline_len,
    )?;
    Ok(())
}

/// NEW: Withdraw.
pub fn withdraw_tokens_new<S>(
    storage: &mut S,
    source: Option<&Address>,
    validator: &Address,
    current_epoch: Epoch,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead + StorageWrite,
{
    // println!("WITHDRAWING TOKENS IN EPOCH {current_epoch}\n");
    let params = read_pos_params(storage)?;
    let source = source.unwrap_or(validator);

    let slashes = validator_slashes_handle(validator);
    // TODO: need some error handling to determine if this unbond even exists?
    // A handle to an empty location is valid - we just won't see any data
    let unbond_handle = unbond_handle(source, validator);

    let mut slashed = token::Amount::default();
    let mut withdrawable_amount = token::Amount::default();
    let mut unbonds_to_remove: Vec<(Epoch, Epoch)> = Vec::new();
    let unbond_iter = unbond_handle.iter(storage)?;
    for unbond in unbond_iter {
        // println!("\nUNBOND ITER\n");
        let (
            NestedSubKey::Data {
                key: withdraw_epoch,
                nested_sub_key: SubKey::Data(start_epoch),
            },
            amount,
        ) = unbond?;

        // dbg!(&end_epoch, &start_epoch, amount);

        // TODO: worry about updating this later after PR 740 perhaps
        // 1. cubic slashing
        // 2. adding slash rates in same epoch, applying cumulatively in dif
        // epochs
        if withdraw_epoch > current_epoch {
            continue;
        }
        for slash in slashes.iter(storage)? {
            let SlashNew {
                epoch,
                block_height: _,
                r#type: slash_type,
            } = slash?;
            if epoch > start_epoch
                && epoch
                    < withdraw_epoch
                        .checked_sub(Epoch(params.unbonding_len))
                        .unwrap_or_default()
            {
                let slash_rate = slash_type.get_slash_rate(&params);
                let to_slash = token::Amount::from(decimal_mult_u64(
                    slash_rate,
                    u64::from(amount),
                ));
                slashed += to_slash;
            }
        }
        withdrawable_amount += amount;
        unbonds_to_remove.push((withdraw_epoch, start_epoch));
    }
    withdrawable_amount -= slashed;

    // Remove the unbond data from storage
    for (withdraw_epoch, start_epoch) in unbonds_to_remove {
        // println!("Remove ({}, {}) from unbond\n", end_epoch, start_epoch);
        unbond_handle
            .at(&withdraw_epoch)
            .remove(storage, &start_epoch)?;
        // TODO: check if the `end_epoch` layer is now empty and remove it if
        // so, may need to implement remove/delete for nested map
    }

    // Transfer the tokens from the PoS address back to the source
    transfer_tokens(
        storage,
        &staking_token_address(),
        withdrawable_amount,
        &ADDRESS,
        source,
    )?;

    Ok(withdrawable_amount)
}

/// Change the commission rate of a validator
pub fn change_validator_commission_rate_new<S>(
    storage: &mut S,
    validator: &Address,
    new_rate: Decimal,
    current_epoch: Epoch,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    if new_rate < Decimal::ZERO {
        return Err(CommissionRateChangeError::NegativeRate(
            new_rate,
            validator.clone(),
        )
        .into());
    }

    let max_change =
        read_validator_max_commission_rate_change(storage, validator)?;
    if max_change.is_none() {
        return Err(CommissionRateChangeError::NoMaxSetInStorage(
            validator.clone(),
        )
        .into());
    }

    let params = read_pos_params(storage)?;
    let commission_handle = validator_commission_rate_handle(validator);
    let pipeline_epoch = current_epoch + params.pipeline_len;

    let rate_at_pipeline = commission_handle
        .get(storage, pipeline_epoch, &params)?
        .expect("Could not find a rate in given epoch");
    if new_rate == rate_at_pipeline {
        return Ok(());
    }
    let rate_before_pipeline = commission_handle
        .get(storage, pipeline_epoch - 1, &params)?
        .expect("Could not find a rate in given epoch");
    let change_from_prev = new_rate - rate_before_pipeline;
    if change_from_prev.abs() > max_change.unwrap() {
        return Err(CommissionRateChangeError::RateChangeTooLarge(
            change_from_prev,
            validator.clone(),
        )
        .into());
    }

    commission_handle.set(storage, new_rate, current_epoch, params.pipeline_len)
}

/// NEW: apply a slash and write it to storage
pub fn slash_new<S>(
    storage: &mut S,
    params: &PosParams,
    current_epoch: Epoch,
    evidence_epoch: Epoch,
    evidence_block_height: impl Into<u64>,
    slash_type: SlashType,
    validator: &Address,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let rate = slash_type.get_slash_rate(params);
    let slash = SlashNew {
        epoch: evidence_epoch,
        block_height: evidence_block_height.into(),
        r#type: slash_type,
    };

    let current_stake =
        read_validator_stake(storage, params, validator, current_epoch)?
            .unwrap_or_default();
    let slashed_amount = decimal_mult_u64(rate, u64::from(current_stake));
    let token_change = -token::Change::from(slashed_amount);

    // Update validator sets and deltas at the pipeline length
    update_validator_set_new(
        storage,
        params,
        validator,
        token_change,
        current_epoch,
    )?;
    update_validator_deltas(
        storage,
        params,
        validator,
        token_change,
        current_epoch,
    )?;
    update_total_deltas(storage, params, token_change, current_epoch)?;

    // Write the validator slash to storage
    validator_slashes_handle(validator).push(storage, slash)?;

    // Transfer the slashed tokens from PoS account to Slash Fund address
    transfer_tokens(
        storage,
        &staking_token_address(),
        token::Amount::from(slashed_amount),
        &ADDRESS,
        &SLASH_POOL_ADDRESS,
    )?;

    Ok(())
}

// TODO: should we write a new function for PoSReadOnly::bond_amount? For the
// one place it is used in native_vp/governance/utils.rs, the usage may actually
// be properly to read the deltas than use this function

/// Transfer tokens between accounts
/// TODO: may want to move this into core crate
pub fn transfer_tokens<S>(
    storage: &mut S,
    token: &Address,
    amount: token::Amount,
    src: &Address,
    dest: &Address,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let src_key = token::balance_key(token, src);
    let dest_key = token::balance_key(token, dest);
    if let Some(mut src_balance) = storage.read::<token::Amount>(&src_key)? {
        // let mut src_balance: token::Amount =
        //     decode(src_balance).unwrap_or_default();
        if src_balance < amount {
            tracing::error!(
                "PoS system transfer error, the source doesn't have \
                 sufficient balance. It has {}, but {} is required",
                src_balance,
                amount
            );
        }
        src_balance.spend(&amount);
        let mut dest_balance = storage
            .read::<token::Amount>(&dest_key)?
            .unwrap_or_default();

        // let dest_balance = storage.read_bytes(&dest_key).unwrap_or_default();
        // let mut dest_balance: token::Amount = dest_balance
        //     .and_then(|b| decode(b).ok())
        //     .unwrap_or_default();
        dest_balance.receive(&amount);
        storage
            .write(&src_key, src_balance)
            .expect("Unable to write token balance for PoS system");
        storage
            .write(&dest_key, dest_balance)
            .expect("Unable to write token balance for PoS system");
    } else {
        tracing::error!("PoS system transfer error, the source has no balance");
    }
    Ok(())
}

/// NEW: Get the total bond amount for a given bond ID at a given epoch
pub fn bond_amount_new<S>(
    storage: &S,
    params: &PosParams,
    bond_id: &BondId,
    epoch: Epoch,
) -> storage_api::Result<(token::Amount, token::Amount)>
where
    S: StorageRead,
{
    // TODO: review this logic carefully, do cubic slashing, apply rewards
    let slashes = validator_slashes_handle(&bond_id.validator);
    let bonds =
        bond_handle(&bond_id.source, &bond_id.validator).get_data_handler();
    let mut total = token::Amount::default();
    let mut total_active = token::Amount::default();
    for next in bonds.iter(storage)? {
        let (bond_epoch, delta) = next?;
        // if bond_epoch > epoch {
        //     break;
        // }
        for slash in slashes.iter(storage)? {
            let SlashNew {
                epoch: slash_epoch,
                block_height: _,
                r#type: slash_type,
            } = slash?;
            if slash_epoch > bond_epoch {
                continue;
            }
            let current_slashed =
                decimal_mult_i128(slash_type.get_slash_rate(params), delta);
            let delta = token::Amount::from_change(delta - current_slashed);
            total += delta;
            if bond_epoch <= epoch {
                total_active += delta;
            }
        }
    }
    Ok((total, total_active))
}

/// NEW: adapting `PosBase::validator_set_update for lazy storage
pub fn validator_set_update_tendermint<S>(
    storage: &S,
    params: &PosParams,
    current_epoch: Epoch,
    f: impl FnMut(ValidatorSetUpdate),
) where
    S: StorageRead,
{
    let current_epoch: Epoch = current_epoch;
    let current_epoch_u64: u64 = current_epoch.into();

    let previous_epoch: Option<Epoch> = if current_epoch_u64 == 0 {
        None
    } else {
        Some(Epoch::from(current_epoch_u64 - 1))
    };

    let cur_active_validators =
        active_validator_set_handle().at(&current_epoch);
    let prev_active_validators = previous_epoch.map(|previous_epoch| {
        active_validator_set_handle().at(&previous_epoch)
    });

    let active_validators = cur_active_validators
        .iter(storage)
        .unwrap()
        .filter_map(|validator| {
            let (
                NestedSubKey::Data {
                    key: cur_stake,
                    nested_sub_key: _,
                },
                address,
            ) = validator.unwrap();

            println!(
                "ACTIVE VALIDATOR ADDRESS {}, CUR_STAKE {}\n",
                address, cur_stake
            );

            // Check if the validator was active in the previous epoch with the
            // same stake
            //
            // TODO: check consistency btwn here and old method
            //
            // TODO: do I need to check Pending here? (will be deprecated soon
            // anyway)
            //
            // TODO: perhaps write a specific function for
            // (In)ActiveValidatorSetsNew that checks if a validator is
            // contained
            if prev_active_validators.is_some() {
                if let Some(prev_epoch) = previous_epoch {
                    let prev_validator_state = validator_state_handle(&address)
                        .get(storage, prev_epoch, params)
                        .unwrap();
                    let prev_tm_voting_power = Lazy::new(|| {
                        let prev_validator_stake =
                            validator_deltas_handle(&address)
                                .get_sum(storage, prev_epoch, params)
                                .unwrap()
                                .map(token::Amount::from_change);
                        prev_validator_stake.map(|tokens| {
                            into_tm_voting_power(
                                params.tm_votes_per_token,
                                tokens,
                            )
                        })
                    });
                    let cur_tm_voting_power = Lazy::new(|| {
                        into_tm_voting_power(
                            params.tm_votes_per_token,
                            cur_stake,
                        )
                    });
                    if matches!(
                        prev_validator_state,
                        Some(
                            ValidatorState::Consensus
                                | ValidatorState::BelowCapacity
                        )
                    ) && *prev_tm_voting_power == Some(*cur_tm_voting_power)
                    {
                        return None;
                    }

                    if *cur_tm_voting_power == 0 {
                        // TODO: check if it's new validator or previously non-0
                        // stake
                        println!(
                            "skipping validator update, {} active but without \
                             a stake",
                            address
                        );
                        return None;
                    }
                }
            }
            println!("\nMAKING AN ACTIVE VALIDATOR CHANGE");
            let consensus_key = validator_consensus_key_handle(&address)
                .get(storage, current_epoch, params)
                .unwrap()
                .unwrap();
            Some(ValidatorSetUpdate::Active(ActiveValidator {
                consensus_key,
                bonded_stake: cur_stake.into(),
            }))
        });
    let cur_inactive_validators =
        inactive_validator_set_handle().at(&current_epoch);
    let inactive_validators = cur_inactive_validators
        .iter(storage)
        .unwrap()
        .filter_map(|validator| {
            let (
                NestedSubKey::Data {
                    key: cur_stake,
                    nested_sub_key: _,
                },
                address,
            ) = validator.unwrap();
            let cur_stake = token::Amount::from(cur_stake);

            println!(
                "INACTIVE VALIDATOR ADDRESS {}, STAKE {}\n",
                address, cur_stake
            );

            let prev_inactive_vals =
                inactive_validator_set_handle().at(&previous_epoch.unwrap());
            if !prev_inactive_vals.is_empty(storage).unwrap() {
                if let Some(prev_epoch) = previous_epoch {
                    // Check if the current validator was in the inactive set

                    // Note: don't think we should care if a validator that was
                    // and still is inactive has changed
                    // stake, since we will still tell
                    // tendermint that it is 0 stake to make it inactive. I
                    // think we were doing too much
                    // previously.
                    let prev_state = validator_state_handle(&address)
                        .get(storage, prev_epoch, params)
                        .unwrap();
                    if prev_state == Some(ValidatorState::Inactive) {
                        return None;
                    }
                    // I think that's right, but we have to check that it wasn't
                    // previously in the active set (the state is not relevant
                    // to this). It would help to have that
                    // in the storage as epoched
                    // e.g. validator_sub_set (I think you suggested we add
                    // this)

                    // TODO: this will be deprecated, but not sure if it is even
                    // needed rn
                    let cur_tm_voting_power = into_tm_voting_power(
                        params.tm_votes_per_token,
                        cur_stake,
                    );
                    if cur_tm_voting_power == 0 {
                        // TODO: check if it's new validator or previously non-0
                        // stake after `Pending` state is
                        // removed

                        // let state = validator_state_handle(&address)
                        //     .get(storage, prev_epoch, params)
                        //     .unwrap();
                        if prev_state == Some(ValidatorState::Inactive) {
                            return None;
                        }
                    }
                }
            }

            let consensus_key = validator_consensus_key_handle(&address)
                .get(storage, current_epoch, params)
                .unwrap()
                .unwrap();
            Some(ValidatorSetUpdate::Deactivated(consensus_key))
        });
    active_validators.chain(inactive_validators).for_each(f)
}

/// Find all validators to which a given bond `owner` (or source) has a
/// delegation
pub fn find_delegation_validators<S>(
    storage: &S,
    owner: &Address,
) -> storage_api::Result<HashSet<Address>>
where
    S: StorageRead + StorageWrite,
{
    let bonds_prefix = bonds_for_source_prefix(owner);
    let mut delegations: HashSet<Address> = HashSet::new();

    for iter_result in storage_api::iter_prefix_bytes(storage, &bonds_prefix)? {
        let (key, _bond_bytes) = iter_result?;
        let validator_address = get_validator_address_from_bond(&key)
            .ok_or_else(|| {
                storage_api::Error::new_const(
                    "Delegation key should contain validator address.",
                )
            })?;
        delegations.insert(validator_address);
    }
    Ok(delegations)
}

/// Find all validators to which a given bond `owner` (or source) has a
/// delegation with the amount
pub fn find_delegations<S>(
    storage: &S,
    owner: &Address,
    epoch: &Epoch,
) -> storage_api::Result<HashMap<Address, token::Amount>>
where
    S: StorageRead + StorageWrite,
{
    let bonds_prefix = bonds_for_source_prefix(owner);
    let params = read_pos_params(storage)?;
    let mut delegations: HashMap<Address, token::Amount> = HashMap::new();

    for iter_result in storage_api::iter_prefix_bytes(storage, &bonds_prefix)? {
        let (key, _bond_bytes) = iter_result?;
        let validator_address = get_validator_address_from_bond(&key)
            .ok_or_else(|| {
                storage_api::Error::new_const(
                    "Delegation key should contain validator address.",
                )
            })?;
        let amount = bond_handle(owner, &validator_address)
            .get_sum(storage, epoch.clone(), &params)?
            .unwrap_or_default();
        delegations
            .insert(validator_address, token::Amount::from_change(amount));
    }
    Ok(delegations)
}
