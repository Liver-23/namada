use std::collections::HashSet;

use namada_core::ledger::storage_api::collections::lazy_map;
use namada_core::ledger::storage_api::OptionExt;
use namada_proof_of_stake::types::WeightedValidatorNew;
use namada_proof_of_stake::{
    self, active_validator_set_handle, bond_handle,
    inactive_validator_set_handle, read_pos_params, read_total_stake,
    read_validator_stake, unbond_handle, PosReadOnly,
};

use crate::ledger::pos::{self, BondId};
use crate::ledger::queries::types::RequestCtx;
use crate::ledger::storage::{DBIter, StorageHasher, DB};
use crate::ledger::storage_api;
use crate::types::address::Address;
use crate::types::storage::Epoch;
use crate::types::token;

// PoS validity predicate queries
router! {POS,
    ( "validator" ) = {
        ( "is_validator" / [addr: Address] ) -> bool = is_validator,

        ( "addresses" / [epoch: opt Epoch] )
            -> HashSet<Address> = validator_addresses,

        ( "stake" / [validator: Address] / [epoch: opt Epoch] )
            -> Option<token::Amount> = validator_stake,
    },

    ( "validator_set" ) = {
        // TODO: rename to "consensus"
        ( "active" / [epoch: opt Epoch] )
            -> HashSet<WeightedValidatorNew> = active_validator_set,

        // TODO: rename to "below_capacity"
        ( "inactive" / [epoch: opt Epoch] )
            -> HashSet<WeightedValidatorNew> = inactive_validator_set,

        // TODO: add "below_threshold"
    },

    ( "total_stake" / [epoch: opt Epoch] )
        -> token::Amount = total_stake,

    ( "delegations" / [owner: Address] )
        -> HashSet<Address> = delegations,

    ( "bond_amount" / [owner: Address] / [validator: Address] / [epoch: opt Epoch] )
        -> token::Amount = bond_amount,

    ( "bond_remaining" / [source: Address] / [validator: Address] / [epoch: opt Epoch] )
        -> token::Amount = bond_remaining_new,

    ( "withdrawable_tokens" / [source: Address] / [validator: Address] / [epoch: opt Epoch] )
        -> token::Amount = withdrawable_tokens,

}

// Handlers that implement the functions via `trait StorageRead`:

/// Find if the given address belongs to a validator account.
fn is_validator<D, H>(
    ctx: RequestCtx<'_, D, H>,
    addr: Address,
) -> storage_api::Result<bool>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    println!(
        "\nLOOKING UP VALIDATOR IN EPOCH {}\n",
        ctx.wl_storage.storage.block.epoch
    );
    let params = namada_proof_of_stake::read_pos_params(ctx.wl_storage)?;
    namada_proof_of_stake::is_validator(
        ctx.wl_storage,
        &addr,
        &params,
        ctx.wl_storage.storage.block.epoch,
    )
}

/// Get all the validator known addresses. These validators may be in any state,
/// e.g. active, inactive or jailed.
fn validator_addresses<D, H>(
    ctx: RequestCtx<'_, D, H>,
    epoch: Option<Epoch>,
) -> storage_api::Result<HashSet<Address>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);

    // TODO update
    ctx.wl_storage.validator_addresses(epoch)
}

/// Get the total stake of a validator at the given epoch or current when
/// `None`. The total stake is a sum of validator's self-bonds and delegations
/// to their address.
/// Returns `None` when the given address is not a validator address. For a
/// validator with `0` stake, this returns `Ok(token::Amount::default())`.
fn validator_stake<D, H>(
    ctx: RequestCtx<'_, D, H>,
    validator: Address,
    epoch: Option<Epoch>,
) -> storage_api::Result<Option<token::Amount>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    let params = read_pos_params(ctx.wl_storage)?;
    read_validator_stake(ctx.wl_storage, &params, &validator, epoch)
}

/// Get all the validator in the active set with their bonded stake.
fn active_validator_set<D, H>(
    ctx: RequestCtx<'_, D, H>,
    epoch: Option<Epoch>,
) -> storage_api::Result<HashSet<WeightedValidatorNew>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    active_validator_set_handle()
        .at(&epoch)
        .iter(ctx.wl_storage)?
        .map(|next_result| {
            next_result.map(
                |(
                    lazy_map::NestedSubKey::Data {
                        key: bonded_stake,
                        nested_sub_key: _position,
                    },
                    address,
                )| {
                    WeightedValidatorNew {
                        bonded_stake,
                        address,
                    }
                },
            )
        })
        .collect()
}

/// Get all the validator in the inactive set with their bonded stake.
fn inactive_validator_set<D, H>(
    ctx: RequestCtx<'_, D, H>,
    epoch: Option<Epoch>,
) -> storage_api::Result<HashSet<WeightedValidatorNew>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    inactive_validator_set_handle()
        .at(&epoch)
        .iter(ctx.wl_storage)?
        .map(|next_result| {
            next_result.map(
                |(
                    lazy_map::NestedSubKey::Data {
                        key: bonded_stake,
                        nested_sub_key: _position,
                    },
                    address,
                )| {
                    WeightedValidatorNew {
                        bonded_stake: bonded_stake.into(),
                        address,
                    }
                },
            )
        })
        .collect()
}

/// Get the total stake in PoS system at the given epoch or current when `None`.
fn total_stake<D, H>(
    ctx: RequestCtx<'_, D, H>,
    epoch: Option<Epoch>,
) -> storage_api::Result<token::Amount>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    let params = read_pos_params(ctx.wl_storage)?;
    read_total_stake(ctx.wl_storage, &params, epoch)
}

/// TODO: new bond thing
fn bond_remaining_new<D, H>(
    ctx: RequestCtx<'_, D, H>,
    source: Address,
    validator: Address,
    epoch: Option<Epoch>,
) -> storage_api::Result<token::Amount>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = dbg!(epoch.unwrap_or(ctx.wl_storage.storage.last_epoch));
    let params = read_pos_params(ctx.wl_storage)?;

    let handle = bond_handle(&source, &validator, true);
    handle
        .get_sum(ctx.wl_storage, epoch, &params)?
        .map(token::Amount::from_change)
        .ok_or_err_msg("Cannot find bond")
}

fn withdrawable_tokens<D, H>(
    ctx: RequestCtx<'_, D, H>,
    source: Address,
    validator: Address,
    epoch: Option<Epoch>,
) -> storage_api::Result<token::Amount>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);

    let handle = unbond_handle(&source, &validator);
    let mut total = token::Amount::default();
    for result in handle.iter(ctx.wl_storage)? {
        let (
            lazy_map::NestedSubKey::Data {
                key: end,
                nested_sub_key: lazy_map::SubKey::Data(_start),
            },
            amount,
        ) = result?;
        if end <= epoch {
            total += amount;
        }
    }
    Ok(total)
}

/// Get the total bond amount for the given bond ID (this may be delegation or
/// self-bond when `owner == validator`) at the given epoch, or the current
/// epoch when `None`.
fn bond_amount<D, H>(
    ctx: RequestCtx<'_, D, H>,
    owner: Address,
    validator: Address,
    epoch: Option<Epoch>,
) -> storage_api::Result<token::Amount>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);

    let bond_id = BondId {
        source: owner,
        validator,
    };
    // TODO update
    ctx.wl_storage.bond_amount(&bond_id, epoch)
}
/// Find all the validator addresses to whom the given `owner` address has
/// some delegation in any epoch
fn delegations<D, H>(
    ctx: RequestCtx<'_, D, H>,
    owner: Address,
) -> storage_api::Result<HashSet<Address>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let bonds_prefix = pos::bonds_for_source_prefix(&owner);

    // TODO update
    let mut delegations: HashSet<Address> = HashSet::new();
    for iter_result in
        storage_api::iter_prefix_bytes(ctx.wl_storage, &bonds_prefix)?
    {
        let (key, _bonds_bytes) = iter_result?;
        let validator_address = pos::get_validator_address_from_bond(&key)
            .ok_or_else(|| {
                storage_api::Error::new_const(
                    "Delegation key should contain validator address.",
                )
            })?;
        delegations.insert(validator_address);
    }
    Ok(delegations)
}
