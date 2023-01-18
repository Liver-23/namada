//! Implementation of chain initialization for the Shell
use std::collections::HashMap;
use std::hash::Hash;

#[cfg(not(feature = "mainnet"))]
use namada::core::ledger::testnet_pow;
use namada::ledger::parameters::Parameters;
use namada::ledger::pos::into_tm_voting_power;
use namada::ledger::storage_api::StorageWrite;
use namada::types::key::*;
use sha2::{Digest, Sha256};

use super::*;
use crate::config::genesis::chain::FinalizedTokenConfig;
use crate::config::genesis::templates::TokenConfig;
use crate::facade::tendermint_proto::abci;
use crate::facade::tendermint_proto::crypto::PublicKey as TendermintPublicKey;
use crate::facade::tendermint_proto::google::protobuf;
use crate::wasm_loader;

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Create a new genesis for the chain with specified id. This includes
    /// 1. A set of initial users and tokens
    /// 2. Setting up the validity predicates for both users and tokens
    pub fn init_chain(
        &mut self,
        init: request::InitChain,
    ) -> Result<response::InitChain> {
        let mut response = response::InitChain::default();
        let chain_id = self.wl_storage.storage.chain_id.as_str();
        if chain_id != init.chain_id.as_str() {
            return Err(Error::ChainId(format!(
                "Current chain ID: {}, Tendermint chain ID: {}",
                chain_id, init.chain_id
            )));
        }

        // Read the genesis files
        let chain_dir = self.base_dir.join(chain_id);
        let genesis = genesis::chain::Finalized::read_toml_files(&chain_dir)
            .expect("Missing genesis files");
        dbg!(genesis);

        let ts: protobuf::Timestamp = init.time.expect("Missing genesis time");
        let initial_height = init
            .initial_height
            .try_into()
            .expect("Unexpected block height");
        // TODO hacky conversion, depends on https://github.com/informalsystems/tendermint-rs/issues/870
        let genesis_time: DateTimeUtc = (Utc
            .timestamp_opt(ts.seconds, ts.nanos as u32))
        .single()
        .expect("genesis time should be a valid timestamp")
        .into();

        // Initialize protocol parameters
        let parameters = genesis.get_chain_parameters(&self.wasm_dir);
        parameters.init_storage(&mut self.wl_storage);

        // Initialize governance parameters
        let gov_params = genesis.get_gov_params();
        gov_params.init_storage(&mut self.wl_storage);

        // Depends on parameters being initialized
        self.wl_storage
            .storage
            .init_genesis_epoch(initial_height, genesis_time, &parameters)
            .expect("Initializing genesis epoch must not fail");

        // Loaded VP code cache to avoid loading the same files multiple times
        let mut vp_code_cache: HashMap<String, Vec<u8>> = HashMap::default();

        let lookup_vp =
            |name| genesis.vps.wasm.get(name).map(|config| &config.filename);

        // Init token accounts
        for (alias, token) in &genesis.tokens.token {
            tracing::debug!("Initializing token {alias}");
            let FinalizedTokenConfig {
                address,
                config: TokenConfig { vp },
            } = token;
            let vp_filename = lookup_vp(vp).expect("Missing token VP");
            let vp_code =
                vp_code_cache.get_or_insert_with(vp_filename.clone(), || {
                    wasm_loader::read_wasm(&self.wasm_dir, &vp_filename)
                        .unwrap()
                });

            self.wl_storage
                .write(&Key::validity_predicate(address), vp_code)
                .unwrap();
        }
        // Init token balances
        for (token_alias, balances) in genesis.balances.token {
            tracing::debug!("Initializing token balances {token_alias}");
            let token_address = genesis
                .tokens
                .token
                .get(&token_alias)
                .expect("Token with configured balance not found in genesis.")
                .address;
            for (owner_pk, balance) in balances.0 {
                let owner = Address::from(&owner_pk.raw);

                let pk_storage_key = pk_key(&owner);
                self.wl_storage
                    .write(&pk_storage_key, owner_pk.try_to_vec().unwrap())
                    .unwrap();

                self.wl_storage
                    .write(
                        &token::balance_key(&token_address, &owner),
                        balance.try_to_vec().unwrap(),
                    )
                    .unwrap();
            }
        }

        // Initialize genesis established accounts
        for genesis::EstablishedAccount {
            address,
            vp_code_path,
            vp_sha256,
            public_key,
            storage,
        } in genesis.established_accounts
        {
            let vp_code = match vp_code_cache.get(&vp_code_path).cloned() {
                Some(vp_code) => vp_code,
                None => {
                    let wasm =
                        wasm_loader::read_wasm(&self.wasm_dir, &vp_code_path)
                            .map_err(Error::ReadingWasm)?;
                    vp_code_cache.insert(vp_code_path.clone(), wasm.clone());
                    wasm
                }
            };

            let mut hasher = Sha256::new();
            hasher.update(&vp_code);
            let vp_code_hash = hasher.finalize();
            assert_eq!(
                vp_code_hash.as_slice(),
                &vp_sha256,
                "Invalid established account's VP sha256 hash for {}",
                vp_code_path
            );

            self.wl_storage
                .write_bytes(&Key::validity_predicate(&address), vp_code)
                .unwrap();

            if let Some(pk) = public_key {
                let pk_storage_key = pk_key(&address);
                self.wl_storage
                    .write_bytes(&pk_storage_key, pk.try_to_vec().unwrap())
                    .unwrap();
            }

            for (key, value) in storage {
                self.wl_storage.write_bytes(&key, value).unwrap();
            }

            // When using a faucet WASM, initialize its PoW challenge storage
            #[cfg(not(feature = "mainnet"))]
            if vp_code_path == "vp_testnet_faucet.wasm" {
                let difficulty =
                    genesis.faucet_pow_difficulty.unwrap_or_default();
                // withdrawal limit defaults to 1000 NAM when not set
                let withdrawal_limit = genesis
                    .faucet_withdrawal_limit
                    .unwrap_or_else(|| token::Amount::whole(1_000));
                testnet_pow::init_faucet_storage(
                    &mut self.wl_storage,
                    &address,
                    difficulty,
                    withdrawal_limit,
                )
                .expect("Couldn't init faucet storage")
            }
        }

        // Initialize genesis implicit
        for genesis::ImplicitAccount { public_key } in genesis.implicit_accounts
        {
            let address: address::Address = (&public_key).into();
            let pk_storage_key = pk_key(&address);
            self.wl_storage.write(&pk_storage_key, public_key).unwrap();
        }

        // Initialize genesis token accounts
        for genesis::TokenAccount {
            address,
            vp_code_path,
            vp_sha256,
            balances,
        } in genesis.token_accounts
        {
            let vp_code =
                vp_code_cache.get_or_insert_with(vp_code_path.clone(), || {
                    wasm_loader::read_wasm(&self.wasm_dir, &vp_code_path)
                        .unwrap()
                });

            let mut hasher = Sha256::new();
            hasher.update(&vp_code);
            let vp_code_hash = hasher.finalize();
            assert_eq!(
                vp_code_hash.as_slice(),
                &vp_sha256,
                "Invalid token account's VP sha256 hash for {}",
                vp_code_path
            );

            self.wl_storage
                .write_bytes(&Key::validity_predicate(&address), vp_code)
                .unwrap();

            for (owner, amount) in balances {
                self.wl_storage
                    .write(&token::balance_key(&address, &owner), amount)
                    .unwrap();
            }
        }

        // Initialize genesis validator accounts
        for validator in &genesis.validators {
            let vp_code = vp_code_cache.get_or_insert_with(
                validator.validator_vp_code_path.clone(),
                || {
                    wasm_loader::read_wasm(
                        &self.wasm_dir,
                        &validator.validator_vp_code_path,
                    )
                    .unwrap()
                },
            );
            let mut hasher = Sha256::new();
            hasher.update(&vp_code);
            let vp_code_hash = hasher.finalize();
            assert_eq!(
                vp_code_hash.as_slice(),
                &validator.validator_vp_sha256,
                "Invalid validator VP sha256 hash for {}",
                validator.validator_vp_code_path
            );

            let addr = &validator.pos_data.address;
            self.wl_storage
                .write_bytes(&Key::validity_predicate(addr), vp_code)
                .expect("Unable to write user VP");
            // Validator account key
            let pk_key = pk_key(addr);
            self.wl_storage
                .write(&pk_key, &validator.account_key)
                .expect("Unable to set genesis user public key");
            // Account balance (tokens no staked in PoS)
            self.wl_storage
                .write(
                    &token::balance_key(
                        &self.wl_storage.storage.native_token,
                        addr,
                    ),
                    validator.non_staked_balance,
                )
                .expect("Unable to set genesis balance");
            self.wl_storage
                .write(&protocol_pk_key(addr), &validator.protocol_key)
                .expect("Unable to set genesis user protocol public key");

            self.wl_storage
                .write(
                    &dkg_session_keys::dkg_pk_key(addr),
                    &validator.dkg_public_key,
                )
                .expect("Unable to set genesis user public DKG session key");
        }

        // PoS system depends on epoch being initialized
        let (current_epoch, _gas) = self.wl_storage.storage.get_current_epoch();
        let pos_params = genesis.get_pos_params();
        pos::init_genesis_storage(
            &mut self.wl_storage,
            &pos_params,
            genesis
                .validators
                .clone()
                .into_iter()
                .map(|validator| validator.pos_data),
            current_epoch,
        );
        ibc::init_genesis_storage(&mut self.wl_storage.storage);

        // Set the initial validator set
        for validator in genesis.validators {
            let mut abci_validator = abci::ValidatorUpdate::default();
            let consensus_key: common::PublicKey =
                validator.pos_data.consensus_key.clone();
            let pub_key = TendermintPublicKey {
                sum: Some(key_to_tendermint(&consensus_key).unwrap()),
            };
            abci_validator.pub_key = Some(pub_key);
            abci_validator.power = into_tm_voting_power(
                genesis.parameters.pos_params.tm_votes_per_token,
                validator.pos_data.tokens,
            );
            response.validators.push(abci_validator);
        }

        self.wl_storage
            .commit_genesis()
            .expect("Must be able to commit genesis state");

        Ok(response)
    }
}

trait HashMapExt<K, V>
where
    K: Eq + Hash,
    V: Clone,
{
    /// Inserts a value computed from `f` into the map if the given `key` is not
    /// present, then returns a clone of the value from the map.
    fn get_or_insert_with(&mut self, key: K, f: impl FnOnce() -> V) -> V;
}

impl<K, V> HashMapExt<K, V> for HashMap<K, V>
where
    K: Eq + Hash,
    V: Clone,
{
    fn get_or_insert_with(&mut self, key: K, f: impl FnOnce() -> V) -> V {
        use std::collections::hash_map::Entry;
        match self.entry(key) {
            Entry::Occupied(o) => o.get().clone(),
            Entry::Vacant(v) => v.insert(f()).clone(),
        }
    }
}
