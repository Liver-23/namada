//! Functionality to do with persisting data related to the local node

use std::collections::HashMap;
use std::fmt;

use borsh::{BorshDeserialize, BorshSerialize};

use super::{DBIter, Storage, StorageHasher, DB};
use crate::ledger::storage_api::{StorageRead, StorageWrite};
use crate::types::ethereum;
use crate::types::storage::{self, DbKeySeg};

/// Values in storage that are to do with the local node rather than the
/// blockchain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocalNodeValue {
    EthereumOracleLastProcessedBlock,
}

impl fmt::Display for LocalNodeValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LocalNodeValue::EthereumOracleLastProcessedBlock => {
                write!(f, "ethereum_oracle_last_processed_block")
            }
        }
    }
}

impl From<LocalNodeValue> for storage::Key {
    fn from(value: LocalNodeValue) -> Self {
        storage::Key::from(DbKeySeg::StringSeg(value.to_string()))
    }
}

/// We store some values in storage which are to do with our local node, rather
/// than any specific chain.
pub fn ensure_local_node_values_configured<D, H>(storage: &mut Storage<D, H>)
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    let local_node_initial_values = HashMap::from([(
        LocalNodeValue::EthereumOracleLastProcessedBlock,
        ethereum::BlockHeight::from(0),
    )]);

    for (key, initial_value) in local_node_initial_values {
        let key: storage::Key = key.into();
        let (has_key, _) = storage.has_key(&key).unwrap();
        if !has_key {
            tracing::info!(
                ?key,
                ?initial_value,
                "Writing initial value for local node configuration key"
            );
            StorageWrite::write(storage, &key, initial_value).unwrap();
        } else {
            match StorageRead::read::<ethereum::BlockHeight>(storage, &key)
                .unwrap()
            {
                Some(value) => tracing::info!(
                    ?key,
                    ?value,
                    "Value already present for local node configuration key"
                ),
                None => unreachable!(),
            }
        }
    }
}

pub fn read_local_node_value<D, H, T: BorshSerialize + BorshDeserialize>(
    storage: &Storage<D, H>,
    key: LocalNodeValue,
) -> T
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    let key: storage::Key = key.into();
    StorageRead::read(storage, &key).unwrap().unwrap()
}

pub fn write_local_node_value<D, H, T: BorshSerialize + BorshDeserialize>(
    storage: &mut Storage<D, H>,
    key: LocalNodeValue,
    value: T,
) where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    let key: storage::Key = key.into();
    StorageWrite::write(storage, &key, value).unwrap();
}
