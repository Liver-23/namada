//! Storage with write log.

use std::iter::Peekable;
use std::marker::PhantomData;

use super::write_log::{self, WriteLog};
use crate::ledger::storage::{DBIter, Storage, StorageHasher, DB};
use crate::ledger::storage_api;
use crate::ledger::storage_api::{ResultExt, StorageRead, StorageWrite};

/// Read-write storage with write-log
pub type RwWlStorage<'a, D, H> =
    WlStorage<'a, &'a mut WriteLog, &'a mut Storage<D, H>>;

/// Read-only storage with write-log. You can [`From::from`] it from
/// [`RwWlStorage`].
pub type RoWlStorage<'a, D, H> = WlStorage<'a, &'a WriteLog, &'a Storage<D, H>>;

/// Storage with write log that allows to implement prefix iterator that works
/// with changes not yet committed to the DB.
pub struct WlStorage<'a, WL, S> {
    /// Write log
    pub write_log: WL,
    /// Storage provides access to DB
    pub storage: S,
    /// `'a` must be used
    lifetime_phantom: PhantomData<&'a ()>,
}

impl<'a, WL, S> WlStorage<'a, WL, S> {
    /// Combine storage with write-log
    pub fn new(write_log: WL, storage: S) -> Self {
        Self {
            write_log,
            storage,
            lifetime_phantom: PhantomData,
        }
    }
}

// R/W can be converted into R/O, but not the other way
impl<'a, D, H> From<RwWlStorage<'a, D, H>> for RoWlStorage<'a, D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    fn from(
        RwWlStorage {
            storage,
            write_log,
            lifetime_phantom,
        }: RwWlStorage<'a, D, H>,
    ) -> Self {
        Self {
            storage,
            write_log,
            lifetime_phantom,
        }
    }
}

impl<'a, D, H> RwWlStorage<'a, D, H>
where
    D: DB + for<'iter> DBIter<'iter> + 'static,
    H: StorageHasher,
{
    /// Commit the genesis state to DB. This should only be used before any
    /// blocks are produced.
    pub fn commit_genesis(&mut self) -> storage_api::Result<()> {
        self.write_log
            .commit_genesis(self.storage)
            .into_storage_result()
    }

    /// Commit the current transaction's write log to the block when it's
    /// accepted by all the triggered validity predicates. Starts a new
    /// transaction write log.
    pub fn commit_tx(&mut self) {
        self.write_log.commit_tx()
    }

    /// Commit the current block's write log to the storage and commit the block
    /// to DB. Starts a new block write log.
    pub fn commit_block(&mut self) -> storage_api::Result<()> {
        self.write_log
            .commit_block(self.storage)
            .into_storage_result()?;
        self.storage.commit_block().into_storage_result()
    }
}

/// Prefix iterator for [`WlStorage`].
pub struct PrefixIter<'iter, D>
where
    D: DB + for<'iter_> DBIter<'iter_>,
{
    /// Peekable storage iterator
    storage_iter: Peekable<<D as DBIter<'iter>>::PrefixIter>,
    /// Peekable write log iterator
    write_log_iter: Peekable<write_log::PrefixIter>,
}

impl<'iter, D> Iterator for PrefixIter<'iter, D>
where
    D: DB + for<'iter_> DBIter<'iter_>,
{
    type Item = (String, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        enum Next {
            ReturnWl { advance_storage: bool },
            ReturnStorage,
        }
        loop {
            let what: Next;
            {
                let storage_peeked = self.storage_iter.peek();
                let wl_peeked = self.write_log_iter.peek();
                match (storage_peeked, wl_peeked) {
                    (None, None) => return None,
                    (None, Some(_)) => {
                        what = Next::ReturnWl {
                            advance_storage: false,
                        };
                    }
                    (Some(_), None) => {
                        what = Next::ReturnStorage;
                    }
                    (Some((storage_key, _, _)), Some((wl_key, _))) => {
                        let wl_key = wl_key.to_string();
                        if &wl_key <= storage_key {
                            what = Next::ReturnWl {
                                advance_storage: &wl_key == storage_key,
                            };
                        } else {
                            what = Next::ReturnStorage;
                        }
                    }
                }
            }
            match what {
                Next::ReturnWl { advance_storage } => {
                    if advance_storage {
                        let _ = self.storage_iter.next();
                    }

                    if let Some((key, modification)) =
                        self.write_log_iter.next()
                    {
                        match modification {
                            write_log::StorageModification::Write { value }
                            | write_log::StorageModification::Temp { value } => {
                                return Some((key.to_string(), value));
                            }
                            write_log::StorageModification::InitAccount {
                                vp,
                            } => {
                                return Some((key.to_string(), vp));
                            }
                            write_log::StorageModification::Delete => {
                                continue;
                            }
                        }
                    }
                }
                Next::ReturnStorage => {
                    if let Some((key, value, _gas)) = self.storage_iter.next() {
                        return Some((key, value));
                    }
                }
            }
        }
    }
}

macro_rules! impl_storage_read {
    ($($any:tt)*) => {
        $( $any )*
        {
            type PrefixIter<'iter_> = PrefixIter<'iter_, D> where Self: 'iter_;

            fn read_bytes(
                &self,
                key: &crate::types::storage::Key,
            ) -> crate::ledger::storage_api::Result<Option<Vec<u8>>> {
                // try to read from the write log first
                let (log_val, _gas) = self.write_log.read(key);
                match log_val {
                    Some(&write_log::StorageModification::Write { ref value }) => {
                        Ok(Some(value.clone()))
                    }
                    Some(&write_log::StorageModification::Delete) => Ok(None),
                    Some(&write_log::StorageModification::InitAccount {
                        ref vp,
                        ..
                    }) => Ok(Some(vp.clone())),
                    Some(&write_log::StorageModification::Temp { ref value }) => {
                        Ok(Some(value.clone()))
                    }
                    None => {
                        // when not found in write log, try to read from the storage
                        StorageRead::read_bytes(self.storage, key)
                    }
                }
            }

            fn has_key(
                &self,
                key: &crate::types::storage::Key,
            ) -> crate::ledger::storage_api::Result<bool> {
                // try to read from the write log first
                let (log_val, _gas) = self.write_log.read(key);
                match log_val {
                    Some(&write_log::StorageModification::Write { .. })
                    | Some(&write_log::StorageModification::InitAccount {
                        ..
                    })
                    | Some(&write_log::StorageModification::Temp { .. }) => {
                        Ok(true)
                    }
                    Some(&write_log::StorageModification::Delete) => {
                        // the given key has been deleted
                        Ok(false)
                    }
                    None => {
                        // when not found in write log, try to check the storage
                        StorageRead::has_key(self.storage, key)
                    }
                }
            }

            fn iter_prefix<'iter>(
                &'iter self,
                prefix: &crate::types::storage::Key,
            ) -> crate::ledger::storage_api::Result<Self::PrefixIter<'iter>> {
                let storage_iter =
                    StorageRead::iter_prefix(self.storage, prefix)?.peekable();
                let write_log_iter = self.write_log.iter_prefix(prefix).peekable();
                Ok(PrefixIter {
                    storage_iter,
                    write_log_iter,
                })
            }

            fn iter_next<'iter>(
                &'iter self,
                iter: &mut Self::PrefixIter<'iter>,
            ) -> crate::ledger::storage_api::Result<Option<(String, Vec<u8>)>>
            {
                Ok(iter.next())
            }

            fn get_chain_id(
                &self,
            ) -> crate::ledger::storage_api::Result<String> {
                StorageRead::get_chain_id(self.storage)
            }

            fn get_block_height(
                &self,
            ) -> crate::ledger::storage_api::Result<
                crate::types::storage::BlockHeight,
            > {
                StorageRead::get_block_height(self.storage)
            }

            fn get_block_hash(
                &self,
            ) -> crate::ledger::storage_api::Result<
                crate::types::storage::BlockHash,
            > {
                StorageRead::get_block_hash(self.storage)
            }

            fn get_block_epoch(
                &self,
            ) -> crate::ledger::storage_api::Result<
                crate::types::storage::Epoch,
            > {
                StorageRead::get_block_epoch(self.storage)
            }

            fn get_tx_index(
                &self,
            ) -> crate::ledger::storage_api::Result<
                crate::types::storage::TxIndex,
            > {
                StorageRead::get_tx_index(self.storage)
            }

            fn get_native_token(
                &self,
            ) -> crate::ledger::storage_api::Result<
                crate::types::address::Address,
            > {
                StorageRead::get_native_token(self.storage)
            }
        }
    }
}

impl_storage_read! {
    impl<'it, D, H> StorageRead for WlStorage<'it, &'it WriteLog, &'it Storage<D, H>>
    where
    D: DB + for<'iter_> DBIter<'iter_>,
    H: StorageHasher,
}

impl_storage_read! {
    impl<'it, D, H> StorageRead for WlStorage<'it, &'it mut WriteLog, &'it mut Storage<D, H>>
    where
    D: DB + for<'iter_> DBIter<'iter_>,
    H: StorageHasher,
}

impl<'iter, D, H> StorageWrite
    for WlStorage<'iter, &'iter mut WriteLog, &'iter mut Storage<D, H>>
where
    D: DB + for<'iter_> DBIter<'iter_>,
    H: StorageHasher,
{
    fn write_bytes(
        &mut self,
        key: &crate::types::storage::Key,
        val: impl AsRef<[u8]>,
    ) -> crate::ledger::storage_api::Result<()> {
        let _ = self
            .write_log
            .write(key, val.as_ref().to_vec())
            .into_storage_result();
        Ok(())
    }

    fn delete(
        &mut self,
        key: &crate::types::storage::Key,
    ) -> crate::ledger::storage_api::Result<()> {
        let _ = self.write_log.delete(key).into_storage_result();
        Ok(())
    }
}
