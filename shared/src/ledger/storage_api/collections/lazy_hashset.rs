//! Lazy hash set.

use std::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};

use super::super::Result;
use super::hasher::hash_for_storage_key;
use super::LazyCollection;
use crate::ledger::storage_api::{self, ResultExt, StorageRead, StorageWrite};
use crate::types::storage;

/// Subkey corresponding to the data elements of the LazySet
pub const DATA_SUBKEY: &str = "data";

/// Lazy hash set.
///
/// This can be used as an alternative to `std::collections::HashSet` and
/// `BTreeSet`. In the lazy set, the elements do not reside in memory but are
/// instead read and written to storage sub-keys of the storage `key` given to
/// construct the set.
///
/// In the [`LazyHashSet`], the type of value `T` can be anything that
/// [`BorshSerialize`] and [`BorshDeserialize`] and a hex string of sha256 hash
/// over the borsh encoded values are used as storage key segments.
///
/// This is different from [`super::LazySet`], which uses [`storage::KeySeg`]
/// trait.
///
/// Additionally, [`LazyHashSet`] also writes the unhashed values into the
/// storage.
#[derive(Debug)]
pub struct LazyHashSet<T> {
    key: storage::Key,
    phantom: PhantomData<T>,
}

impl<T> LazyCollection for LazyHashSet<T> {
    /// Create or use an existing set with the given storage `key`.
    fn open(key: storage::Key) -> Self {
        Self {
            key,
            phantom: PhantomData,
        }
    }
}

impl<T> LazyHashSet<T>
where
    T: BorshSerialize + BorshDeserialize + 'static,
{
    /// Adds a value to the set. If the set did not have this value present,
    /// `Ok(true)` is returned, `Ok(false)` otherwise.
    pub fn insert<S>(&self, storage: &mut S, val: T) -> Result<bool>
    where
        S: StorageWrite + for<'iter> StorageRead<'iter>,
    {
        if self.contains(storage, &val)? {
            Ok(false)
        } else {
            let data_key = self.get_data_key(&val);
            storage.write(&data_key, &val)?;
            Ok(true)
        }
    }

    /// Removes a value from the set. Returns whether the value was present in
    /// the set.
    pub fn remove<S>(&self, storage: &mut S, val: &T) -> Result<bool>
    where
        S: StorageWrite + for<'iter> StorageRead<'iter>,
    {
        let data_key = self.get_data_key(val);
        let value: Option<T> = storage.read(&data_key)?;
        storage.delete(&data_key)?;
        Ok(value.is_some())
    }

    /// Returns whether the set contains a value.
    pub fn contains<S>(&self, storage: &S, val: &T) -> Result<bool>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        let value: Option<T> = storage.read(&self.get_data_key(val))?;
        Ok(value.is_some())
    }

    /// Reads the number of elements in the set.
    ///
    /// Note that this function shouldn't be used in transactions and VPs code
    /// on unbounded sets to avoid gas usage increasing with the length of the
    /// set.
    #[allow(clippy::len_without_is_empty)]
    pub fn len<S>(&self, storage: &S) -> Result<u64>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        let iter =
            storage_api::iter_prefix_bytes(storage, &self.get_data_prefix())?;
        iter.count().try_into().into_storage_result()
    }

    /// Returns whether the set contains no elements.
    pub fn is_empty<S>(&self, storage: &S) -> Result<bool>
    where
        S: for<'iter> StorageRead<'iter>,
    {
        let mut iter = storage.iter_prefix(&self.get_data_prefix())?;
        Ok(storage.iter_next(&mut iter)?.is_none())
    }

    /// An iterator visiting all elements. The iterator element type is
    /// `Result<T>`, because iterator's call to `next` may fail with e.g. out of
    /// gas or data decoding error.
    ///
    /// Note that this function shouldn't be used in transactions and VPs code
    /// on unbounded sets to avoid gas usage increasing with the length of the
    /// set.
    pub fn iter<'iter>(
        &self,
        storage: &'iter impl StorageRead<'iter>,
    ) -> Result<impl Iterator<Item = Result<T>> + 'iter> {
        let iter = storage_api::iter_prefix(storage, &self.get_data_prefix())?;
        Ok(iter.map(|key_val_res| {
            let (_key, val) = key_val_res?;
            Ok(val)
        }))
    }

    /// Get the prefix of set's elements storage
    fn get_data_prefix(&self) -> storage::Key {
        self.key.push(&DATA_SUBKEY.to_owned()).unwrap()
    }

    /// Get the sub-key of a given element
    fn get_data_key(&self, val: &T) -> storage::Key {
        let hash_str = hash_for_storage_key(val);
        self.get_data_prefix().push(&hash_str).unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ledger::storage::testing::TestStorage;

    #[test]
    fn test_lazy_set_basics() -> storage_api::Result<()> {
        let mut storage = TestStorage::default();

        let key = storage::Key::parse("test").unwrap();
        let lazy_set = LazyHashSet::<i64>::open(key);

        // The set should be empty at first
        assert!(lazy_set.is_empty(&storage)?);
        assert!(lazy_set.len(&storage)? == 0);
        assert!(!lazy_set.contains(&storage, &0)?);
        assert!(lazy_set.is_empty(&storage)?);
        assert!(lazy_set.iter(&storage)?.next().is_none());
        assert!(!lazy_set.remove(&mut storage, &0)?);
        assert!(!lazy_set.remove(&mut storage, &1)?);

        // Insert a new value and check that it's added
        let val = 1337;
        lazy_set.insert(&mut storage, val)?;
        assert!(!lazy_set.is_empty(&storage)?);
        assert!(lazy_set.len(&storage)? == 1);
        assert_eq!(lazy_set.iter(&storage)?.next().unwrap()?, val.clone());
        assert!(!lazy_set.contains(&storage, &0)?);
        assert!(lazy_set.contains(&storage, &val)?);

        // Remove the last value and check that the set is empty again
        let is_removed = lazy_set.remove(&mut storage, &val)?;
        assert!(is_removed);
        assert!(lazy_set.is_empty(&storage)?);
        assert!(lazy_set.len(&storage)? == 0);
        assert!(!lazy_set.contains(&storage, &0)?);
        assert!(lazy_set.is_empty(&storage)?);
        assert!(!lazy_set.remove(&mut storage, &0)?);
        assert!(!lazy_set.remove(&mut storage, &1)?);

        Ok(())
    }
}
