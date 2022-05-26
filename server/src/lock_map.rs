//! This module provides the [LockMap] type, which is useful for providing fine-grained reader/writer concurrency
//! control in cases where an arbitrary number of distinct resources must be managed.

use {
    std::{collections::HashMap, hash::Hash, sync::Arc},
    tokio::sync::RwLock,
};

/// Provides fine-grained reader/writer concurrency control in cases where an arbitrary number of distinct
/// resources must be managed.
#[derive(Debug)]
pub struct LockMap<K, V>(RwLock<HashMap<K, Arc<RwLock<V>>>>);

impl<K, V> Default for LockMap<K, V> {
    /// Return an empty [LockMap].
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<K, V> LockMap<K, V> {
    /// Retrieve the lock for the specified resource.
    ///
    /// If no such lock already exists, it will be created and added to the map.
    pub async fn get(&self, key: K) -> Arc<RwLock<V>>
    where
        K: Eq,
        K: Hash,
        V: Default,
    {
        if let Some(lock) = self.0.read().await.get(&key) {
            return lock.clone();
        }

        let mut write = self.0.write().await;

        if let Some(lock) = write.get(&key) {
            return lock.clone();
        }

        let lock = Arc::<RwLock<V>>::default();
        write.insert(key, lock.clone());
        lock
    }

    /// Remove any unused locks from the map.
    ///
    /// A lock is considered unused if there are no strong or weak references to it outside of the map itself.
    pub async fn clean(&self) {
        self.0
            .write()
            .await
            .retain(|_, lock| Arc::get_mut(lock).is_none());
    }
}
