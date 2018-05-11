use dispatch::{Diff, DiffEvent};
use im::btree::{DiffItem, DiffIter, Iter};
use im::{OrdMap, OrdSet};
use std::cmp::Ordering;
use std::sync::Arc;

#[derive(Clone)]
pub struct KeyValue<K, V>(pub K, pub V);

impl<K: Ord, V> Ord for KeyValue<K, V> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl<K: PartialOrd, V> PartialOrd for KeyValue<K, V> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl<K: PartialEq, V> PartialEq for KeyValue<K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl<K: PartialEq, V> Eq for KeyValue<K, V> {}

pub struct KeyValueAdapter<K, V>(Iter<(K, V)>);

impl<K, V> Iterator for KeyValueAdapter<K, V>
where
    Iter<(K, V)>: Iterator<Item = (K, V)>,
{
    type Item = KeyValue<K, V>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(k, v)| KeyValue(k, v))
    }
}

pub struct DiffMapAdapter<K, V>(DiffIter<(K, V)>);

impl<K, V> Iterator for DiffMapAdapter<K, V>
where
    DiffIter<(K, V)>: Iterator<Item = DiffItem<(K, V)>>,
{
    type Item = DiffEvent<KeyValue<K, V>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|item| match item {
            DiffItem::Add((k, v)) => DiffEvent::Add(KeyValue(k, v)),
            DiffItem::Update { new, old } => DiffEvent::Update {
                new: KeyValue(new.0, new.1),
                old: KeyValue(old.0, old.1),
            },
            DiffItem::Remove((k, v)) => DiffEvent::Remove(KeyValue(k, v)),
        })
    }
}

impl<K: Ord, V: PartialEq> Diff<KeyValue<Arc<K>, Arc<V>>> for OrdMap<K, V> {
    type Iterator = KeyValueAdapter<Arc<K>, Arc<V>>;
    type DiffIterator = DiffMapAdapter<Arc<K>, Arc<V>>;

    fn iter(&self) -> Self::Iterator {
        KeyValueAdapter(self.into_iter())
    }

    fn diff(&self, new: &Self) -> Self::DiffIterator {
        DiffMapAdapter(self.diff(new))
    }
}

pub struct DiffSetAdapter<K>(DiffIter<K>);

impl<K> Iterator for DiffSetAdapter<K>
where
    DiffIter<K>: Iterator<Item = DiffItem<K>>,
{
    type Item = DiffEvent<K>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|item| match item {
            DiffItem::Add(k) => DiffEvent::Add(k),
            DiffItem::Update { new, old } => DiffEvent::Update { new, old },
            DiffItem::Remove(k) => DiffEvent::Remove(k),
        })
    }
}

impl<K: Ord> Diff<Arc<K>> for OrdSet<K> {
    type Iterator = Iter<Arc<K>>;
    type DiffIterator = DiffSetAdapter<Arc<K>>;

    fn iter(&self) -> Self::Iterator {
        self.clone().into_iter()
    }

    fn diff(&self, new: &Self) -> Self::DiffIterator {
        DiffSetAdapter(self.diff(new))
    }
}
