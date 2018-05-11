use dispatch::{Diff, DiffEvent};
use im::btree::{DiffItem, DiffIter, Iter};
use im::{OrdMap, OrdSet};
use std::sync::Arc;

pub struct DiffMapAdapter<K, V>(DiffIter<(K, V)>);

impl<K, V> Iterator for DiffMapAdapter<K, V>
where
    DiffIter<(K, V)>: Iterator<Item = DiffItem<(K, V)>>,
{
    type Item = DiffEvent<K, V>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|item| match item {
            DiffItem::Add((key, new_value)) => DiffEvent::Add { key, new_value },
            DiffItem::Update { new, old } => DiffEvent::Update {
                key: new.0,
                new_value: new.1,
                old_value: old.1,
            },
            DiffItem::Remove((key, old_value)) => DiffEvent::Remove { key, old_value },
        })
    }
}

impl<K: Ord, V: PartialEq> Diff<Arc<K>, Arc<V>> for OrdMap<K, V> {
    type Iterator = Iter<(Arc<K>, Arc<V>)>;
    type DiffIterator = DiffMapAdapter<Arc<K>, Arc<V>>;

    fn iter(&self) -> Self::Iterator {
        self.into_iter()
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
    type Item = DiffEvent<K, ()>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|item| match item {
            DiffItem::Add(key) => DiffEvent::Add { key, new_value: () },
            DiffItem::Update { new, .. } => DiffEvent::Update {
                key: new,
                new_value: (),
                old_value: (),
            },
            DiffItem::Remove(key) => DiffEvent::Remove { key, old_value: () },
        })
    }
}

pub struct UnitAdapter<K>(Iter<K>);

impl<K> Iterator for UnitAdapter<K>
where
    Iter<K>: Iterator<Item = K>,
{
    type Item = (K, ());

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|item| (item, ()))
    }
}

impl<K: Ord> Diff<Arc<K>, ()> for OrdSet<K> {
    type Iterator = UnitAdapter<Arc<K>>;
    type DiffIterator = DiffSetAdapter<Arc<K>>;

    fn iter(&self) -> Self::Iterator {
        UnitAdapter(self.into_iter())
    }

    fn diff(&self, new: &Self) -> Self::DiffIterator {
        DiffSetAdapter(self.diff(new))
    }
}
