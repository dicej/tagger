use im::{OrdMap, OrdSet};
use serde;
use std::fmt;
use std::marker::PhantomData;

#[derive(Deref, DerefMut, Clone)]
pub struct Map<K, V>(OrdMap<K, V>);

impl<'de, K, V> serde::Deserialize<'de> for Map<K, V>
where
    K: serde::Deserialize<'de> + Ord,
    V: serde::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Map<K, V>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct MapVisitor<K, V>(PhantomData<K>, PhantomData<V>);

        impl<'de, K, V> serde::de::Visitor<'de> for MapVisitor<K, V>
        where
            K: serde::Deserialize<'de> + Ord,
            V: serde::Deserialize<'de>,
        {
            type Value = Map<K, V>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut result = Map(OrdMap::new());

                while let Some((key, value)) = map.next_entry()? as Option<(K, V)> {
                    result.insert_mut(key, value);
                }

                Ok(result)
            }
        }

        deserializer.deserialize_map(MapVisitor(PhantomData, PhantomData))
    }
}

#[derive(Deref, DerefMut, Clone)]
pub struct Set<V>(OrdSet<V>);

impl<'de, V> serde::Deserialize<'de> for Set<V>
where
    V: serde::Deserialize<'de> + Ord,
{
    fn deserialize<D>(deserializer: D) -> Result<Set<V>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SeqVisitor<V>(PhantomData<V>);

        impl<'de, V> serde::de::Visitor<'de> for SeqVisitor<V>
        where
            V: serde::Deserialize<'de> + Ord,
        {
            type Value = Set<V>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut result = Set(OrdSet::new());

                while let Some(value) = seq.next_element()? as Option<V> {
                    result.insert_mut(value);
                }

                Ok(result)
            }
        }

        deserializer.deserialize_seq(SeqVisitor(PhantomData))
    }
}
