use {
    anyhow::Result,
    futures::TryStreamExt,
    sqlx::{query::Query, sqlite::SqliteArguments, Row, Sqlite, SqliteConnection},
    std::{
        collections::{BTreeMap, HashMap, HashSet, VecDeque},
        convert::TryFrom,
        fmt::Write,
        str::FromStr,
        sync::Arc,
    },
    tagger_shared::{
        tag_expression::{Tag, TagExpression},
        ImageData, ImageKey, ImagesQuery, ImagesResponse, Medium,
    },
};

const DEFAULT_LIMIT: u32 = 1000;

fn build_images_query<'a>(
    buffer: &'a mut String,
    filter: Option<&TagExpression>,
) -> Query<'a, Sqlite, SqliteArguments<'a>> {
    write!(
        buffer,
        "SELECT \
         hash, \
         datetime, \
         video_offset, \
         perceptual_hash, \
         duplicate_group, \
         duplicate_index, \
         (SELECT group_concat(CASE WHEN category IS NULL THEN tag ELSE category || ':' || tag END) \
          FROM tags WHERE hash = i.hash) \
         FROM images i WHERE {}",
        if let Some(filter) = filter {
            let mut buffer = String::new();
            crate::append_filter_clause(&mut buffer, filter);
            buffer
        } else {
            "1".into()
        }
    )
    .unwrap();

    let mut select = sqlx::query(buffer);

    if let Some(filter) = filter {
        select = crate::bind_filter_clause(filter, select);
    }

    select
}

pub async fn images(conn: &mut SqliteConnection, query: &ImagesQuery) -> Result<ImagesResponse> {
    let limit = usize::try_from(query.limit.unwrap_or(DEFAULT_LIMIT)).unwrap();

    let mut buffer = String::new();
    let mut rows = build_images_query(&mut buffer, query.filter.as_ref()).fetch(&mut *conn);
    let mut row_map = BTreeMap::new();
    let mut duplicates = HashMap::<_, BTreeMap<_, _>>::new();

    while let Some(row) = rows.try_next().await? {
        let key = ImageKey {
            datetime: row.get::<&str, _>(1).parse()?,
            hash: Some(Arc::from(row.get::<&str, _>(0))),
        };

        let perceptual_hash = row.get::<Option<&str>, _>(3).map(Arc::<str>::from);

        if let Some(perceptual_hash) = &perceptual_hash {
            let duplicate_group = row.get::<i64, _>(4);

            if duplicate_group > 0 {
                let duplicate_index = row.get::<i64, _>(5);

                duplicates
                    .entry((perceptual_hash.clone(), duplicate_group))
                    .or_default()
                    .insert(duplicate_index, key.clone());
            }
        }

        row_map.insert(key, (row, perceptual_hash));
    }

    let mut images = Vec::with_capacity(limit);
    let mut later = VecDeque::with_capacity(limit + 1);
    let mut total = 0;
    let mut start = 0;
    let mut previous = None;
    let mut earliest_start = None;
    let mut earlier_count = 0;
    let mut duplicates_seen = HashSet::new();

    for (mut key, (ref row, perceptual_hash)) in row_map.iter().rev() {
        let mut row = row;
        let mut my_duplicates = Vec::new();

        if let Some(perceptual_hash) = &perceptual_hash {
            let duplicate_group = row.get::<i64, _>(4);

            if duplicate_group > 0 {
                if duplicates_seen.contains(&(perceptual_hash.clone(), duplicate_group)) {
                    continue;
                } else if let Some(duplicates) =
                    duplicates.get(&(perceptual_hash.clone(), duplicate_group))
                {
                    duplicates_seen.insert((perceptual_hash.clone(), duplicate_group));

                    let mut iter = duplicates.values();

                    key = iter.next().unwrap();

                    row = &row_map.get(key).unwrap().0;

                    my_duplicates = iter
                        .map(|key| key.hash.clone().unwrap())
                        .collect::<Vec<_>>();
                }
            }
        }

        total += 1;

        if query
            .start
            .as_ref()
            .map(|start| key < start)
            .unwrap_or(true)
        {
            if images.len() < limit {
                images.push(ImageData {
                    hash: key.hash.clone().unwrap(),

                    datetime: key.datetime,

                    medium: match row.get::<Option<i64>, _>(2) {
                        Some(0) => Medium::Video,
                        Some(_) => Medium::ImageWithVideo,
                        None => Medium::Image,
                    },

                    duplicates: my_duplicates,

                    tags: row
                        .get::<&str, _>(6)
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(Tag::from_str)
                        .collect::<Result<HashSet<_>>>()?,
                });
            } else {
                if earlier_count == 0 {
                    earliest_start = previous;
                }

                earlier_count = (earlier_count + 1) % limit;
            }
        } else {
            start += 1;

            if later.len() > limit {
                later.pop_front();
            }

            later.push_back(key.clone());
        }

        previous = Some(key);
    }

    Ok(ImagesResponse {
        start,
        total,
        later_start: if later.len() > limit {
            later.pop_front()
        } else {
            None
        },
        earliest_start: earliest_start.cloned(),
        images,
    })
}
