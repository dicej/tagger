//! This module provides the [images] function, which handles incoming GET /images requests, which retrieve an
//! optionally filtered sequence of media item metadata from the server.

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

/// Maximum number of media items to return if the client does not specify a limit
const DEFAULT_LIMIT: u32 = 1000;

/// Build an SQL query based on the specified `filter` which retrieves metadata for all matching media items,
/// appending the result to `buffer`.
///
/// If `filter` is `None`, all items in the database will be retrieved.
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

/// Handle a GET /images request by converting the specified `query` to the equivalent SQL query and collecting the
/// result as an `ImagesResponse` object.
pub async fn images(conn: &mut SqliteConnection, query: &ImagesQuery) -> Result<ImagesResponse> {
    // This function is currently somewhat inelegant since it queries the database for all matching items, sorts
    // them in memory, and scans the result to find the requested interval and gather pagination statistics.
    //
    // It may be more elegant to convert some or all of this logic to SQL and possibly avoid the sort and linear
    // scan.  Meanwhile, this works and performs well enough.

    let limit = usize::try_from(query.limit.unwrap_or(DEFAULT_LIMIT)).unwrap();

    // First, query the database, collecting the rows into a map sorted chronologically, and grouping any
    // duplicates together.

    let mut buffer = String::new();
    let mut rows = build_images_query(&mut buffer, query.filter.as_ref()).fetch(&mut *conn);
    let mut row_map = BTreeMap::new();
    let mut duplicates = HashMap::<_, BTreeMap<_, _>>::new();

    while let Some(row) = rows.try_next().await? {
        let key = ImageKey {
            datetime: row.get::<&str, _>(1).parse()?,
            hash: Some(Arc::from(row.get::<&str, _>(0))),
        };

        let duplicate_group = row.get::<Option<&str>, _>(3).map(Arc::<str>::from);
        let duplicate_index = row.get::<Option<i64>, _>(4);

        if let (Some(duplicate_group), Some(duplicate_index)) = (&duplicate_group, duplicate_index)
        {
            duplicates
                .entry(duplicate_group.clone())
                .or_default()
                .insert(duplicate_index, key.clone());
        }

        row_map.insert(key, (row, duplicate_group));
    }

    // Next, scan the map in reverse chronological order, consolidating duplicates and building `ImageData` objects
    // out of each row that falls within the requested interval.

    let mut images = Vec::with_capacity(limit);
    let mut later = VecDeque::with_capacity(limit + 1);
    let mut total = 0;
    let mut start = 0;
    let mut previous = None;
    let mut earliest_start = None;
    let mut earlier_count = 0;
    let mut duplicates_seen = HashSet::new();

    for (mut key, (ref row, duplicate_group)) in row_map.iter().rev() {
        let mut row = row;
        let mut my_duplicates = Vec::new();

        if let Some(duplicate_group) = &duplicate_group {
            if duplicates_seen.contains(duplicate_group) {
                continue;
            } else if let Some(duplicates) = duplicates.get(duplicate_group) {
                duplicates_seen.insert(duplicate_group.clone());

                let mut iter = duplicates.values();

                key = iter.next().unwrap();

                row = &row_map.get(key).unwrap().0;

                my_duplicates = iter
                    .map(|key| key.hash.clone().unwrap())
                    .collect::<Vec<_>>();
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
                        .get::<&str, _>(5)
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
