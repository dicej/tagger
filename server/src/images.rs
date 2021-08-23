use {
    anyhow::Result,
    futures::TryStreamExt,
    sqlx::{query::Query, sqlite::SqliteArguments, Row, Sqlite, SqliteConnection},
    std::{
        collections::{HashSet, VecDeque},
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

    let mut sorted = Vec::new();

    while let Some(row) = rows.try_next().await? {
        sorted.push((
            ImageKey {
                datetime: row.get::<&str, _>(1).parse()?,
                hash: Some(Arc::from(row.get::<&str, _>(0))),
            },
            row,
        ));
    }

    sorted.sort_by(|(a, _), (b, _)| b.cmp(a));

    let mut images = Vec::with_capacity(limit);
    let mut later = VecDeque::with_capacity(limit + 1);
    let mut total = 0;
    let mut start = 0;
    let mut previous = None;
    let mut earliest_start = None;
    let mut earlier_count = 0;

    for (key, row) in sorted.into_iter() {
        total += 1;

        if query
            .start
            .as_ref()
            .map(|start| &key < start)
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
                    tags: row
                        .get::<&str, _>(3)
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
        earliest_start,
        images,
    })
}
