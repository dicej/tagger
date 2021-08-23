use {
    anyhow::Result,
    futures::TryStreamExt,
    http::status::StatusCode,
    http::Response,
    hyper::Body,
    sqlx::{Row, SqliteConnection},
    std::{collections::HashMap, ops::Deref, sync::Arc},
    tagger_shared::{
        tag_expression::TagExpression, Action, Authorization, Patch, TagsQuery, TagsResponse,
    },
};

async fn visible(conn: &mut SqliteConnection, filter: &TagExpression, hash: &str) -> Result<bool> {
    Ok(crate::bind_filter_clause(
        filter,
        sqlx::query(&format!(
            "SELECT 1 as x FROM tags WHERE hash = ?1 AND {}",
            {
                let mut buffer = String::new();
                crate::append_filter_clause(&mut buffer, filter);
                buffer
            }
        ))
        .bind(hash),
    )
    .fetch_optional(&mut *conn)
    .await?
    .is_some())
}

pub async fn apply(
    auth: &Authorization,
    conn: &mut SqliteConnection,
    patches: &[Patch],
) -> Result<Response<Body>> {
    if !auth.may_patch {
        return Ok(crate::response()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::empty())?);
    }

    if let Some(filter) = &auth.filter {
        for patch in patches {
            if !(filter.evaluate(&patch.tag) && visible(conn, filter, &patch.hash).await?) {
                return Ok(crate::response()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Body::empty())?);
            }
        }
    }

    for patch in patches {
        if let Some(category) = &patch.tag.category {
            let category = category.deref();

            if let Some(row) =
                sqlx::query!("SELECT immutable FROM categories WHERE name = ?1", category)
                    .fetch_optional(&mut *conn)
                    .await?
            {
                if row.immutable != 0 {
                    return Ok(crate::response()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(Body::empty())?);
                }
            }
        }
    }

    for patch in patches {
        let value = patch.tag.value.deref();

        match patch.action {
            Action::Add => {
                let category = patch.tag.category.as_deref();

                sqlx::query!(
                    "INSERT OR IGNORE INTO tags (hash, tag, category) VALUES (?1, ?2, ?3)",
                    patch.hash,
                    value,
                    category
                )
                .execute(&mut *conn)
                .await?;
            }

            Action::Remove => {
                if let Some(category) = &patch.tag.category {
                    let category = category.deref();

                    sqlx::query!(
                        "DELETE FROM tags WHERE hash = ?1 AND tag = ?2 AND category = ?3",
                        patch.hash,
                        value,
                        category
                    )
                    .execute(&mut *conn)
                    .await?;
                } else {
                    sqlx::query!(
                        "DELETE FROM tags WHERE hash = ?1 AND tag = ?2 AND category IS NULL",
                        patch.hash,
                        value
                    )
                    .execute(&mut *conn)
                    .await?;
                }
            }
        }
    }

    Ok(crate::response().body(Body::empty())?)
}

fn entry<'a>(
    response: &'a mut TagsResponse,
    parents: &HashMap<Arc<str>, Arc<str>>,
    category: &Arc<str>,
) -> &'a mut TagsResponse {
    if let Some(parent) = parents.get(category) {
        entry(response, parents, parent)
    } else {
        response
    }
    .categories
    .entry(category.clone())
    .or_insert_with(TagsResponse::default)
}

pub async fn tags(conn: &mut SqliteConnection, query: &TagsQuery) -> Result<TagsResponse> {
    let select = format!(
        "SELECT (SELECT parent from categories where name = t.category), \
                (SELECT immutable from categories where name = t.category), \
                t.category, \
                t.tag, \
                count(i.hash) \
         FROM images i \
         LEFT JOIN tags t \
         ON i.hash = t.hash \
         WHERE {} AND t.hash IS NOT NULL \
         GROUP BY t.category, t.tag",
        if let Some(filter) = &query.filter {
            let mut buffer = String::new();
            crate::append_filter_clause(&mut buffer, filter);
            buffer
        } else {
            "1".into()
        }
    );

    let mut select = sqlx::query(&select);

    if let Some(filter) = &query.filter {
        select = crate::bind_filter_clause(filter, select);
    }

    let mut parents = HashMap::new();
    let mut category_tags = HashMap::new();
    let mut category_immutable = HashMap::new();
    let mut tags = HashMap::new();

    let mut rows = select.fetch(&mut *conn);

    while let Some(row) = rows.try_next().await? {
        let tag = Arc::from(row.get::<&str, _>(3));
        let count = row.get(4);

        if let Some(category) = row.get::<Option<&str>, _>(2) {
            let category = Arc::<str>::from(category);

            if let Some(immutable) = row.get::<Option<bool>, _>(1) {
                category_immutable.insert(category.clone(), immutable);
            }

            if let Some(parent) = row.get::<Option<&str>, _>(0) {
                parents.insert(category.clone(), Arc::from(parent));
            }

            category_tags
                .entry(category)
                .or_insert_with(HashMap::new)
                .insert(tag, count);
        } else {
            tags.insert(tag, count);
        }
    }

    let mut response = TagsResponse {
        immutable: None,
        categories: HashMap::new(),
        tags,
    };

    for (category, tags) in category_tags {
        let entry = entry(&mut response, &parents, &category);

        entry.tags = tags;
        entry.immutable = category_immutable.get(&category).cloned();
    }

    Ok(response)
}
