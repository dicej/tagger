use {
    crate::warp_util::HttpError,
    anyhow::Result,
    http::{header, status::StatusCode, Response},
    hyper::Body,
    jsonwebtoken::{self, Algorithm, DecodingKey, EncodingKey, Header, Validation},
    sqlx::SqliteConnection,
    std::{
        num::NonZeroU32,
        ops::DerefMut,
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    },
    tagger_shared::{
        Authorization, TokenError, TokenErrorType, TokenRequest, TokenSuccess, TokenType,
    },
    tokio::{sync::Mutex as AsyncMutex, time},
    tracing::warn,
};

const TOKEN_EXPIRATION_SECS: u64 = 24 * 60 * 60;

pub fn hash_password(salt: &[u8], secret: &[u8]) -> String {
    let iterations = NonZeroU32::new(100_000).unwrap();
    const SIZE: usize = ring::digest::SHA256_OUTPUT_LEN;
    let mut hash: [u8; SIZE] = [0u8; SIZE];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        secret,
        &mut hash,
    );
    base64::encode(&hash)
}

pub async fn authenticate(
    conn: &AsyncMutex<SqliteConnection>,
    request: &TokenRequest,
    key: &[u8],
    mutex: &AsyncMutex<()>,
    invalid_credential_delay: Duration,
) -> Result<Response<Body>> {
    let _lock = mutex.lock().await;

    let hash = hash_password(request.username.as_bytes(), request.password.as_bytes());

    let permissions = sqlx::query!(
        "SELECT filter, may_patch FROM users WHERE name = ?1 AND password_hash = ?2",
        request.username,
        hash
    )
    .fetch_optional(conn.lock().await.deref_mut())
    .await?;

    Ok(if let Some(permissions) = permissions {
        let expiration = (SystemTime::now() + Duration::from_secs(TOKEN_EXPIRATION_SECS))
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        let success = TokenSuccess {
            access_token: jsonwebtoken::encode(
                &Header::new(Algorithm::HS256),
                &Authorization {
                    expiration: Some(expiration),
                    subject: Some(request.username.clone()),
                    filter: permissions.filter.map(|s| s.parse()).transpose()?,
                    may_patch: permissions.may_patch != 0,
                },
                &EncodingKey::from_secret(key),
            )?,
            token_type: TokenType::Jwt,
        };

        let json = serde_json::to_vec(&success)?;

        crate::response()
            .header(header::CONTENT_LENGTH, json.len())
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json))?
    } else {
        warn!("received invalid credentials; delaying response");

        time::sleep(invalid_credential_delay).await;

        let error = serde_json::to_vec(&TokenError {
            error: TokenErrorType::UnauthorizedClient,
            error_description: None,
        })?;

        crate::response()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::CONTENT_LENGTH, error.len())
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(error))?
    })
}

pub async fn authenticate_anonymous(
    conn: &AsyncMutex<SqliteConnection>,
    key: &[u8],
) -> Result<Response<Body>> {
    let permissions = sqlx::query!(
        "SELECT filter, may_patch FROM users WHERE name IS NULL AND password_hash IS NULL"
    )
    .fetch_optional(conn.lock().await.deref_mut())
    .await?;

    Ok(if let Some(permissions) = permissions {
        let expiration = (SystemTime::now() + Duration::from_secs(TOKEN_EXPIRATION_SECS))
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        let success = TokenSuccess {
            access_token: jsonwebtoken::encode(
                &Header::new(Algorithm::HS256),
                &Authorization {
                    expiration: Some(expiration),
                    subject: None,
                    filter: permissions.filter.map(|s| s.parse()).transpose()?,
                    may_patch: permissions.may_patch != 0,
                },
                &EncodingKey::from_secret(key),
            )?,
            token_type: TokenType::Jwt,
        };

        let json = serde_json::to_vec(&success)?;

        crate::response()
            .header(header::CONTENT_LENGTH, json.len())
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json))?
    } else {
        let error = serde_json::to_vec(&TokenError {
            error: TokenErrorType::UnauthorizedClient,
            error_description: None,
        })?;

        crate::response()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::CONTENT_LENGTH, error.len())
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(error))?
    })
}

pub fn authorize(token: &str, key: &[u8]) -> Result<Arc<Authorization>, HttpError> {
    Ok(Arc::new(
        jsonwebtoken::decode::<Authorization>(
            token,
            &DecodingKey::from_secret(key),
            &Validation::new(Algorithm::HS256),
        )
        .map_err(|e| {
            warn!("received invalid token: {}: {:?}", token, e);

            HttpError::from_slice(StatusCode::UNAUTHORIZED, "invalid token")
        })?
        .claims,
    ))
}
