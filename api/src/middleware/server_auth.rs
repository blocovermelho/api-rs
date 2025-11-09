use std::sync::Arc;

use axum::{
    extract::{FromRef, FromRequestParts},
    headers::{authorization::Bearer, Authorization, HeaderMapExt},
};
use http::request::Parts;
use reqwest::StatusCode;

use crate::{
    db::{
        data::{ServerV2, Token},
        interface::DataSource,
    },
    AuthServer,
};

pub struct AuthorizedServer(pub Token, pub ServerV2);

#[async_trait::async_trait]
impl<S> FromRequestParts<S> for AuthorizedServer
where
    Arc<AuthServer>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(req: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app: Arc<AuthServer> = Arc::from_ref(state);

        let auth = req
            .headers
            .typed_try_get::<Authorization<Bearer>>()
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid Authorization header"))?
            .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header"))?;

        let token = app
            .db
            .get_token(auth.0.token().to_string())
            .await
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid token"))?;

        let server = app
            .db
            .get_server(&token.owner)
            .await
            .map_err(|_| (StatusCode::NOT_FOUND, "Server owned by token was not found"))?;

        Ok(Self(token, server))
    }
}
