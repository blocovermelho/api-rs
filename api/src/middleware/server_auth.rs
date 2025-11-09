use std::sync::Arc;

use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use headers::{authorization::Bearer, Authorization, HeaderMapExt};
use http::StatusCode;
use reqwest::header::SEC_WEBSOCKET_PROTOCOL;

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

        let mut auth = req
            .headers
            .typed_try_get::<Authorization<Bearer>>()
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid Authorization header"))?
            .map(|it| it.0.token().to_string());

        let proto_start = "Authorization=";

        for ele in req.headers.get_all(SEC_WEBSOCKET_PROTOCOL) {
            if let Ok(value) = ele.to_str() {
                let protos: Vec<_> = value.split(",").map(str::trim).collect();

                if let Some(found) = protos.iter().find(|it| it.starts_with(proto_start)) {
                    auth = Some(found.trim_start_matches(proto_start).to_string());
                    break;
                }
            }
        }

        if let Some(auth) = auth {
            let token = app
                .db
                .get_token(auth.to_string())
                .await
                .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid token"))?;

            let server = app
                .db
                .get_server(&token.owner)
                .await
                .map_err(|_| (StatusCode::NOT_FOUND, "Server owned by token was not found"))?;

            Ok(Self(token, server))
        } else {
            Err((StatusCode::UNAUTHORIZED, "Missing Authorization header"))
        }
    }
}
