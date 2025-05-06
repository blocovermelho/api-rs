pub use std::sync::Arc;

pub use axum::{
    extract::{Path, Query, State},
    Json,
};
pub use db::interface::DataSource;
pub use uuid::Uuid;

pub use crate::AppState;

pub mod types {
    use axum::{response::IntoResponse, Json};
    use reqwest::StatusCode;
    use serde::Serialize;

    pub type Res<T> = Result<Json<T>, ErrKind>;

    #[derive(Serialize, Clone)]
    pub struct Err {
        pub error: String,
        pub inner: Option<String>,
    }

    impl Err {
        pub fn new(message: impl ToString) -> Self {
            Self { error: message.to_string(), inner: None }
        }

        pub fn with_inner(&mut self, inner: impl ToString) -> Self {
            self.inner = Some(inner.to_string());
            self.clone()
        }
    }

    pub enum ErrKind {
        NotFound(Err),
        Internal(Err),
        BadRequest(Err),
    }

    impl IntoResponse for ErrKind {
        fn into_response(self) -> axum::response::Response {
            match self {
                Self::NotFound(e) => (StatusCode::NOT_FOUND, Json(e)).into_response(),
                Self::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(e)).into_response(),
                Self::BadRequest(e) => (StatusCode::BAD_REQUEST, Json(e)).into_response(),
            }
        }
    }
}

pub use types::*;

pub mod query_params {
    use std::net::Ipv4Addr;

    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    #[derive(Serialize, Deserialize)]
    pub struct ChangePassword {
        pub uuid: Uuid,
        pub old: String,
        pub new: String,
    }

    #[derive(Deserialize)]
    pub struct InnerUuid {
        pub uuid: Uuid,
    }

    #[derive(Serialize, Deserialize)]
    pub struct LoginAttempt {
        pub uuid: Uuid,
        pub ip: Ipv4Addr,
        pub password: String,
    }

    #[derive(Deserialize)]
    pub struct InnerConnectionAttempt {
        pub uuid: Uuid,
        pub ip: Ipv4Addr,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub server: Option<Uuid>,
    }

    #[derive(Deserialize)]
    pub struct DiscordLink {
        pub code: String,
        pub state: String,
    }

    #[derive(Deserialize)]
    pub struct MigrateAccount {
        pub old: String,
        pub new: String,
    }

    pub type OfflineUuid = InnerUuid;
    pub type MojangUuid = InnerUuid;
    pub type ServerUuid = InnerUuid;
    pub type MigrationUuid = InnerUuid;

    pub type IpCheck = InnerConnectionAttempt;
    pub type BanIp = InnerConnectionAttempt;
    pub type AllowIp = InnerConnectionAttempt;
}

pub mod responses {
    use chrono::{DateTime, Utc};
    use serde::Serialize;
    use uuid::Uuid;

    #[derive(Serialize, Clone, Debug)]
    pub struct LinkResult {
        pub discord_id: String,
        pub discord_username: String,
        pub when: DateTime<Utc>,
        pub minecraft_uuid: Uuid,
    }

    #[derive(Serialize, Clone)]
    pub enum BanKind {
        Existing,
        Merged,
        New,
        Invalid,
    }

    #[derive(Serialize)]
    pub enum IpKind {
        Allowed,
        Banned,
        Unknown,
    }
}
