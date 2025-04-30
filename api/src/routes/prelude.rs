pub use std::sync::Arc;

pub use axum::{
    extract::{Path, Query, State},
    Json,
};
pub use db::interface::DataSource;
pub use uuid::Uuid;

pub use crate::{
    routes::{Err, ErrKind, Res},
    AppState,
};

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
    struct InnerUuid {
        pub uuid: Uuid,
    }

    #[derive(Serialize, Deserialize)]
    pub struct LoginAttempt {
        pub uuid: Uuid,
        pub ip: Ipv4Addr,
        pub password: String,
    }

    #[derive(Deserialize)]
    struct InnerConnectionAttempt {
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
}
