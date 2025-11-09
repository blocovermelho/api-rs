use std::collections::HashSet;

use axum::{http::StatusCode, Json};

use crate::db::data::Token;

pub mod discord;
pub mod game_server;
pub mod profile;

pub type JsonResult<T, E> = Result<Json<T>, (StatusCode, E)>;
pub type StringResult<E> = Result<String, (StatusCode, E)>;

macro_rules! scopes {
    ($s:expr, [$($x:expr),+]) => {
        if (!crate::routes::check_scopes(&$s, &[$($x),+])) {
            return Err((
                axum::http::StatusCode::UNAUTHORIZED,
                format!("Token without the {} scope(s).", &[$($x),+].join(", ")),
            ));
        }
    }
}

pub(crate) use scopes;

pub fn check_scopes(token: &Token, scopes: &[&'static str]) -> bool {
    let token: HashSet<_> = token.scopes.0.iter().cloned().collect();
    let check: HashSet<_> = scopes
        .iter()
        .map(std::string::ToString::to_string)
        .collect();

    token.is_superset(&check)
}

pub mod query_params {
    use std::net::Ipv4Addr;

    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct LinkQuery {
        pub state: String,
        pub code: String,
    }

    #[derive(Deserialize)]
    pub struct ManualLink {
        pub username: String,
        pub token: String,
    }

    #[derive(Deserialize)]
    pub struct IpQuery {
        pub ip: Ipv4Addr,
    }

    #[derive(Deserialize)]
    pub struct LoginQuery {
        pub ip: Ipv4Addr,
        pub password: String,
    }

    #[derive(Deserialize)]
    pub struct ProfileQuery {
        pub username: String,
        pub xuid: Option<u64>,
    }

    #[derive(Deserialize)]
    pub struct UsernameQuery {
        pub username: String,
    }
    #[derive(Deserialize)]
    pub struct IdQuery {
        pub id: uuid::Uuid,
    }
    #[derive(Deserialize)]
    pub struct PasswordChange {
        pub old: String,
        pub new: String,
    }
}

pub mod body {
    use serde::Deserialize;
    use uuid::Uuid;

    #[derive(Deserialize)]
    pub struct BedrockAccount {
        pub gamertag: String,
        pub xuid: Option<u64>,
    }

    #[derive(Deserialize)]
    pub struct MojangApiId {
        pub name: String,
        pub id: Uuid,
    }

    #[derive(Deserialize)]
    pub struct NewProfile {
        pub password: String,
        pub discord_id: String,
    }
}

pub mod results {

    use serde::Serialize;
    use uuid::Uuid;

    use crate::core::types::enums::ConnectionData;

    #[derive(Serialize)]
    pub struct Profile {
        pub id: Uuid,
        pub username: String,
        pub discord_id: String,
        pub connections: Vec<Connection>,
    }
    #[derive(Serialize)]
    pub struct Connection {
        pub issuer: Option<Uuid>,
        pub extra: ConnectionData,
    }

    #[derive(Serialize)]
    pub struct Server {
        pub id: Uuid,
        pub name: String,
        pub game: String,
        pub versions: Vec<String>,
        pub max_players: i32,
        pub staff: Vec<Profile>,
    }

    #[derive(Serialize)]
    #[serde(tag = "kind", content = "data", rename_all = "snake_case")]
    pub enum MojangAccountStanding {
        KnownProfile {
            profile: Profile,
        },
        RenamedProfile {
            profile: Profile,
            mojang_name: String,
        },
        UnknownUser {
            mojang_uuid: Uuid,
            mojang_name: String,
        },
        InvalidName,
    }
    #[derive(Serialize)]
    #[serde(tag = "kind", content = "data", rename_all = "snake_case")]
    pub enum BedrockAccountStanding {
        KnownProfile { profile: Profile },
        RenamedProfile { profile: Profile, gamertag: String },
        UnknownUser { gamertag: String, xuid: Option<u64> },
    }

    #[derive(Serialize)]
    #[serde(tag = "kind", content = "data", rename_all = "snake_case")]
    pub enum Login {
        NewIp,
        AllowedIp,
        BannedIp,
        BlockedIp,
    }

    #[derive(Serialize)]
    #[serde(tag = "kind", content = "data", rename_all = "snake_case")]
    pub enum Authenticate {
        ServerOffline,
        InvalidPassword { attempts: i32, max_attempts: i32 },
        InvalidProfile,
        LoggedIn,
    }

    #[derive(Serialize)]
    #[serde(tag = "kind", content = "data", rename_all = "snake_case")]
    pub enum Logout {
        ServerOffline,
        ProfileNotInServer,
        LoggedOut,
    }

    #[derive(Serialize)]
    #[serde(tag = "kind", content = "data", rename_all = "snake_case")]
    pub enum PasswordUpdate {
        ServerOffline,
        ProfileNotInServer,
        InvalidPlayerState,
        InvalidPassword,
        PasswordChanged,
    }

    #[derive(Serialize)]
    #[serde(tag = "kind", content = "data", rename_all = "snake_case")]
    pub enum CreateProfile {
        UsernameExists,
        Created(Uuid),
    }
}
