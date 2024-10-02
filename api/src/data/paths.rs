
/*
The new routing:
- /meta : General Metadata
- /user : User-related data
- /server : Server-related data
- /session : BV-Auth Session Server
- /auth : Authentication
 */

use axum_macros::TypedPath;
use serde::Deserialize;
use uuid::Uuid;

#[derive(TypedPath, Deserialize)]
#[typed_path("/meta")]
pub struct Metadata;

#[derive(TypedPath, Deserialize)]
#[typed_path("/meta/mojauth/by-name/:name")]
pub struct GetMojUuid {
    pub name: String
}

#[derive(TypedPath, Deserialize)]
#[typed_path("/users/by-discord-id/:discord_id")]
pub struct GetUsersForDiscordId {
    pub discord_id: u64
}

#[derive(TypedPath, Deserialize)]
#[typed_path("/user")]
pub struct User;

#[derive(TypedPath, Deserialize)]
#[typed_path("/user/by-uuid/:uuid")]
pub struct GetUserByUuid {
    pub uuid: Uuid
}

#[derive(TypedPath, Deserialize)]
#[typed_path("/server/by-name/:name")]
pub struct GetServerByName {
    pub name: String
}

#[derive(TypedPath, Deserialize)]
#[typed_path("/server/by-uuid/:uuid")]
pub struct GetServerByUuid {
    pub uuid: Uuid
}

