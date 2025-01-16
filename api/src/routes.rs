use std::{collections::HashSet, net::Ipv4Addr, sync::Arc, time::Duration};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use bv_discord::utils::notify;
use chrono::{DateTime, Utc};
use db::{
    data::{
        result::{NodeDeletion, ServerJoin},
        stub::{AccountStub, ServerStub, UserStub},
        BanActor, Migration, Server, User, Viewport,
    },
    drivers::err::{
base::{InvalidError, NotFoundError},
DriverError,
},
    interface::{DataSource, NetworkProvider},
};
use futures::SinkExt;
use oauth2::{reqwest::async_http_client, AuthorizationCode};
use serde::{Deserialize, Serialize};
use serenity::all::{GuildId, RoleId, UserId};
use uuid::Uuid;
use uuid_mc::PlayerUuid;

use crate::{
    cidr::{lowest_common_prefix, MIN_COMMON_PREFIX},
    models::{BanIssuer, BanResponse, CidrResponse},
    websocket::MessageOut,
    AppState,
};

pub type Res<T> = Result<Json<T>, ErrKind>;
pub const MAX_ATTEMPTS_PER_ACC: i32 = 5;

#[derive(Serialize, Clone)]
pub struct Err {
    pub error: String,
    pub inner: Option<String>,
}

#[allow(clippy::needless_pass_by_value)]
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

/// [GET] /api/link?state=<>&code=<>
pub async fn link(
    State(state): State<Arc<AppState>>, Query(link): Query<LinkQueryParams>,
) -> Res<LinkResult> {
    let eph = state.ephemeral.lock().await;
    let uuid = eph.links.get_by_right(&link.state).ok_or_else(|| {
        ErrKind::NotFound(Err::new("Tried getting an user that hasn't started linking yet."))
    })?;

    let client = oauth::routes::get_client(&state.config).map_err(|e| {
        ErrKind::Internal(Err::new("Error while getting a BasicClient").with_inner(e))
    })?;

    let response = client
        .exchange_code(AuthorizationCode::new(link.code))
        .request_async(async_http_client)
        .await;

    let token = response.map_err(|e| {
        ErrKind::Internal(Err::new("Couldn't exchange the code for a discord user.").with_inner(e))
    })?;

    let member = oauth::routes::get_guild(&state.client.reqwest, &token, &state.config).await.map_err(|e| {
        ErrKind::Internal(Err::new("Provided discord User didn't had a valid Guild Member object. Are you on the discord guild?").with_inner(e))
    })?;

    let link_result = LinkResult {
        discord_id: member.user.id,
        discord_username: member.user.username,
        when: member.joined_at,
        minecraft_uuid: *uuid,
    };

    let mut buff = state.channel.messages.0.lock().await;
    let _ = buff
        .send(MessageOut::LinkResponse(link_result.clone()))
        .await;

    Ok(Json(link_result))
}

/// [GET] /api/oauth?uuid=<ID>
pub async fn discord(
    State(state): State<Arc<AppState>>, Query(uuid): Query<UuidQueryParam>,
) -> Res<String> {
    let mut data = state.ephemeral.lock().await;

    let client = oauth::routes::get_client(&state.config).map_err(|e| {
        ErrKind::Internal(Err::new("Error while getting a BasicClient").with_inner(e))
    })?;

    let (url, token) = oauth::routes::authorize(&client).url();

    data.links.insert(uuid.uuid, token.secret().clone());

    Ok(Json(url.to_string()))
}

/// [GET] /api/users
pub async fn get_users(State(state): State<Arc<AppState>>) -> Res<Vec<Uuid>> {
    let data = state.db.get_all_users().await.map_err(|e| {
        ErrKind::Internal(Err::new("Couldn't get all users").with_inner(format!("{:?}", e)))
    })?;
    Ok(Json(data))
}

/// [GET] /`api/user/:user_id`
pub async fn get_user(State(state): State<Arc<AppState>>, Path(user_id): Path<Uuid>) -> Res<User> {
    let data = state
        .db
        .get_user_by_uuid(&user_id)
        .await
        .map_err(|_| ErrKind::Internal(Err::new("User not found.")))?;

    Ok(Json(data))
}

/// [GET] /api/user/by-name/:username
pub async fn get_user_by_name(
    State(state): State<Arc<AppState>>, Path(username): Path<String>,
) -> Res<User> {
    let data = state
        .db
        .get_user_by_name(username)
        .await
        .map_err(|_| ErrKind::Internal(Err::new("User not found.")))?;

    Ok(Json(data))
}

/// [GET] /api/user/by-discord/:discordId
pub async fn get_user_by_discord(
    State(state): State<Arc<AppState>>, Path(discord_id): Path<u64>,
) -> Res<Vec<User>> {
    let data = state
        .db
        .get_users_by_discord_id(discord_id.to_string())
        .await
        .map_err(|_| ErrKind::Internal(Err::new("User not found.")))?;

    Ok(Json(data))
}

/// [GET] /api/user/exists?uuid=<uuid>
pub async fn user_exists(
    State(state): State<Arc<AppState>>, Query(user_id): Query<UuidQueryParam>,
) -> Res<bool> {
    let data = state.db.get_user_by_uuid(&user_id.uuid).await;

    Ok(Json(data.is_ok()))
}

/// [DELETE] /`api/user/:user_id`
pub async fn delete_user(State(state): State<Arc<AppState>>, Path(user): Path<Uuid>) -> Res<User> {
    let user = state.db.delete_user(&user).await.map_err(|e| {
        ErrKind::Internal(Err::new("Couldn't flush data for User").with_inner(format!("{:?}", e)))
    })?;

    Ok(Json(user))
}

/// [POST] /api/user
pub async fn create_user(
    State(state): State<Arc<AppState>>, Json(stub): Json<UserStub>,
) -> Res<User> {
    let user = state
        .db
        .create_user(stub)
        .await
        .map_err(|_| ErrKind::BadRequest(Err::new("This user already exists.")))?;

    Ok(Json(user))
}

/// [GET] /api/servers
pub async fn get_servers(State(state): State<Arc<AppState>>) -> Res<Vec<Uuid>> {
    let data = state.db.get_all_servers().await.map_err(|e| {
        ErrKind::Internal(Err::new("Couldn't get all servers").with_inner(format!("{:?}", e)))
    })?;

    Ok(Json(data))
}

/// [GET] /`api/server/:server_id`
pub async fn get_server(
    State(state): State<Arc<AppState>>, Path(server_uuid): Path<Uuid>,
) -> Res<Server> {
    let data = state
        .db
        .get_server(&server_uuid)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Server not found.")))?;

    Ok(Json(data))
}

/// [DELETE] /`api/server/:user_id`
pub async fn delete_server(
    State(state): State<Arc<AppState>>, Path(server_uuid): Path<Uuid>,
) -> Res<Server> {
    let data = state
        .db
        .delete_server(&server_uuid)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Server not found.")))?;

    Ok(Json(data))
}

/// [POST] /api/server
pub async fn create_server(
    State(state): State<Arc<AppState>>, Json(stub): Json<ServerStub>,
) -> Res<Server> {
    let data = state
        .db
        .create_server(stub)
        .await
        .map_err(|_| ErrKind::BadRequest(Err::new("Server already exists.")))?;

    Ok(Json(data))
}

/// [PATCH] /`api/server/:server_id/enable`
pub async fn enable(State(state): State<Arc<AppState>>, Path(server_id): Path<Uuid>) -> Res<bool> {
    let status = state
        .db
        .update_server_status(&server_id, true)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Server not found.")))?;

    Ok(Json(status))
}

/// [PATCH] /`api/server/:server_id/disable`
pub async fn disable(State(state): State<Arc<AppState>>, Path(server_id): Path<Uuid>) -> Res<bool> {
    let status = state
        .db
        .update_server_status(&server_id, false)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Server not found.")))?;

    Ok(Json(status))
}

/// [GET] /api/auth/session?uuid=<ID>&ip=<IP>
pub async fn get_session(
    State(state): State<Arc<AppState>>, Query(session): Query<SessionQueryParams>,
) -> Res<bool> {
    let now = chrono::offset::Utc::now();

    let entries = state
        .db
        .get_allowlists_with_ip(&session.uuid, session.ip)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Account not found.")))?;

    for entry in entries {
        let diff = now - entry.last_join;
        if diff.num_minutes() <= 10 {
            // Bump that entry since it was a successful match.
            let _ = state.db.bump_allowlist(entry).await;

            state.db.update_current_join(&session.uuid).await.unwrap();
            return Ok(Json(true));
        }
    }

    // Automatically broaden netmask on user login
    let broad = state
        .db
        .get_allowlists_with_range(&session.uuid, session.ip, MIN_COMMON_PREFIX)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Account not found.")))?;

    for entry in broad {
        let diff = now - entry.last_join;
        // Calculate new netmask
        let nmask = lowest_common_prefix(&entry.get_network(), &session.ip).unwrap();
        // Update the netmask
        let _ = state.db.broaden_allowlist_mask(entry.clone(), nmask).await;

        if diff.num_minutes() <= 10 {
            // Bump that entry since it was a successful match.
            let _ = state.db.bump_allowlist(entry).await;

            state.db.update_current_join(&session.uuid).await.unwrap();

            return Ok(Json(true));
        }
    }

    Ok(Json(false))
}

/// [PATCH] /api/auth/resume?uuid=<ID>&ip=<IP>
pub async fn resume(
    State(state): State<Arc<AppState>>, Query(session): Query<SessionQueryParams>,
) -> Res<bool> {
    let user = state
        .db
        .get_user_by_uuid(&session.uuid)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("User not found.")))?;

    let entries = state
        .db
        .get_allowlists_with_ip(&session.uuid, session.ip)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Account not found.")))?;

    for entry in entries {
        let _ = state.db.bump_allowlist(entry).await;
    }

    let cfg = &state.config;
    let client = &state.client.serenity;

    state.db.update_current_join(&session.uuid).await.unwrap();

    let _ = client
        .http
        .add_member_role(
            GuildId::new(cfg.guild_id.parse().unwrap()),
            UserId::new(user.discord_id.parse().unwrap()),
            RoleId::new(cfg.role_id.parse().unwrap()),
            None,
        )
        .await;

    Ok(Json(true))
}

/// [POST] /`api/auth/:server_id/logoff?uuid`=<ID>&ip=<IP>
/// ```json
/// {
///   "loc": {
///       "x": 0,
///       "z": 0,
///       "y": 64,
///       "dim": "minecraft:overworld"
///   },
///   "yaw": 0,
///   "pitch": 0
/// }
/// ```
pub async fn logoff(
    State(state): State<Arc<AppState>>, Path(server_id): Path<Uuid>,
    Query(session): Query<SessionQueryParams>, Json(pos): Json<Viewport>,
) -> Res<bool> {
    let cfg = &state.config;
    let client = &state.client.serenity;

    let user = state
        .db
        .get_user_by_uuid(&session.uuid)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("User not found.")))?;

    let server = state
        .db
        .get_server(&server_id)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Server not found.")))?;

    let account = state
        .db
        .get_account(&session.uuid)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Account not foumd.")))?;

    if let Err(DriverError::DatabaseError(NotFoundError::UserData{ server_uuid: _, player_uuid: _ })) = state
        .db
        .get_viewport(&session.uuid, &server.uuid)
        .await
       
    {
        let _ = state.db.create_savedata(&session.uuid, &server.uuid).await;
    }
    
    state
        .db
        .update_viewport(&session.uuid, &server.uuid, pos)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("SaveData not found.")))?;

    let now = chrono::offset::Utc::now();

    let mut playtime = state
        .db
        .get_playtime(&session.uuid, &server.uuid)
        .await
        .unwrap_or_default();

    let delta = (now - account.current_join).to_std().unwrap();

    playtime += delta;

    state
        .db
        .update_playtime(&session.uuid, &server.uuid, playtime)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("SaveData not found.")))?;

    state
        .db
        .leave_server(&server.uuid, &session.uuid)
        .await
        .unwrap();


    // Bump allowlists at logoff.
    if let Ok(entries) = state
        .db
        .get_allowlists_with_ip(&session.uuid, session.ip)
        .await
    {
        for entry in entries {
            let _ = state.db.bump_allowlist(entry).await;
        }
    }

    let _ = client
        .http
        .remove_member_role(
            GuildId::new(cfg.guild_id.parse().unwrap()),
            UserId::new(user.discord_id.parse().unwrap()),
            RoleId::new(cfg.role_id.parse().unwrap()),
            None,
        )
        .await;

    Ok(Json(true))
}

/// [POST] /`api/auth/:server_id/login`
/// ```json
/// {
///     "uuid": "743a0a05-8929-4383-a564-edc983ea0231",
///     "ip": "127.0.0.1",
///     "pass": "password123"
/// }
/// ```
pub async fn login(
    State(state): State<Arc<AppState>>, Path(server_id): Path<Uuid>,
    Json(session): Json<AuthenticationQueryParams>,
) -> Res<Option<ServerJoin>> {
    let cfg = &state.config;
    let client = &state.client.serenity;
    let mut eph = state.ephemeral.lock().await;

    let _ = state
        .db
        .get_server(&server_id)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Server not found.")))?;

    let user = state
        .db
        .get_user_by_uuid(&session.uuid)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("User not found.")))?;

    let account = state
        .db
        .get_account(&user.uuid)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Account not found.")))?;

    let password = bcrypt::verify(session.password, &account.password)
        .map_err(|e| ErrKind::Internal(Err::new("BCrypt Error.".to_string()).with_inner(e)))?;

    if !password {
        let mut count = 1;

        if eph.password.contains_key(&session.uuid) {
            count = *(eph.password.get(&session.uuid).unwrap());
            count += 1;
        }

        eph.password.insert(session.uuid, count);

        if count >= MAX_ATTEMPTS_PER_ACC {
            Err(ErrKind::BadRequest(Err::new("Exhausted MAX_ATTEMPTS for this account.")))
        } else {
            Ok(Json(None))
        }
    } else {
        eph.password.remove(&session.uuid);

        state.db.update_current_join(&session.uuid).await.unwrap();

        let res = state
            .db
            .join_server(&server_id, &session.uuid)
            .await
            .unwrap();

        if matches!(res, ServerJoin::FirstJoin) {
            let _ = state.db.create_savedata(&session.uuid, &server_id).await;
        }

        let _ = client
            .http
            .add_member_role(
                GuildId::new(cfg.guild_id.parse().unwrap()),
                UserId::new(user.discord_id.parse().unwrap()),
                RoleId::new(cfg.role_id.parse().unwrap()),
                None,
            )
            .await;

        Ok(Json(Some(res)))
    }
}

/// [GET] /auth/exists?uuid=<uuid>
pub async fn account_exists(
    State(state): State<Arc<AppState>>, Query(account): Query<UuidQueryParam>,
) -> Res<bool> {
    let data = state.db.get_account(&account.uuid).await;

    Ok(Json(data.is_ok()))
}

/// [POST] /auth/migrate?old=<old_username>&new=<new_username>
pub async fn create_migration(
    State(state): State<Arc<AppState>>, Query(migrate): Query<MigrateQueryParam>,
) -> Res<Migration> {
    let old_user = state
        .db
        .get_user_by_name(migrate.old.clone())
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Old user not found.")))?;

    let mut new_user = state.db.get_user_by_name(migrate.new.clone()).await;

    if new_user.is_err() {
        let user_uuid = PlayerUuid::new_with_offline_username(&migrate.new);
        new_user = state
            .db
            .create_user(UserStub {
                uuid: *user_uuid.as_uuid(),
                username: migrate.new.clone(),
                discord_id: old_user.discord_id,
            })
            .await;
    }

    let new_user =
        new_user.map_err(|_| ErrKind::Internal(Err::new("Couldn't get or create New User")))?;

    // If the new account already has a pending migration, return that pending migration and dont create a new one.
    if let Some(id) = new_user.current_migration {
        let migration =
            state.db.get_migration(&id).await.map_err(|_| {
                ErrKind::NotFound(Err::new("Invalid Current Migration for New User."))
            })?;

        // Migration hasn't finished yet.
        if migration.finished_at.is_none() {
            return Ok(Json(migration));
        }
    }

    // We now should create a new migration
    let migration = state
        .db
        .create_migration(
            migrate.old,
            migrate.new,
            old_user.current_migration.or(new_user.current_migration),
        )
        .await
        .map_err(|e| ErrKind::Internal(Err::new("Couldn't create migration").with_inner(e)))?;

    // And set it as the current migration for the new user.
    let _ = state
        .db
        .set_current_migration(&new_user.uuid, Some(migration.id))
        .await
        .map_err(|e| {
            ErrKind::Internal(Err::new("Couldn't set Current Migration for New User").with_inner(e))
        })?;

    Ok(Json(migration))
}

/// [GET] /auth/migration?id=<uuid>
pub async fn get_migration(
    State(state): State<Arc<AppState>>, Query(migration_id): Query<UuidQueryParam>,
) -> Res<Migration> {
    let migration = state
        .db
        .get_migration(&migration_id.uuid)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Migration not found.")))?;

    Ok(Json(migration))
}

/// [DELETE] /auth/migration?id=<uuid>
pub async fn delete_migration(
    State(state): State<Arc<AppState>>, Query(migration_id): Query<UuidQueryParam>,
) -> Res<bool> {
    let migration = state
        .db
        .get_migration(&migration_id.uuid)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Migration not found.")))?;

    let new_user = state
        .db
        .get_user_by_name(migration.new)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("New User not found.")))?;

    let node = state
        .db
        .delete_migration(&migration_id.uuid)
        .await
        .map_err(|e| ErrKind::Internal(Err::new("Couldn't delete Migration").with_inner(e)))?;

    match node {
        NodeDeletion::Middle | NodeDeletion::First { is_orphan: false } => {}
        NodeDeletion::First { is_orphan: true } => {
            state
                .db
                .set_current_migration(&new_user.uuid, None)
                .await
                .map_err(|e| {
                    ErrKind::Internal(
                        Err::new("Couldn't update user state. Orphaned Node.").with_inner(e),
                    )
                })?;
        }
        NodeDeletion::Last { replacement } => {
            state
                .db
                .set_current_migration(&new_user.uuid, Some(replacement))
                .await
                .map_err(|e| {
                    ErrKind::Internal(
                        Err::new("Couldn't update user state. Last Node.").with_inner(e),
                    )
                })?;
        }
    }

    Ok(Json(true))
}

/// [POST] /server/<uuid>/migrated?id=<uuid>
pub async fn mark_migrated(
    State(state): State<Arc<AppState>>, Path(server_id): Path<Uuid>,
    Query(migration_id): Query<UuidQueryParam>,
) -> Res<bool> {
    let _ = state
        .db
        .get_server(&server_id)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Server not found.")))?;

    let migration = state
        .db
        .get_migration(&migration_id.uuid)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Migration not found")))?;

    let affected: HashSet<_> = migration.affected_servers.0.into_iter().collect();

    let completed = state
        .db
        .add_completed_server(&migration_id.uuid, &server_id)
        .await;

    if matches!(completed, Err(DriverError::InvalidInput(InvalidError::UnaffectedServer))) {
        return Ok(Json(false));
    }

    if matches!(completed, Err(DriverError::InvalidInput(InvalidError::AlreadyMigrated))) {
        return Ok(Json(true));
    }

    if let Ok(completed) = completed {
        let set: HashSet<_> = completed.into_iter().collect();
        let diff: HashSet<_> = affected.symmetric_difference(&set).collect();

        let old_user = state
            .db
            .get_user_by_name(migration.old)
            .await
            .map_err(|_| {
                ErrKind::NotFound(Err::new(
                    "Couldn't get Old User from Migration. Is it already deleted?",
                ))
            })?;

        let new_user = state
            .db
            .get_user_by_name(migration.new)
            .await
            .map_err(|_| {
                ErrKind::NotFound(Err::new(
                    "Couldn't get New User from Migration. Is it already deleted?",
                ))
            })?;

        // We actually dont know if the new account has a SaveData yet.
        // As such we try to make a new SaveData for the new user.
        // If this fails thats okay, it just means that the user has a SaveData already.
        let _ = state.db.create_savedata(&new_user.uuid, &server_id).await;

        // Migrate SaveData for this server
        // Merge playtimes
        let old_playtime = state
            .db
            .get_playtime(&old_user.uuid, &server_id)
            .await
            .unwrap_or(Duration::ZERO);
        let new_playtime = state
            .db
            .get_playtime(&new_user.uuid, &server_id)
            .await
            .unwrap_or(Duration::ZERO);

        let combined_playtime = old_playtime + new_playtime;

        // We must set the old account's playtime to zero.
        let _ = state
            .db
            .update_playtime(&old_user.uuid, &server_id, Duration::ZERO)
            .await;
        // And set the newest account to the combined playtime.
        let _ = state
            .db
            .update_playtime(&new_user.uuid, &server_id, combined_playtime)
            .await;

        // Transfer last saved position if the newest account has a default viewport
        let new_viewport = state
            .db
            .get_viewport(&new_user.uuid, &server_id)
            .await
            .unwrap_or_default();

        if new_viewport == Viewport::default() {
            let old_viewport = state
                .db
                .get_viewport(&old_user.uuid, &server_id)
                .await
                .unwrap_or_default();
            let _ = state
                .db
                .update_viewport(&new_user.uuid, &server_id, old_viewport)
                .await;
        }

        if diff.is_empty() {
            // Update Completion of Migration
            let _ = state.db.update_completion(&migration.id).await.unwrap();

            // Do destructive actions.
            // Migrate User
            let _ = state
                .db
                .migrate_user(&old_user.uuid, &new_user.uuid)
                .await
                .unwrap();

            let account = state.db.get_account(&new_user.uuid).await;

            // Migrate account if the new account isn't registered yet.
            if account.is_err() {
                state
                    .db
                    .migrate_account(&old_user.uuid, &new_user.uuid)
                    .await
                    .unwrap();
            }

            // Delete Old Account
            state.db.delete_account(&old_user.uuid).await.unwrap();

            // Delete Old SaveDatas
            let _ = state.db.delete_savedatas(&old_user.uuid).await.unwrap();

            // Delete Old User
            let _ = state.db.delete_user(&old_user.uuid).await.unwrap();
        }
    }

    Ok(Json(true))
}

/// [POST] /auth/ban?uuid=<>&ip=<ip>
/// ```json
/// "Automatic" |
/// {
///    "Manual": "<uuid>"
/// }
/// ```
pub async fn ban_cidr(
    State(state): State<Arc<AppState>>, Query(params): Query<BanCidrQueryParam>,
    Json(issuer): Json<BanIssuer>,
) -> Res<BanResponse> {
    if let Ok(strict) = state.db.get_blacklists(params.ip).await {
        if !strict.is_empty() {
            return Ok(Json(BanResponse::Existing));
        }
    }

    if let Ok(broad) = state
        .db
        .get_blacklists_with_range(params.ip, MIN_COMMON_PREFIX)
        .await
    {
        if !broad.is_empty() {
            for entry in broad {
                let nmask = lowest_common_prefix(&entry.get_network(), &params.ip).unwrap();
                let _ = state.db.broaden_blacklist_mask(entry.clone(), nmask).await;
                let _ = state.db.bump_blacklist(entry).await;
            }
        }

        return Ok(Json(BanResponse::Merged));
    }

    let actor = match issuer {
        BanIssuer::Manual(uuid) => BanActor::Staff(uuid),
        BanIssuer::Automatic => {
            BanActor::AutomatedSystem(format!("Logged while {} was online.", params.uuid))
        }
    };

    if state.db.create_blacklist(params.ip, actor).await.is_ok() {
        return Ok(Json(BanResponse::New));
    }

    Ok(Json(BanResponse::Invalid))
}

/// **Note**: This is **not** a direct port to the new sqlite backend.
///
/// This *was* a part of the three step manual verification process, but became a manual override for allowing IP addresses.
/// This is why the logic looks similar to `ban_cidr`, including the check to see if the IP is already allowed.
/// Kept around for being possibly useful in the future. Manual overrides and fail-safes are nice.
///
/// [POST] /auth/allow?uuid=<id>&ip=<ip>
pub async fn allow_cidr(
    State(state): State<Arc<AppState>>, Query(params): Query<CheckCidrQueryParam>,
) -> Res<bool> {
    if let Ok(strict) = state
        .db
        .get_allowlists_with_ip(&params.uuid, params.ip)
        .await
    {
        if !strict.is_empty() {
            return Ok(Json(true));
        }
    }

    // We always do automatic widening when possible, since the next call will be amortized and returned early.
    if let Ok(broad) = state
        .db
        .get_allowlists_with_range(&params.uuid, params.ip, MIN_COMMON_PREFIX)
        .await
    {
        if !broad.is_empty() {
            for entry in broad {
                let nmask = lowest_common_prefix(&entry.get_network(), &params.ip).unwrap();
                let _ = state.db.broaden_allowlist_mask(entry, nmask).await;
                // We don't bump the allowlist here, since that would lead to counting connections twice.
                // Allowlists are only bumped at `resume` (after (re)logging in) and `get_session` (on the case of a valid existing session).
            }
            return Ok(Json(true));
        }
    }

    let _ = state.db.create_allowlist(&params.uuid, params.ip).await;
    Ok(Json(true))
}

/// [POST] /auth/cidr?uuid=<id>&ip=<ip>
pub async fn cidr_check(
    State(state): State<Arc<AppState>>, Query(params): Query<CheckCidrQueryParam>,
) -> Res<CidrResponse> {
    // This is a trivial "can join" or "is banned check"
    // We should check things broadly for users, but strict for bans.
    // If the user doesn't exist, we allow it in, only if the IP isn't banned.

    // Honestly this should be the place to put all broadening logic, and everything else should just strict-check.
    // Since this everything *should* be CIDR-checked at the Pre-Login phase.

    if let Ok(strict) = state
        .db
        .get_allowlists_with_ip(&params.uuid, params.ip)
        .await
    {
        if !strict.is_empty() {
            return Ok(Json(CidrResponse::Allowed));
        }
    }

    if let Ok(broad) = state
        .db
        .get_allowlists_with_range(&params.uuid, params.ip, MIN_COMMON_PREFIX)
        .await
    {
        if !broad.is_empty() {
            for entry in broad {
                let nmask = lowest_common_prefix(&entry.get_network(), &params.ip).unwrap();
                let _ = state.db.broaden_allowlist_mask(entry, nmask).await;
                // We don't bump the allowlist here, since that would lead to counting connections twice.
                // Allowlists are only bumped at `resume` (after (re)logging in) and `get_session` (on the case of a valid existing session).
            }
            return Ok(Json(CidrResponse::Allowed));
        }
    }

    if let Ok(strict) = state.db.get_blacklists(params.ip).await {
        if !strict.is_empty() {
            return Ok(Json(CidrResponse::Banned));
        }
    }

    if let Ok(broad) = state
        .db
        .get_blacklists_with_range(params.ip, MIN_COMMON_PREFIX)
        .await
    {
        if !broad.is_empty() {
            for entry in broad {
                let nmask = lowest_common_prefix(&entry.get_network(), &params.ip).unwrap();
                let _ = state.db.broaden_blacklist_mask(entry.clone(), nmask).await;
                let _ = state.db.bump_blacklist(entry).await;
            }

            return Ok(Json(CidrResponse::Banned));
        }
    }

    let server_name = match params.server {
        Some(uuid) => {
            if let Ok(server) = state.db.get_server(&uuid).await {
                server.name
            } else {
                "Servidor Desconhecido".to_string()
            }
        }
        None => "Servidor Desconhecido".to_string(),
    };

    // An user exist and can be notified.
    if let Ok(user) = state.db.get_user_by_uuid(&params.uuid).await {
        notify::unknown_ip(
            &state.client.serenity,
            &user,
            &server_name,
            &params.ip,
            &state.config.verification_channel_id,
        )
        .await;
    }

    Ok(Json(CidrResponse::Unknown))
}

/// [POST] /api/auth
/// ```json
/// {
///     "uuid": "<uuid>",
///     "ip": "<ip>",
///     "pass": "<pass>"
/// }
/// ```
pub async fn create_account(
    State(state): State<Arc<AppState>>, Json(session): Json<AuthenticationQueryParams>,
) -> Res<bool> {
    // This function does a lot of stuff. So attention is needed in order to make things work.
    // Accounts were once a cohesive thing that existed in one object, now it spans a little more then that.
    // Firstly, we basically need to create the account and set the initial allowlist entry.
    // The account should also have the last logged in time updated to the current time, if thats unset by default.

    // Lets create the account. For that obviously an user need to exist.
    let hash = bcrypt::hash(&session.password, 12)
        .map_err(|e| ErrKind::Internal(Err::new("BCrypt Error.").with_inner(e)))?;

    if state
        .db
        .create_account(AccountStub { uuid: session.uuid, password: hash })
        .await
        .is_err()
    {
        return Err(ErrKind::Internal(Err::new("Account already existed")));
    }

    // Now we need to store the initial ip address
    let _ = state.db.create_allowlist(&session.uuid, session.ip).await;

    // We're done with initial account creation

    Ok(Json(true))
}

/// [DELETE] /`api/auth/:user_id`
pub async fn delete_account(
    State(state): State<Arc<AppState>>, Path(user): Path<Uuid>,
) -> Res<bool> {
    state
        .db
        .delete_account(&user)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("User not found.")))?;

    Ok(Json(true))
}

/// [PATCH] /api/auth/changepw
/// ```json
///     "uuid": "<uuid>"
///     "ip": "<ip>"
///     "old": "<old password>"
///     "new": "<new password>"
/// ```
pub async fn changepw(
    State(state): State<Arc<AppState>>, Json(session): Json<ChangePasswordQueryParams>,
) -> Res<bool> {
    let mut eph = state.ephemeral.lock().await;

    let acc = state
        .db
        .get_account(&session.uuid)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Account not found.")))?;

    let matches = bcrypt::verify(session.old, &acc.password)
        .map_err(|e| ErrKind::Internal(Err::new("BCrypt Error.").with_inner(e)))?;

    if matches {
        let new_pass = bcrypt::hash(session.new, 12)
            .map_err(|e| ErrKind::Internal(Err::new("BCrypt Error.").with_inner(e)))?;

        let _ = state.db.update_password(&session.uuid, new_pass).await;

        Ok(Json(true))
    } else {
        let mut count = 1;

        if eph.password.contains_key(&session.uuid) {
            count = *(eph.password.get(&session.uuid).unwrap());
            count += 1;
        }

        eph.password.insert(session.uuid, count);

        if count >= MAX_ATTEMPTS_PER_ACC {
            Err(ErrKind::BadRequest(Err::new("Exhausted MAX_ATTEMPTS for this account.")))
        } else {
            Ok(Json(false))
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ChangePasswordQueryParams {
    uuid: Uuid,
    old: String,
    new: String,
}

#[derive(Serialize, Deserialize)]
pub struct AuthenticationQueryParams {
    uuid: Uuid,
    ip: Ipv4Addr,
    password: String,
}

#[derive(Serialize, Deserialize)]
pub struct SessionQueryParams {
    uuid: Uuid,
    ip: Ipv4Addr,
}

#[derive(Deserialize)]
pub struct LinkQueryParams {
    code: String,
    state: String,
}

#[derive(Deserialize)]
pub struct UuidQueryParam {
    pub uuid: Uuid,
}

#[derive(Deserialize)]
pub struct AllowCidrQueryParams {
    pub uuid: Uuid,
    pub nonce: String,
    pub ip: Ipv4Addr,
}

#[derive(Deserialize)]
pub struct DiscordDenyCidrQueryParams {
    pub id: UserId,
    pub ip: Ipv4Addr,
}

#[derive(Deserialize)]
pub struct MinecraftDenyCidrQueryParams {
    pub uuid: Uuid,
    pub ip: Ipv4Addr,
}

#[derive(Deserialize)]
pub struct CheckCidrQueryParam {
    pub uuid: Uuid,
    pub ip: Ipv4Addr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<Uuid>,
}

#[derive(Deserialize)]
pub struct BanCidrQueryParam {
    pub uuid: Uuid,
    pub ip: Ipv4Addr,
}

#[derive(Deserialize)]
pub struct DiscordIdQueryParam {
    pub id: UserId,
}

#[derive(Serialize, Clone, Debug)]
pub struct LinkResult {
    pub discord_id: String,
    pub discord_username: String,
    pub when: DateTime<Utc>,
    pub minecraft_uuid: Uuid,
}
