use std::{collections::HashSet, time::Duration};

use db::{
    data::{result::ServerJoin, stub::ServerStub, Server, Viewport},
    drivers::err::{
        base::{InvalidError, NotFoundError},
        DriverError,
    },
};
use query_params::{LoginAttempt, OfflineUuid};
use serenity::all::{GuildId, RoleId, UserId};

use crate::routes::prelude::*;

pub const MAX_ATTEMPTS_PER_ACC: i32 = 5;

/// [GET] /api/servers
pub async fn get_all_servers(State(state): State<Arc<AppState>>) -> Res<Vec<Uuid>> {
    let data = state.db.get_all_servers().await.map_err(|e| {
        ErrKind::Internal(Err::new("Couldn't get all servers").with_inner(format!("{:?}", e)))
    })?;

    Ok(Json(data))
}

/// [GET] /`api/server/:server_id`
pub async fn get(State(state): State<Arc<AppState>>, Path(server_uuid): Path<Uuid>) -> Res<Server> {
    let data = state
        .db
        .get_server(&server_uuid)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Server not found.")))?;

    Ok(Json(data))
}

/// [DELETE] /`api/server/:user_id`
pub async fn delete(
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
pub async fn create(
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

/// [POST] /api/auth/:server_id/login
pub async fn login(
    State(state): State<Arc<AppState>>, Path(server_id): Path<Uuid>,
    Json(attempt): Json<LoginAttempt>,
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
        .get_user_by_uuid(&attempt.uuid)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("User not found.")))?;

    let account = state
        .db
        .get_account(&user.uuid)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Account not found.")))?;

    let password = bcrypt::verify(attempt.password, &account.password)
        .map_err(|e| ErrKind::Internal(Err::new("BCrypt Error.".to_string()).with_inner(e)))?;

    if !password {
        let mut count = 1;

        if eph.password.contains_key(&attempt.uuid) {
            count = *(eph.password.get(&attempt.uuid).unwrap());
            count += 1;
        }

        eph.password.insert(attempt.uuid, count);

        if count >= MAX_ATTEMPTS_PER_ACC {
            Err(ErrKind::BadRequest(Err::new("Exhausted MAX_ATTEMPTS for this account.")))
        } else {
            Ok(Json(None))
        }
    } else {
        eph.password.remove(&attempt.uuid);

        state.db.update_current_join(&attempt.uuid).await.unwrap();

        let res = state
            .db
            .join_server(&server_id, &attempt.uuid)
            .await
            .unwrap();

        if matches!(res, ServerJoin::FirstJoin) {
            let _ = state.db.create_savedata(&attempt.uuid, &server_id).await;
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

/// [POST] /api/auth/:server_id/logoff?uuid=<ID>&ip=<IP>
pub async fn logoff(
    State(state): State<Arc<AppState>>, Path(server_id): Path<Uuid>,
    Query(attempt): Query<LoginAttempt>, Json(pos): Json<Viewport>,
) -> Res<bool> {
    let cfg = &state.config;
    let client = &state.client.serenity;

    let user = state
        .db
        .get_user_by_uuid(&attempt.uuid)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("User not found.")))?;

    let server = state
        .db
        .get_server(&server_id)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Server not found.")))?;

    let account = state
        .db
        .get_account(&attempt.uuid)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Account not foumd.")))?;

    if let Err(DriverError::DatabaseError(NotFoundError::UserData {
        server_uuid: _,
        player_uuid: _,
    })) = state.db.get_viewport(&attempt.uuid, &server.uuid).await
    {
        let _ = state.db.create_savedata(&attempt.uuid, &server.uuid).await;
    }

    state
        .db
        .update_viewport(&attempt.uuid, &server.uuid, pos)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("SaveData not found.")))?;

    let now = chrono::offset::Utc::now();

    let mut playtime = state
        .db
        .get_playtime(&attempt.uuid, &server.uuid)
        .await
        .unwrap_or_default();

    let delta = (now - account.current_join).to_std().unwrap();

    playtime += delta;

    state
        .db
        .update_playtime(&attempt.uuid, &server.uuid, playtime)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("SaveData not found.")))?;

    state
        .db
        .leave_server(&server.uuid, &attempt.uuid)
        .await
        .unwrap();

    // Bump allowlists at logoff.
    if let Ok(entries) = state
        .db
        .get_allowlists_with_ip(&attempt.uuid, attempt.ip)
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

/// [POST] /server/<uuid>/migrated?uuid=<uuid>
pub async fn migrate_user(
    State(state): State<Arc<AppState>>, Path(server_id): Path<Uuid>,
    Query(migration_id): Query<OfflineUuid>,
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
