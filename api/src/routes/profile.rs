use std::sync::Arc;

use ::http::StatusCode;
use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::Utc;
use serenity::http;
use uuid_mc::PlayerUuid;

use super::{
    body::{self, BedrockAccount},
    query_params::{self},
    results, JsonResult,
};
use crate::{
    core::types::{
        consts::{
            api_scopes::{PROFILE_OTHERS_MODIFY, PROFILE_READ, SERVER_READ, SERVER_SELF_MODIFY},
            connection_ids::{BEDROCK_ACCOUNT, MOJANG_UUID},
        },
        enums::{ConnectionData, PlayerState},
        structs::{Connection, Player},
    },
    db::{data::Profile, drivers::sqlite::Sqlite, interface::DataSource},
    middleware::server_auth::AuthorizedServer,
    routes::{
        results::{BedrockAccountStanding, MojangAccountStanding},
        scopes,
    },
    AuthServer,
};

pub async fn hydrate_profile_id(db: &Arc<Sqlite>, profile: Profile) -> results::Profile {
    let connections = db
        .get_connections_by_profile(&profile.uuid)
        .await
        .unwrap_or_default()
        .iter()
        .map(|it| results::Connection {
            issuer: it.issuer,
            extra: (it.kind.clone(), it.data.clone()).try_into().unwrap(),
        })
        .collect();

    results::Profile {
        id: profile.uuid,
        username: profile.username,
        discord_id: profile.discord_id,
        connections,
    }
}

/// [GET] /api/profile?username=<username>
pub async fn get_profile(
    State(state): State<Arc<AuthServer>>, Query(query): Query<query_params::UsernameQuery>,
) -> JsonResult<results::Profile, String> {
    let db = state.db.clone();

    let profile = db.get_profile(query.username).await.map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            "An user with the given username could not be found.".to_string(),
        )
    })?;

    Ok(Json(hydrate_profile_id(&db, profile).await))
}

/// [GET] /api/profile/resolve_mojang?username=<name>
pub async fn resolve_mojang(
    State(state): State<Arc<AuthServer>>, AuthorizedServer(token, _server): AuthorizedServer,
    Query(query): Query<query_params::UsernameQuery>,
) -> JsonResult<results::MojangAccountStanding, String> {
    scopes!(token, [PROFILE_READ]);
    if let Ok(moj) = PlayerUuid::new_with_online_username(&query.username) {
        let conns: Vec<_> = state
            .db
            .get_connections_by_kind(MOJANG_UUID)
            .await
            .unwrap_or_default();

        for conn in conns {
            if let ConnectionData::MojangUuid { id, name } =
                (conn.kind, conn.data).try_into().unwrap()
            {
                if id == *moj.as_uuid() {
                    let candidate = state.db.get_profile_by_id(&conn.profile).await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Profile ID stored inside of the connection was desynced. This should only happen if an account gets deleted by mojang or the database was manually modified.".to_string()))?;
                    let profile = hydrate_profile_id(&state.db, candidate).await;

                    if name == query.username {
                        return Ok(Json(MojangAccountStanding::KnownProfile { profile }));
                    } else {
                        return Ok(Json(MojangAccountStanding::RenamedProfile {
                            profile,
                            mojang_name: query.username,
                        }));
                    }
                }
            }
        }

        Ok(Json(MojangAccountStanding::UnknownUser {
            mojang_uuid: *moj.as_uuid(),
            mojang_name: query.username,
        }))
    } else {
        Ok(Json(MojangAccountStanding::InvalidName))
    }
}

/// [GET] /api/profile/resolve_bedrock?username=<name>[&xuid=<id>]
pub async fn resolve_bedrock(
    State(state): State<Arc<AuthServer>>, AuthorizedServer(token, _server): AuthorizedServer,
    Query(query): Query<BedrockAccount>,
) -> JsonResult<results::BedrockAccountStanding, String> {
    scopes!(token, [PROFILE_READ]);

    let conns: Vec<_> = state
        .db
        .get_connections_by_kind(BEDROCK_ACCOUNT)
        .await
        .unwrap_or_default();

    for conn in conns {
        if let ConnectionData::BedrockUsername { name, .. } =
            (conn.kind, conn.data).try_into().unwrap()
        {
            if name == query.gamertag {
                let candidate = state.db.get_profile_by_id(&conn.profile).await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Profile ID stored inside of the connection was desynced. This should only happen if an account gets deleted by mojang or the database was manually modified.".to_string()))?;
                let profile = hydrate_profile_id(&state.db, candidate).await;

                // TODO: XUID matching when we're capable.
                // Microsoft's API absolutely sucks and we're *totally* not wrapping that now.
                // Its likely even against eula for some reason.
                // This is honestly an "help-wanted" kind of issue.

                return Ok(Json(BedrockAccountStanding::KnownProfile { profile }));
            }
        }
    }

    Ok(Json(BedrockAccountStanding::UnknownUser {
        gamertag: query.gamertag,
        xuid: query.xuid,
    }))
}

/// [POST] /api/profile/<username>/bedrock?gamertag=<>[&xuid=<>]
pub async fn connect_bedrock(
    State(state): State<Arc<AuthServer>>, AuthorizedServer(token, server): AuthorizedServer,
    Path(username): Path<String>, Query(account): Query<BedrockAccount>,
) -> JsonResult<results::Connection, String> {
    scopes!(token, [PROFILE_READ, PROFILE_OTHERS_MODIFY]);

    let profile = state
        .db
        .get_profile(username)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Invalid username.".to_string()))?;

    let exists = state
        .db
        .get_connections_by_kind(BEDROCK_ACCOUNT)
        .await
        .unwrap_or_default()
        .iter()
        .map(|it| (it.kind.clone(), it.data.clone()).try_into().unwrap())
        .any(|f| {
            if let ConnectionData::BedrockUsername { name, .. } = f {
                name == account.gamertag
            } else {
                false
            }
        });

    if exists {
        return Err((
            StatusCode::BAD_REQUEST,
            "This Bedrock gamertag already belongs to another user.".to_string(),
        ));
    }

    let conn = state
        .db
        .create_connection(
            Connection {
                issuer: Some(server.uuid),
                profile: profile.into(),
                extra: ConnectionData::BedrockUsername {
                    name: account.gamertag,
                    xuid: account.xuid,
                },
            }
            .into(),
        )
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Couldn't add bedrock account connection".to_string(),
            )
        })?;

    Ok(Json(results::Connection {
        issuer: conn.issuer,
        extra: (conn.kind, conn.data).try_into().unwrap(),
    }))
}

/// [POST] /api/profile/<username>/mojang?id=<mojang_id>
pub async fn connect_mojang(
    State(state): State<Arc<AuthServer>>, AuthorizedServer(token, server): AuthorizedServer,
    Path(username): Path<String>, Query(query): Query<query_params::IdQuery>,
) -> JsonResult<results::Connection, String> {
    scopes!(token, [PROFILE_READ, PROFILE_OTHERS_MODIFY]);

    let profile = state
        .db
        .get_profile(username)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Invalid username.".to_string()))?;

    let mojang_api_url =
        format!("https://api.mojang.com/user/profile/{}", query.id.to_string().replace("-", ""));

    if let Ok(response) = state.clients.reqwest.get(mojang_api_url).send().await {
        if response.status() == http::StatusCode::OK {
            let mojang: body::MojangApiId = response
                .json()
                .await
                .map_err(|_| (StatusCode::BAD_REQUEST, "Mojang API Error".to_string()))?;

            let exists = state
                .db
                .get_connections_by_kind(MOJANG_UUID)
                .await
                .unwrap_or_default()
                .iter()
                .map(|it| (it.kind.clone(), it.data.clone()).try_into().unwrap())
                .any(|f| {
                    if let ConnectionData::MojangUuid { id, .. } = f {
                        id == mojang.id
                    } else {
                        false
                    }
                });

            if exists {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "This Mojang account already belongs to another user.".to_string(),
                ));
            }

            let conn = state
                .db
                .create_connection(
                    Connection {
                        issuer: Some(server.uuid),
                        profile: profile.into(),
                        extra: ConnectionData::MojangUuid { name: mojang.name, id: mojang.id },
                    }
                    .into(),
                )
                .await
                .map_err(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Could not create mojang account connection".to_string(),
                    )
                })?;

            return Ok(Json(results::Connection {
                issuer: conn.issuer,
                extra: (conn.kind, conn.data).try_into().unwrap(),
            }));
        } else if response.status() == http::StatusCode::NO_CONTENT {
            return Err((
                StatusCode::NOT_FOUND,
                "The provided uuid was not found in Mojang's server".to_string(),
            ));
        }
    }

    Err((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Couldn't reach mojang's servers. Are they down?".to_string(),
    ))
}

/// [POST] /api/profile/<username>/login?ip=<ip_addr>&pass=<password>
pub async fn login(
    State(state): State<Arc<AuthServer>>, AuthorizedServer(token, server): AuthorizedServer,
    Path(username): Path<String>, Query(query): Query<query_params::LoginQuery>,
) -> JsonResult<results::Login, String> {
    scopes!(token, [PROFILE_READ, SERVER_SELF_MODIFY]);

    let now = Utc::now();

    let profile = state.db.get_profile(username).await.map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            "An profile with the given username could not be found".to_string(),
        )
    })?;

    let mut eph = state.state.lock().await;

    if !eph.servers.contains_key(&server.uuid) {
        return Ok(Json(results::Login::ServerOffline));
    }

    if !state
        .db
        .get_blacklists_with_range(query.ip, 16)
        .await
        .unwrap_or_default()
        .is_empty()
    {
        return Ok(Json(results::Login::BannedIp));
    }

    let allowlists = state
        .db
        .get_allowlists_with_range(&profile.uuid, query.ip, 16)
        .await
        .unwrap_or_default();

    if allowlists.is_empty() {
        return Ok(Json(results::Login::NewIp));
    }

    let trimmed = query.password.trim().to_string();

    let otp_check = if let Some(owner) = eph.tokens.get_by_right(&trimmed) {
        *owner == profile.uuid
    } else {
        false
    };

    let pass_check = bcrypt::verify(trimmed, &profile.password).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, "Couldn't verify password.".to_string())
    })?;

    let current = eph.bad_password_count.remove(&profile.uuid).unwrap_or(0);

    if !(pass_check || otp_check) {
        eph.bad_password_count.insert(profile.uuid, current + 1);

        return Ok(Json(results::Login::InvalidPassword {
            attempts: current + 1,
            max_attempts: 5,
        }));
    }

    if otp_check {
        // They are One-Time-Passphrases
        eph.tokens.remove_by_left(&profile.uuid);
    }

    let state = if let Some(mut session) = eph.sessions.remove(&profile.uuid) {
        if session.get_expiry() > now {
            session.last_seen = now;

            eph.sessions.insert(profile.uuid, session);
            (results::Login::ResumedSession, PlayerState::ResumedSession)
        } else {
            (results::Login::LoggedIn, PlayerState::LoggedIn)
        }
    } else {
        (results::Login::LoggedIn, PlayerState::LoggedIn)
    };

    let mut gameserver = eph.servers.remove(&server.uuid).unwrap();

    gameserver.players.insert(profile.username.clone(), Player {
        profile: Some(profile.into()),
        status: state.1,
    });

    eph.servers.insert(gameserver.id, gameserver);

    Ok(Json(state.0))
}

/// [POST] /api/profile/<username>/logout
pub async fn logout(
    State(state): State<Arc<AuthServer>>, AuthorizedServer(token, server): AuthorizedServer,
    Path(username): Path<String>,
) -> JsonResult<results::Logout, String> {
    scopes!(token, [PROFILE_READ, SERVER_SELF_MODIFY]);

    let now = Utc::now();

    let profile = state.db.get_profile(username).await.map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            "An profile with the given username could not be found".to_string(),
        )
    })?;

    let mut eph = state.state.lock().await;

    if let Some(mut gs) = eph.servers.remove(&server.uuid) {
        match gs.players.remove(&profile.username) {
            Some(_) => {
                if let Some(mut session) = eph.sessions.remove(&profile.uuid) {
                    session.last_seen = now;
                    eph.sessions.insert(profile.uuid, session);
                }
                Ok(Json(results::Logout::LoggedOut))
            }
            None => Ok(Json(results::Logout::ProfileNotInServer)),
        }
    } else {
        Ok(Json(results::Logout::ServerOffline))
    }
}

/// [POST] /api/profile/<username>/password_change?old=<pass>&new=<pass>
pub async fn password_change(
    State(state): State<Arc<AuthServer>>, AuthorizedServer(token, server): AuthorizedServer,
    Path(username): Path<String>, Query(query): Query<query_params::PasswordChange>,
) -> JsonResult<results::PasswordUpdate, String> {
    scopes!(token, [PROFILE_READ, SERVER_READ, PROFILE_OTHERS_MODIFY]);

    let profile = state.db.get_profile(username).await.map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            "An profile with the given username could not be found".to_string(),
        )
    })?;

    let mut eph = state.state.lock().await;

    match eph.servers.get(&server.uuid) {
        Some(s) => match s.players.get(&profile.username) {
            Some(p) => match p.status {
                PlayerState::LoggedIn | PlayerState::ResumedSession => {}
                _ => {
                    return Ok(Json(results::PasswordUpdate::InvalidPlayerState));
                }
            },
            None => {
                return Ok(Json(results::PasswordUpdate::ProfileNotInServer));
            }
        },
        None => return Ok(Json(results::PasswordUpdate::ServerOffline)),
    }

    let pass_check = bcrypt::verify(query.old.trim(), &profile.password).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, "Couldn't verify password.".to_string())
    })?;

    if !pass_check {
        let current = eph.bad_password_count.remove(&profile.uuid).unwrap_or(0);
        eph.bad_password_count.insert(profile.uuid, current + 1);

        return Ok(Json(results::PasswordUpdate::InvalidPassword {
            attempts: current + 1,
            max_attempts: 5,
        }));
    }

    state
        .db
        .update_password(&profile.uuid, query.new.trim().to_string())
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "An error occured while updating your password.".to_string(),
            )
        })?;

    Ok(Json(results::PasswordUpdate::PasswordChanged))
}
