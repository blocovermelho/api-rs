use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use uuid_mc::PlayerUuid;

use super::{
    body::{self, BedrockAccount},
    query_params::{self},
    results, JsonResult,
};
use crate::{
    core::types::{
        consts::{
            api_scopes::{
                PROFILE_CREATE, PROFILE_OTHERS_MODIFY, PROFILE_READ, SERVER_READ,
                SERVER_SELF_MODIFY,
            },
            connection_ids::{BEDROCK_ACCOUNT, MOJANG_UUID},
        },
        enums::{ConnectionData, DiscordMemberFetchError},
        structs::{stub::ProfileStub, Connection},
    },
    db::{data::Profile, drivers::sqlite::Sqlite, interface::DataSource},
    middleware::server_auth::AuthorizedServer,
    routes::{
        query_params::IpQuery,
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
        if response.status() == reqwest::StatusCode::OK {
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
        } else if response.status() == reqwest::StatusCode::NO_CONTENT {
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

/// [POST] /api/profile/<username>/authenticate?ip=<ip_addr>&pass=<password>
pub async fn authenticate(
    State(state): State<Arc<AuthServer>>, AuthorizedServer(token, server): AuthorizedServer,
    Path(username): Path<String>, Query(query): Query<query_params::LoginQuery>,
) -> JsonResult<results::Authenticate, String> {
    scopes!(token, [PROFILE_READ, SERVER_SELF_MODIFY]);

    match state
        .mailbox
        .session_authenticate(username, query.password, server.uuid)
        .await
    {
        crate::actor::session::LoginAttempt::InvalidProfile => {
            Ok(Json(results::Authenticate::InvalidProfile))
        }
        crate::actor::session::LoginAttempt::InvalidPassword { error_count, max_errors } => {
            Ok(Json(results::Authenticate::InvalidPassword {
                attempts: error_count,
                max_attempts: max_errors,
            }))
        }
        crate::actor::session::LoginAttempt::LoggedIn => Ok(Json(results::Authenticate::LoggedIn)),
    }
}

/// [POST] /api/profile/<username>/login?ip=<ip>
pub async fn login(
    State(state): State<Arc<AuthServer>>, AuthorizedServer(token, server): AuthorizedServer,
    Path(username): Path<String>, Query(query): Query<IpQuery>,
) -> JsonResult<results::Login, String> {
    scopes!(token, [PROFILE_READ, SERVER_SELF_MODIFY]);

    let member = state
        .mailbox
        .get_discord_member(username.clone(), state.config.guild_id.parse().unwrap())
        .await;

    match state
        .mailbox
        .check_ip(query.ip, username.clone(), server.uuid)
        .await
    {
        crate::actor::cidr::CidrResolution::AllowedIp(_) => Ok(Json(results::Login::AllowedIp)),
        crate::actor::cidr::CidrResolution::UnknownIp => {
            if let Err(k) = member {
                return match k {
                    DiscordMemberFetchError::UnknownUsername => Ok(Json(results::Login::NewIp)),
                    DiscordMemberFetchError::NotInGuild => Ok(Json(results::Login::NotInGuild)),
                };
            }
            Ok(Json(results::Login::NewIp))
        }
        crate::actor::cidr::CidrResolution::BannedIp(_) => Ok(Json(results::Login::BannedIp)),
        crate::actor::cidr::CidrResolution::BlockedWithHeuristic(_) => {
            Ok(Json(results::Login::BlockedIp))
        }
    }
}

/// [POST] /api/profile/<username>/logout
pub async fn logout(
    State(state): State<Arc<AuthServer>>, AuthorizedServer(token, server): AuthorizedServer,
    Path(username): Path<String>,
) -> JsonResult<results::Logout, String> {
    scopes!(token, [PROFILE_READ, SERVER_SELF_MODIFY]);

    if !state
        .mailbox
        .profile_check_activity(username.clone(), server.uuid)
        .await
    {
        return Ok(Json(results::Logout::ProfileNotInServer));
    }

    state.mailbox.profile_logout(username, server.uuid);
    Ok(Json(results::Logout::LoggedOut))
}

/// [GET] /api/profile/<username>/session_restore
pub async fn session(
    State(state): State<Arc<AuthServer>>, AuthorizedServer(token, _server): AuthorizedServer,
    Path(username): Path<String>,
) -> JsonResult<bool, String> {
    scopes!(token, [PROFILE_READ]);

    Ok(Json(state.mailbox.session_restore(username).await))
}

/// [POST] /api/profile/<username>/password_change?old=<pass>&new=<pass>
pub async fn password_change(
    State(state): State<Arc<AuthServer>>, AuthorizedServer(token, _server): AuthorizedServer,
    Path(username): Path<String>, Query(query): Query<query_params::PasswordChange>,
) -> JsonResult<results::PasswordUpdate, String> {
    scopes!(token, [PROFILE_READ, SERVER_READ, PROFILE_OTHERS_MODIFY]);

    match state
        .mailbox
        .profile_change_password(username, query.old, query.new)
        .await
    {
        crate::actor::database::ChangePasswordAttempt::InvalidProfile => Err((
            StatusCode::NOT_FOUND,
            "An profile with the given username could not be found".to_string(),
        )),
        crate::actor::database::ChangePasswordAttempt::InvalidPassword => {
            Ok(Json(results::PasswordUpdate::InvalidPassword))
        }
        crate::actor::database::ChangePasswordAttempt::Changed => {
            Ok(Json(results::PasswordUpdate::PasswordChanged))
        }
    }
}

/// [POST] /api/profile/<username>
pub async fn create_profile(
    State(state): State<Arc<AuthServer>>, AuthorizedServer(token, _server): AuthorizedServer,
    Path(username): Path<String>, Json(query): Json<body::NewProfile>,
) -> JsonResult<results::CreateProfile, String> {
    scopes!(token, [PROFILE_CREATE]);

    let hash = bcrypt::hash(query.password, 12).unwrap();
    if let Ok(profile) = state
        .db
        .create_profile(
            ProfileStub {
                username: username.clone(),
                discord_id: query.discord_id,
                password: hash,
            },
            None,
        )
        .await
    {
        let res = results::CreateProfile::Created { id: profile.uuid };
        state
            .mailbox
            .session_profile_update(username, profile.into());

        Ok(Json(res))
    } else {
        Ok(Json(results::CreateProfile::UsernameExists))
    }
}
