use std::{collections::HashSet, net::Ipv4Addr, time::Duration};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};

use chrono::{DateTime, Utc};
use oauth2::{reqwest::async_http_client, AuthorizationCode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    models::{Account, CreateServer, CreateUser, Pos, Server, User},
    store::MAX_ATTEMPTS_PER_ACC,
    AppState,
};

pub type Res<T> = Result<Json<T>, ErrKind>;

#[derive(Serialize, Clone)]
pub struct Err {
    pub error: String,
    pub inner: Option<String>,
}

impl Err {
    pub fn new(message: impl ToString) -> Self {
        Self {
            error: message.to_string(),
            inner: None,
        }
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
            ErrKind::NotFound(e) => (StatusCode::NOT_FOUND, Json(e)).into_response(),
            ErrKind::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(e)).into_response(),
            ErrKind::BadRequest(e) => (StatusCode::BAD_REQUEST, Json(e)).into_response(),
        }
    }
}

/// [GET] /api/link?state=<>&code=<>
pub async fn link(
    State(state): State<AppState>,
    Query(link): Query<LinkQueryParams>,
) -> Res<LinkResult> {
    let mut data = state.data.lock().await;
    let uuid = data
        .get_uuid_from_nonce(&link.state)
        .ok_or(ErrKind::NotFound(Err::new(
            "Tried getting an user that hasn't started linking yet.",
        )))?
        .clone();

    data.drop_nonce(&link.state);

    let cfg = state.config.lock().await;
    let client = oauth::routes::get_client(cfg.clone()).map_err(|e| {
        ErrKind::Internal(Err::new("Error while getting a BasicClient").with_inner(e))
    })?;

    let response = client
        .exchange_code(AuthorizationCode::new(link.code))
        .request_async(async_http_client)
        .await;

    let token = response.map_err(|e| {
        ErrKind::Internal(Err::new("Couldn't exchange the code for a discord user.").with_inner(e))
    })?;

    let reqwest_client = state.reqwest_client.lock().await;
    let on_discord = oauth::routes::get_guild(&reqwest_client, &token, &cfg)
        .await
        .map_err(|e| {
            ErrKind::Internal(Err::new("Provided discord User didn't had a valid Guild Member object. Are you on the discord guild?").with_inner(e))
        })?;

    let result = LinkResult {
        discord_id: on_discord.user.id,
        discord_username: on_discord.user.username,
        when: on_discord.joined_at,
        minecraft_uuid: uuid,
    };

    let _ = state.chs.links.send(uuid, result.clone()).await;

    Ok(Json(result))
}

/// [GET] /api/oauth?uuid=<ID>
pub async fn discord(
    State(state): State<AppState>,
    Query(uuid): Query<UuidQueryParam>,
) -> Res<String> {
    let mut data = state.data.lock().await;
    let cfg = state.config.lock().await;

    let client = oauth::routes::get_client(cfg.clone()).map_err(|e| {
        ErrKind::Internal(Err::new("Error while getting a BasicClient").with_inner(e))
    })?;

    let (url, token) = oauth::routes::authorize(&client).url();

    data.add_nonce(token.secret().clone(), uuid.uuid);

    Ok(Json(url.to_string()))
}

/// [GET] /api/users
pub async fn get_users(State(state): State<AppState>) -> Res<Vec<User>> {
    let data = state.data.lock().await;
    Ok(Json(data.get_users()))
}

/// [GET] /api/user/:user_id
pub async fn get_user(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<User>, StatusCode> {
    let data = state.data.lock().await;

    return match data.get_user(&user_id) {
        Some(u) => Ok(Json(u.clone())),
        None => Err(StatusCode::NOT_FOUND),
    };
}

/// [POST] /api/user
pub async fn create_user(
    State(state): State<AppState>,
    Json(stub): Json<CreateUser>,
) -> Result<Json<User>, StatusCode> {
    let mut data = state.data.lock().await;
    let user = User::from(stub);

    if data.add_user(user.clone()) {
        state
            .flush(&data)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(Json(user))
    } else {
        Err(StatusCode::IM_USED)
    }
}

/// [GET] /api/servers
pub async fn get_servers(State(state): State<AppState>) -> Result<Json<Vec<Server>>, StatusCode> {
    let data = state.data.lock().await;
    Ok(Json(data.get_servers()))
}

/// [GET] /api/server/:server_id
pub async fn get_server(
    State(state): State<AppState>,
    Path(server_id): Path<Uuid>,
) -> Result<Json<Server>, StatusCode> {
    let data = state.data.lock().await;
    let server = data.get_server(&server_id).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(server.to_owned()))
}

/// [POST] /api/server
pub async fn create_server(
    State(state): State<AppState>,
    Json(stub): Json<CreateServer>,
) -> Result<Json<Server>, StatusCode> {
    let mut data = state.data.lock().await;

    let server = Server::from(stub);

    if data.add_server(server.clone()) {
        state
            .flush(&data)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(Json(server))
    } else {
        Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

/// [PATCH] /api/server/:server_id/enable
pub async fn enable(
    State(state): State<AppState>,
    Path(server_id): Path<Uuid>,
) -> Result<Json<bool>, StatusCode> {
    let mut data = state.data.lock().await;
    let mut server = data
        .get_server(&server_id)
        .ok_or(StatusCode::NOT_FOUND)?
        .clone();

    server.available = true;

    data.update_server(server);

    state
        .flush(&data)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(true))
}

/// [PATCH] /api/server/:server_id/disable
pub async fn disable(
    State(state): State<AppState>,
    Path(server_id): Path<Uuid>,
) -> Result<Json<bool>, StatusCode> {
    let mut data = state.data.lock().await;
    let mut server = data
        .get_server(&server_id)
        .ok_or(StatusCode::NOT_FOUND)?
        .clone();

    server.available = false;

    data.update_server(server);

    state
        .flush(&data)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(true))
}

/// [GET] /api/auth/session?uuid=<ID>&ip=<IP>
pub async fn get_session(
    State(state): State<AppState>,
    Query(session): Query<SessionQueryParams>,
) -> Result<Json<bool>, StatusCode> {
    let data = state.data.lock().await;
    let user = data.get_user(&session.uuid).ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(data.has_valid_session(
        user,
        &session.ip,
        chrono::offset::Utc::now(),
    )))
}

/// [POST] /api/auth/:server_id/logoff?uuid=<ID>&ip=<IP>
/// ```json
/// {
///     "x": 0,
///     "z": 0,
///     "y": 64,
///     "dim": "minecraft:overworld"
/// }
/// ```
pub async fn logoff(
    State(state): State<AppState>,
    Path(server_id): Path<Uuid>,
    Query(session): Query<SessionQueryParams>,
    Json(pos): Json<Pos>,
) -> Result<Json<bool>, StatusCode> {
    let mut data = state.data.lock().await;

    let server = data.get_server(&server_id).ok_or(StatusCode::NOT_FOUND)?;
    let mut user = data
        .get_user(&session.uuid)
        .ok_or(StatusCode::NOT_FOUND)?
        .clone();
    let mut account = data
        .get_account(&user.uuid)
        .ok_or(StatusCode::NOT_FOUND)?
        .clone();

    user.last_server = Some(server.uuid);
    user.last_pos.insert(server_id, pos);

    let now = chrono::offset::Utc::now();

    let current_duration = user
        .playtime
        .get(&server_id)
        .unwrap_or(&Duration::default())
        .to_owned();
    let duration = (now - account.current_join)
        .to_std()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    user.playtime.insert(server_id, current_duration + duration);

    account.last_login = Some(now);
    account.previous_ips.insert(session.ip);

    data.update_account(account);
    data.update_user(user);

    state
        .flush(&data)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(true))
}

/// [POST] /api/auth/:server_id/login
/// ```json
/// {
///     "uuid": "743a0a05-8929-4383-a564-edc983ea0231",
///     "ip": "127.0.0.1",
///     "pass": "password123"
/// }
/// ```
pub async fn login(
    State(state): State<AppState>,
    Path(server_id): Path<Uuid>,
    Json(session): Json<AuthenticationQueryParams>,
) -> Result<Json<bool>, StatusCode> {
    let mut data = state.data.lock().await;

    let _ = data.get_server(&server_id).ok_or(StatusCode::NOT_FOUND)?;
    let user = data.get_user(&session.uuid).ok_or(StatusCode::NOT_FOUND)?;
    let mut account = data
        .get_account(&user.uuid)
        .ok_or(StatusCode::NOT_FOUND)?
        .clone();

    let password =
        bcrypt::verify(session.password, &account.password).map_err(|_| StatusCode::BAD_REQUEST)?;

    if !password {
        let count = data.wrong_password(&account);

        if count >= MAX_ATTEMPTS_PER_ACC {
            Err(StatusCode::UNAUTHORIZED)
        } else {
            Ok(Json(false))
        }
    } else {
        data.correct_password(&account);

        account.current_join = chrono::offset::Utc::now();
        data.update_account(account);

        state
            .flush(&data)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(Json(true))
    }
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
    State(state): State<AppState>,
    Json(session): Json<AuthenticationQueryParams>,
) -> Result<Json<bool>, StatusCode> {
    let mut data = state.data.lock().await;
    let hash =
        bcrypt::hash(&session.password, 12).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user = data.get_user(&session.uuid).ok_or(StatusCode::NOT_FOUND)?;
    let mut ips = HashSet::new();
    ips.insert(session.ip);

    let acc = Account {
        uuid: user.uuid,
        password: hash,
        current_join: chrono::offset::Utc::now(),
        last_login: Some(chrono::offset::Utc::now()),
        previous_ips: ips,
    };

    let result = data.add_account(acc);

    state
        .flush(&data)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(result))
}

/// [PATCH] /api/auth/changepw
/// ```json
///     "uuid": "<uuid>"
///     "ip": "<ip>"
///     "old": "<old password>"
///     "new": "<new password>"
/// ```
pub async fn changepw(
    State(state): State<AppState>,
    Json(session): Json<ChangePasswordQueryParams>,
) -> Result<Json<bool>, StatusCode> {
    let mut data = state.data.lock().await;

    let mut acc = data
        .get_account(&session.uuid)
        .ok_or(StatusCode::NOT_FOUND)?
        .clone();
    let matches =
        bcrypt::verify(session.old, &acc.password).map_err(|_| StatusCode::BAD_REQUEST)?;

    if matches {
        data.correct_password(&acc);
        acc.password =
            bcrypt::hash(session.new, 12).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        data.invalidate_session(&mut acc);

        state
            .flush(&data)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(Json(data.update_account(acc)))
    } else {
        let count = data.wrong_password(&acc);

        if count >= MAX_ATTEMPTS_PER_ACC {
            Err(StatusCode::UNAUTHORIZED)
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

#[derive(Serialize, Clone, Debug)]
pub struct LinkResult {
    pub discord_id: String,
    pub discord_username: String,
    pub when: DateTime<Utc>,
    pub minecraft_uuid: Uuid,
}
