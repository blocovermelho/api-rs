use std::{collections::HashSet, net::Ipv4Addr, time::Duration};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};

use chrono::{DateTime, Utc};
use futures::SinkExt;
use ipnet::Ipv4Net;
use iprange::IpRange;
use oauth2::{reqwest::async_http_client, AuthorizationCode};
use serde::{Deserialize, Serialize};
use serenity::all::{GuildId, RoleId, UserId};
use uuid::Uuid;

use crate::{
    cidr::{any_match, lowest_common_prefix, try_merge, HOST_PREFIX}, models::{Account, BanIssuer, BanResponse, CidrKind, CidrResponse, CreateServer, CreateUser, GraceResponse, Pos, Server, User}, store::MAX_ATTEMPTS_PER_ACC, websocket::MessageOut, AppState
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
pub async fn get_user(State(state): State<AppState>, Path(user_id): Path<Uuid>) -> Res<User> {
    let data = state.data.lock().await;

    let u = data
        .get_user(&user_id)
        .ok_or(ErrKind::NotFound(Err::new("User not found.")))?;

    Ok(Json(u.clone()))
}

/// [GET] /api/user/exists?uuid=<uuid>
pub async fn user_exists(
    State(state): State<AppState>,
    Query(user_id): Query<UuidQueryParam>,
) -> Res<bool> {
    let data = state.data.lock().await;
    let user = data.get_user(&user_id.uuid);

    Ok(Json(user.is_some()))
}

/// [DELETE] /api/user/:user_id
pub async fn delete_user(State(state): State<AppState>, Path(user): Path<Uuid>) -> Res<User> {
    let mut data = state.data.lock().await;

    let u = data
        .drop_user(&user)
        .ok_or(ErrKind::NotFound(Err::new("User not found.")))?;

    state
        .flush(&data)
        .map_err(|e| ErrKind::Internal(Err::new("Couldn't flush data for User").with_inner(e)))?;

    Ok(Json(u))
}

/// [POST] /api/user
pub async fn create_user(State(state): State<AppState>, Json(stub): Json<CreateUser>) -> Res<User> {
    let mut data = state.data.lock().await;
    let user = User::from(stub);

    if data.add_user(user.clone()) {
        state.flush(&data).map_err(|e| {
            ErrKind::Internal(Err::new("Couldn't flush the data for this user.").with_inner(e))
        })?;

        Ok(Json(user))
    } else {
        Err(ErrKind::BadRequest(Err::new("This user already exists.")))
    }
}

/// [GET] /api/servers
pub async fn get_servers(State(state): State<AppState>) -> Res<Vec<Server>> {
    let data = state.data.lock().await;
    Ok(Json(data.get_servers()))
}

/// [GET] /api/server/:server_id
pub async fn get_server(State(state): State<AppState>, Path(server_id): Path<Uuid>) -> Res<Server> {
    let data = state.data.lock().await;
    let server = data
        .get_server(&server_id)
        .ok_or(ErrKind::NotFound(Err::new("Server not found.")))?;
    Ok(Json(server.to_owned()))
}

/// [DELETE] /api/server/:user_id
pub async fn delete_server(State(state): State<AppState>, Path(user): Path<Uuid>) -> Res<Server> {
    let mut data = state.data.lock().await;

    let u = data
        .drop_server(&user)
        .ok_or(ErrKind::NotFound(Err::new("Server not found.")))?;

    state
        .flush(&data)
        .map_err(|e| ErrKind::Internal(Err::new("Couldn't flush data for Server").with_inner(e)))?;

    Ok(Json(u))
}

/// [POST] /api/server
pub async fn create_server(
    State(state): State<AppState>,
    Json(stub): Json<CreateServer>,
) -> Res<Server> {
    let mut data = state.data.lock().await;

    let server = Server::from(stub);

    if data.add_server(server.clone()) {
        state.flush(&data).map_err(|e| {
            ErrKind::Internal(Err::new("Couldn't flush data for Server.").with_inner(e))
        })?;

        Ok(Json(server))
    } else {
        Err(ErrKind::BadRequest(Err::new("Server already exists.")))
    }
}

/// [PATCH] /api/server/:server_id/enable
pub async fn enable(State(state): State<AppState>, Path(server_id): Path<Uuid>) -> Res<bool> {
    let mut data = state.data.lock().await;
    let mut server = data
        .get_server(&server_id)
        .ok_or(ErrKind::NotFound(Err::new("Server not found.")))?
        .clone();

    server.available = true;

    data.update_server(server);

    state.flush(&data).map_err(|e| {
        ErrKind::Internal(Err::new("Couldn't flush data for Server.").with_inner(e))
    })?;

    Ok(Json(true))
}

/// [PATCH] /api/server/:server_id/disable
pub async fn disable(State(state): State<AppState>, Path(server_id): Path<Uuid>) -> Res<bool> {
    let mut data = state.data.lock().await;
    let mut server = data
        .get_server(&server_id)
        .ok_or(ErrKind::NotFound(Err::new("Server not found.")))?
        .clone();

    server.available = false;

    data.update_server(server);

    state.flush(&data).map_err(|e| {
        ErrKind::Internal(Err::new("Couldn't flush data for Server.").with_inner(e))
    })?;

    Ok(Json(true))
}

/// [GET] /api/auth/session?uuid=<ID>&ip=<IP>
pub async fn get_session(
    State(state): State<AppState>,
    Query(session): Query<SessionQueryParams>,
) -> Res<bool> {
    let data = state.data.lock().await;
    let user = data
        .get_user(&session.uuid)
        .ok_or(ErrKind::NotFound(Err::new("User not found.")))?;

    Ok(Json(data.has_valid_session(
        user,
        &session.ip,
        chrono::offset::Utc::now(),
    )))
}

/// [PATCH] /api/auth/:player_id/resume
pub async fn resume(
    State(state) : State<AppState>,
    Path(player_id): Path<Uuid>,
) -> Res<bool> {
    let mut data = state.data.lock().await;
    let cfg = state.config.lock().await;
    let client = state.discord_client.clone();
    let mut p = data.get_account(&player_id).ok_or(ErrKind::NotFound(Err::new("Account not found.")))?.clone();
    let u = data.get_user(&player_id).ok_or(ErrKind::NotFound(Err::new("User not found.")))?;

    p.current_join = chrono::offset::Utc::now();

    let _ = client
        .http
        .add_member_role(
            GuildId::new(cfg.guild_id.parse().unwrap()),
            UserId::new(u.discord_id.parse().unwrap()),
            RoleId::new(cfg.role_id.parse().unwrap()),
            None,
        )
        .await;

    data.update_account(p);

    Ok(Json(true))
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
) -> Res<bool> {
    let mut data = state.data.lock().await;
    let cfg = state.config.lock().await;
    let client = state.discord_client.clone();

    let server = data
        .get_server(&server_id)
        .ok_or(ErrKind::NotFound(Err::new("Server not found.")))?;
    let mut user = data
        .get_user(&session.uuid)
        .ok_or(ErrKind::NotFound(Err::new("User not found.")))?
        .clone();
    let mut account = data
        .get_account(&user.uuid)
        .ok_or(ErrKind::NotFound(Err::new("Account not found.")))?
        .clone();

    user.last_server = Some(server.uuid);
    user.last_pos.insert(server_id, pos);

    let now = chrono::offset::Utc::now();

    let current_duration = user
        .playtime
        .get(&server_id)
        .unwrap_or(&Duration::default())
        .to_owned();
    let duration = (now - account.current_join).to_std().map_err(|e| {
        ErrKind::Internal(Err::new("Negative duration while calculating playtime.").with_inner(e))
    })?;

    user.playtime.insert(server_id, current_duration + duration);

    account.last_login = Some(now);
    // account.previous_ips.insert(session.ip);

    let req = client
        .http
        .remove_member_role(
            GuildId::new(cfg.guild_id.parse().unwrap()),
            UserId::new(user.discord_id.parse().unwrap()),
            RoleId::new(cfg.role_id.parse().unwrap()),
            None,
        )
        .await;

    data.update_account(account);
    data.update_user(user);

    state
        .flush(&data)
        .map_err(|e| ErrKind::Internal(Err::new("Couldn't flush data for User.").with_inner(e)))?;

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
) -> Res<bool> {
    let mut data = state.data.lock().await;
    let cfg = state.config.lock().await;
    let client = state.discord_client.clone();

    let server = data
        .get_server(&server_id)
        .ok_or(ErrKind::NotFound(Err::new("Server not found.")))?;
    let mut user = data
        .get_user(&session.uuid)
        .ok_or(ErrKind::NotFound(Err::new("User not found.")))?
        .clone();
    let mut account = data
        .get_account(&user.uuid)
        .ok_or(ErrKind::NotFound(Err::new("Account not found.")))?
        .clone();

    let password = bcrypt::verify(session.password, &account.password)
        .map_err(|e| ErrKind::Internal(Err::new(format!("BCrypt Error.")).with_inner(e)))?;

    if !password {
        let count = data.wrong_password(&account);

        if count >= MAX_ATTEMPTS_PER_ACC {
            Err(ErrKind::BadRequest(Err::new(
                "Exhausted MAX_ATTEMPTS for this account.",
            )))
        } else {
            Ok(Json(false))
        }
    } else {
        data.correct_password(&account);

        account.current_join = chrono::offset::Utc::now();
        data.update_account(account);

        let _ = client
            .http
            .add_member_role(
                GuildId::new(cfg.guild_id.parse().unwrap()),
                UserId::new(user.discord_id.parse().unwrap()),
                RoleId::new(cfg.role_id.parse().unwrap()),
                None,
            )
            .await;

        state.flush(&data).map_err(|e| {
            ErrKind::Internal(Err::new("Couldn't flush data for User.").with_inner(e))
        })?;

        Ok(Json(true))
    }
}

/// [GET] /auth/exists?uuid=<uuid>
pub async fn account_exists(
    State(state): State<AppState>,
    Query(account): Query<UuidQueryParam>,
) -> Res<bool> {
    let data = state.data.lock().await;

    Ok(Json(data.get_account(&account.uuid).is_some()))
}

/// [POST] /auth/handshake?id=<id>
pub async fn cidr_handshake(
    State(state): State<AppState>,
    Query(discord_id) : Query<DiscordIdQueryParam>,
) -> Res<String> {
    let mut data  = state.data.lock().await;
    let discord = state.discord_client.clone();
    let cfg = state.config.lock().await;

    
    let _ = discord.http.get_member(
        GuildId::new(cfg.guild_id.parse().expect("Invalid Guild Id")), 
        discord_id.id
    ).await.map_err(|_| {
        ErrKind::Internal(Err::new("Unknown Error"))
    })?;

    let user = data.get_user_from_discord(discord_id.id.get())
    .ok_or(ErrKind::NotFound(Err::new("User not found.")))?.clone();

    let secret = data.add_handshake(discord_id.id.get());

    state.flush(&data).map_err(|_| ErrKind::Internal(Err::new("Error while flushing data")))?;

    let _ = state.chs.verify.send(secret.clone(), discord_id.id.get()).await;
    let mut buff = state.chs.messages.0.lock().await;
    let _ = buff.send(MessageOut::CidrSyn(user.uuid)).await;

    Ok(Json(secret))
}

/// [POST] /auth/grace?id=<id>
pub async fn cidr_grace(
    State(state): State<AppState>,
    Query(discord_id) : Query<DiscordIdQueryParam>,
) -> Res<GraceResponse> {
    let mut data  = state.data.lock().await;

    if !data.has_handshake(discord_id.id.get()) {
        return Err(ErrKind::BadRequest(Err::new("Unknown Error")));
    }

    let response = data.grace_user(CidrKind::Allowed { user_id: discord_id.id.get(), self_registered: true, time: chrono::offset::Utc::now() });
    
    state.flush(&data).map_err(|_| ErrKind::Internal(Err::new("Error while flushing data")))?;

    Ok(Json(response))
}

/// [POST] /auth/ban?uuid=<>&ip=<ip>
/// ```json
/// "Automatic" |
/// {
///    "Manual": "<uuid>"
/// }
/// ```
pub async fn ban_cidr(
    State(state): State<AppState>,
    Query(params) : Query<BanCidrQueryParam>,
    Json(issuer) : Json<BanIssuer>
) -> Res<BanResponse> {
    let mut data  = state.data.lock().await;
    let response = data.ban_cidr(params.ip.to_string(), CidrKind::Banned { uuid: params.uuid, time: chrono::offset::Utc::now(), issuer: issuer, ip: params.ip });

    state.flush(&data).map_err(|_| ErrKind::Internal(Err::new("Error while flushing data")))?;

    Ok(Json(response))
}

/// [POST] /auth/allow?uuid=<id>&nonce=<nonce>&ip=<ip>

pub async fn allow_cidr(
    State(state): State<AppState>,
    Query(params) : Query<AllowCidrQueryParams>,
) -> Res<bool> {
    let mut data  = state.data.lock().await;
    let holder = data.get_handshake_holder(&params.nonce).ok_or(ErrKind::NotFound(Err::new("User not found")))?;

    if holder.uuid != params.uuid {
        return Err(ErrKind::BadRequest(Err::new("Unknown Error")));
    }

    let mut account = data.get_account(&holder.uuid)
    .ok_or(ErrKind::NotFound(Err::new("Account not found")))?
    .clone();

    let mut new_prefix: Option<u8> = None;
    let mut net : Option<Ipv4Net> = None;

    for network in account.cidr.clone() {
        new_prefix = lowest_common_prefix(&network, &params.ip);
        
        if new_prefix.is_some() {
            net = Some(network);
            break;
        }
    }

    if new_prefix.is_some() {
        let netw = net.unwrap();
        let addr = netw.addr();
        account.cidr.remove(&netw);
        account.cidr.insert(format!("{}/{}", addr, new_prefix.unwrap()).parse().unwrap());
    } else {
        account.cidr.insert(format!("{}/{}", params.ip, HOST_PREFIX).parse().unwrap());
    }

    if let Some(merged) = try_merge(&account.cidr) {
        account.cidr = merged;
    }

    data.update_account(account);
    let holder = data.get_handshake_holder(&params.nonce).ok_or( ErrKind::NotFound(Err::new("Missing User")))?;
    let id : u64 = holder.discord_id.parse().unwrap();
    data.clear_handshake(id);
    state.flush(&data).map_err(|_| ErrKind::Internal(Err::new("Error while flushing data")))?;

    Ok(Json(true))
}

/// [POST] /auth/disallow?id=<id>&ip=<ip>
pub async fn disallow_cidr(
    State(state): State<AppState>,
    Query(params) : Query<DiscordDenyCidrQueryParams>,
) -> Res<bool> {
    let mut data  = state.data.lock().await;
    let u = data.get_user_from_discord(params.id.get()).ok_or(ErrKind::BadRequest(Err::new("Missing User")))?;
    let mut a = data.get_account(&u.uuid).ok_or(ErrKind::BadRequest(Err::new("Missing Account")))?.clone(); 

    let mut range: Option<IpRange<Ipv4Net>> = None;
    let mut selected: Option<Ipv4Net> = None;

    for network in a.cidr.clone() {
        if ! network.contains(&params.ip) {
            continue;
        }

        let mut this = IpRange::new();
        this.add(network);

        let mut other: IpRange<Ipv4Net> = IpRange::new();
        other.add(format!("{}/32", &params.ip).parse().unwrap());
    
        range = Some(this.exclude(&other));
        selected = Some(network);
    };

    if selected.is_some() {
        a.cidr.remove(&selected.unwrap());
        for new_net in &range.unwrap() {
            a.cidr.insert(new_net);
        }
    }

    data.update_account(a);
    state.flush(&data).map_err(|_| ErrKind::Internal(Err::new("Error while flushing data")))?;

    Ok(Json(true))
}

/// [POST] /auth/disallow-ingame?uuid=<id>&ip=<ip>
pub async fn disallow_cidr_ingame(
    State(state): State<AppState>,
    Query(params) : Query<MinecraftDenyCidrQueryParams>,
) -> Res<bool> {
    let mut data  = state.data.lock().await;
    let mut a = data.get_account(&params.uuid).ok_or(ErrKind::BadRequest(Err::new("Missing Account")))?.clone(); 

    let mut range: Option<IpRange<Ipv4Net>> = None;
    let mut selected: Option<Ipv4Net> = None;

    for network in a.cidr.clone() {
        if ! network.contains(&params.ip) {
            continue;
        }

        let mut this = IpRange::new();
        this.add(network);

        let mut other: IpRange<Ipv4Net> = IpRange::new();
        other.add(format!("{}/32", &params.ip).parse().unwrap());
    
        range = Some(this.exclude(&other));
        selected = Some(network);
    };

    if selected.is_some() {
        a.cidr.remove(&selected.unwrap());
        for new_net in &range.unwrap() {
            a.cidr.insert(new_net);
        }
    }

    data.update_account(a);
    state.flush(&data).map_err(|_| ErrKind::Internal(Err::new("Error while flushing data")))?;

    Ok(Json(true))
}

/// [POST] /auth/cidr?uuid=<id>&ip=<ip>
pub async fn cidr_check(
    State(state): State<AppState>,
    Query(params) : Query<CheckCidrQueryParam>,
) -> Res<CidrResponse> {
    let data  = state.data.lock().await;
    let ledger = data.get_all_banned_cidr();
    if any_match(&ledger, &params.ip) {
        return Ok(Json(CidrResponse::Banned));
    }

    let a = data.get_account(&params.uuid).ok_or(ErrKind::BadRequest(Err::new("Missing Account")))?.clone();

    if any_match(&a.cidr, &params.ip) {
        return Ok(Json(CidrResponse::Allowed));
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
    State(state): State<AppState>,
    Json(session): Json<AuthenticationQueryParams>,
) -> Res<bool> {
    let mut data = state.data.lock().await;
    let user = data
        .get_user(&session.uuid)
        .ok_or(ErrKind::NotFound(Err::new("User not found.")))?;

    let hash = bcrypt::hash(&session.password, 12)
        .map_err(|e| ErrKind::Internal(Err::new("BCrypt Error.").with_inner(e)))?;

    let mut ips = HashSet::new();
    ips.insert(session.ip);

    let net = Ipv4Net::new(session.ip, 32).unwrap();
    let mut netset = HashSet::new();
    netset.insert(net);

    let acc = Account {
        uuid: user.uuid,
        password: hash,
        current_join: chrono::offset::Utc::now(),
        last_login: Some(chrono::offset::Utc::now()),
        cidr: netset
    };

    let result = data.add_account(acc);

    state
        .flush(&data)
        .map_err(|e| ErrKind::Internal(Err::new("Couldn't flush data for User.").with_inner(e)))?;

    Ok(Json(result))
}

/// [DELETE] /api/auth/:user_id
pub async fn delete_account(State(state): State<AppState>, Path(user): Path<Uuid>) -> Res<bool> {
    let mut data = state.data.lock().await;

    let _ = data
        .drop_account(&user)
        .ok_or(ErrKind::NotFound(Err::new("User not found.")))?;

    state.flush(&data).map_err(|e| {
        ErrKind::Internal(Err::new("Couldn't flush data for Account").with_inner(e))
    })?;

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
    State(state): State<AppState>,
    Json(session): Json<ChangePasswordQueryParams>,
) -> Res<bool> {
    let mut data = state.data.lock().await;

    let mut acc = data
        .get_account(&session.uuid)
        .ok_or(ErrKind::NotFound(Err::new("Account not found.")))?
        .clone();
    let matches = bcrypt::verify(session.old, &acc.password)
        .map_err(|e| ErrKind::Internal(Err::new("BCrypt Error.").with_inner(e)))?;

    if matches {
        data.correct_password(&acc);
        acc.password = bcrypt::hash(session.new, 12)
            .map_err(|e| ErrKind::Internal(Err::new("BCrypt Error.").with_inner(e)))?;

        data.invalidate_session(&mut acc);

        state.flush(&data).map_err(|e| {
            ErrKind::Internal(Err::new("Couldn't flush data for User.").with_inner(e))
        })?;

        Ok(Json(data.update_account(acc)))
    } else {
        let count = data.wrong_password(&acc);

        if count >= MAX_ATTEMPTS_PER_ACC {
            Err(ErrKind::BadRequest(Err::new(
                "Exhausted MAX_ATTEMPTS for this account.",
            )))
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
    pub ip: Ipv4Addr
}


#[derive(Deserialize)]
pub struct DiscordDenyCidrQueryParams {
    pub id : UserId,
    pub ip: Ipv4Addr
}

#[derive(Deserialize)]
pub struct MinecraftDenyCidrQueryParams {
    pub uuid : Uuid,
    pub ip: Ipv4Addr
}

#[derive(Deserialize)]
pub struct CheckCidrQueryParam {
    pub uuid: Uuid,
    pub ip: Ipv4Addr
}

#[derive(Deserialize)]
pub struct BanCidrQueryParam {
    pub uuid: Uuid,
    pub ip: Ipv4Addr
}

#[derive(Deserialize)]
pub struct DiscordIdQueryParam {
    pub id: UserId
}

#[derive(Serialize, Clone, Debug)]
pub struct LinkResult {
    pub discord_id: String,
    pub discord_username: String,
    pub when: DateTime<Utc>,
    pub minecraft_uuid: Uuid,
}
