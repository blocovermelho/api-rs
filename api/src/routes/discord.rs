use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use oauth2::AuthorizationCode;
use serenity::all::{CacheHttp, Colour, GuildId, Role};

use super::{query_params, JsonResult};
use crate::{
    actor::websocket::{DiscordExtras, DiscordLink},
    middleware::server_auth::AuthorizedServer,
    oauth,
    routes::StringResult,
    AuthServer,
};

/// [GET] /api/link?state=<>&code=<>
pub async fn link(
    State(state): State<Arc<AuthServer>>, Query(link): Query<query_params::LinkQuery>,
) -> StringResult<String> {
    let token = state
        .clients
        .oauth
        .exchange_code(AuthorizationCode::new(link.code))
        .request_async(&state.clients.reqwest)
        .await
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Não foi possivel conectar com a API do discord. Sugestão: Use o comando /link (Bot do Discord) para conectar sua conta manualmente.".to_string()
            )
        })?;

    let username = state
        .mailbox
        .get_user_by_csrf(link.state)
        .await
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "O código informado é invalido ou já foi utilizado. O link de conexão automática só funciona uma vez, crie um novo e tente novamente.".to_string()))?;

    let user = oauth::routes::get_self(&state.clients.reqwest, &token)
        .await
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Token provided had no access to getting self.".to_string(),
            )
        })?;

    let guild = state
        .mailbox
        .get_discord_guild(state.config.guild_id.parse().unwrap())
        .await;

    let response =
        match oauth::routes::get_guild(&state.clients.reqwest, &token, &state.config).await {
            Ok(member) => {
                let role = if let Some(h_guild) = guild {
                    let mut roles = h_guild.roles;
                    roles.retain(|k, _| member.roles.contains(k));
                    let mut highest: Option<Role> = None;
                    for role in roles.values() {
                        if let Some(ref highest) = highest {
                            if role.position < highest.position ||
                                (role.position == highest.position && role.id > highest.id)
                            {
                                continue;
                            }
                        }
                        highest = Some(role.clone());
                    }
                    highest
                } else {
                    None
                };

                DiscordLink {
                    username,
                    discord_id: user.id,
                    discord_handle: user.name,
                    is_member: true,
                    member_since: member.joined_at.map(|it| it.to_utc()),
                    extras: Some(DiscordExtras {
                        nickname: member.nick,
                        role_color: role.as_ref().map(|it| it.colour.hex()),
                        role_name: role.as_ref().map(|it| it.name.clone()),
                    }),
                }
            }
            Err(_) => DiscordLink {
                username,
                discord_id: user.id,
                discord_handle: user.name,
                is_member: false,
                member_since: None,
                extras: None,
            },
        };

    state.mailbox.ws_send_discord_link(response);

    Ok("Conta conectada com sucesso. Você pode retornar ao servidor.".to_string())
}

/// [GET] /api/link/new?username=<name>
pub async fn get_link(
    State(state): State<Arc<AuthServer>>, Query(username): Query<query_params::UsernameQuery>,
) -> JsonResult<String, String> {
    let client = oauth::routes::get_client(&state.config).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Couldn't get a BasicClient from the given Config".to_string(),
        )
    })?;

    let (url, token) = oauth::routes::authorize(&client).url();

    state
        .mailbox
        .tokens_submit_csrf(username.username, token.secret().clone());

    Ok(Json(url.to_string()))
}

/// [GET] /api/link/manual?username=<user>&token=<token>
pub async fn manual(
    State(state): State<Arc<AuthServer>>, AuthorizedServer(_token, _server): AuthorizedServer,
    Query(query): Query<query_params::ManualLink>,
) -> JsonResult<DiscordLink, String> {
    let user = state
        .mailbox
        .get_userid_by_token(query.token.clone())
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid Token.".to_string()))?;

    let user = state
        .clients
        .serenity
        .http
        .get_user(user)
        .await
        .expect("Provided User Id must be valid");

    let guild = state
        .clients
        .serenity
        .http
        .get_guild(state.config.guild_id.parse().unwrap())
        .await
        .expect("Bot must be on guild for this functionality to work.");

    let response = if let Ok(member) = guild.member(&state.clients.serenity.http, user.id).await {
        let role = guild
            .roles
            .iter()
            .filter(|(k, v)| member.roles.contains(*k) && v.colour != Colour::default())
            .max_by_key(|(_, v)| v.position)
            .map(|(_, v)| v);

        DiscordLink {
            username: query.username,
            discord_id: user.id,
            discord_handle: user.name,
            is_member: true,
            member_since: member.joined_at.map(|it| it.to_utc()),
            extras: Some(DiscordExtras {
                nickname: member.nick,
                role_color: role.map(|it| format!("#{}", it.colour.hex())),
                role_name: role.map(|it| it.name.clone()),
            }),
        }
    } else {
        DiscordLink {
            username: query.username,
            discord_id: user.id,
            discord_handle: user.name,
            is_member: false,
            member_since: None,
            extras: None,
        }
    };

    state.mailbox.token_revoke(query.token);
    state.mailbox.ws_send_discord_link(response.clone());

    Ok(Json(response))
}
