use std::sync::Arc;

use axum::{
    extract::{Query, State},
    Json,
};
use futures::SinkExt;
use http::StatusCode;
use oauth2::{reqwest::async_http_client, AuthorizationCode};
use results::DiscordLink;

use super::{query_params, results, JsonResult};
use crate::{oauth, AuthServer, Event};

/// [GET] /api/link?state=<>&code=<>
pub async fn link(
    State(state): State<Arc<AuthServer>>, Query(link): Query<query_params::LinkQuery>,
) -> JsonResult<results::DiscordLink, String> {
    let eph = state.state.lock().await;
    let username = eph
        .nonces
        .get_by_right(&link.state)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid Nonce.".to_string()))?;

    let client = oauth::routes::get_client(&state.config).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Couldn't get a BasicClient from the given Config".to_string(),
        )
    })?;

    let token = client
        .exchange_code(AuthorizationCode::new(link.code))
        .request_async(async_http_client)
        .await
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                format!("Couldn't exchange the code for a discord user. {:?}", e),
            )
        })?;

    let user = oauth::routes::get_self(&state.clients.reqwest, &token)
        .await
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Token provided had no access to getting self.".to_string(),
            )
        })?;

    let response =
        match oauth::routes::get_guild(&state.clients.reqwest, &token, &state.config).await {
            Ok(guild) => DiscordLink {
                game_username: username.clone(),
                discord_username: user.username,
                when: Some(guild.joined_at),
            },
            Err(_) => DiscordLink {
                game_username: username.clone(),
                discord_username: user.username,
                when: None,
            },
        };

    let _ = state
        .event_bus
        .0
        .clone()
        .send(Event::DiscordLink {
            profile: response.game_username.clone(),
            discord_id: user.id,
            discord_username: response.discord_username.clone(),
            when: response.when,
        })
        .await;

    Ok(Json(response))
}

/// [GET] /api/link/new?username=<name>
pub async fn get_link(
    State(state): State<Arc<AuthServer>>, Query(username): Query<query_params::UsernameQuery>,
) -> JsonResult<String, String> {
    let mut data = state.state.lock().await;

    let client = oauth::routes::get_client(&state.config).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Couldn't get a BasicClient from the given Config".to_string(),
        )
    })?;

    let (url, token) = oauth::routes::authorize(&client).url();

    data.nonces
        .insert(username.username, token.secret().to_owned());

    Ok(Json(url.to_string()))
}
