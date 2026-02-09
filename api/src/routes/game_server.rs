use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, Json};
use axum_typed_websockets::WebSocketUpgrade;
use tracing::debug;

use super::{profile::hydrate_profile_id, results, JsonResult, StringResult};
use crate::{
    actor::websocket::{IncomingMessage, OutgoingMessage},
    core::types::{
        consts::api_scopes::{SERVER_READ, SERVER_SELF_MODIFY},
        structs::packet::GameServerKeepAlive,
    },
    db::interface::DataSource,
    middleware::server_auth::AuthorizedServer,
    routes::scopes,
    AuthServer,
};

/// [GET] /api/servers/@me/ws
pub async fn websocket(
    State(state): State<Arc<AuthServer>>, AuthorizedServer(_token, server): AuthorizedServer,
    ws: WebSocketUpgrade<OutgoingMessage, IncomingMessage>,
) -> impl IntoResponse {
    ws.on_upgrade(async move |upgrade| {
        state.mailbox.ws_initiate(server.uuid, upgrade);
    })
}

/// [PATCH] /api/servers/@me/heartbeat
#[axum::debug_handler]
pub async fn keepalive(
    State(state): State<Arc<AuthServer>>, AuthorizedServer(token, server): AuthorizedServer,
    packet: Option<Json<GameServerKeepAlive>>,
) -> StringResult<String> {
    scopes!(token, [SERVER_SELF_MODIFY]);

    match packet {
        Some(packet) => {
            debug!(
                "[r:Heartbeat] Attempting to send to Mailbox: KeepAlive | server={}",
                server.uuid
            );
            state
                .mailbox
                .server_keepalive(server.uuid, packet.0.players, packet.0.motd);
        }
        None => {
            debug!("[r:Heartbeat] Attempting to send to Mailbox: Ping | server={}", server.uuid);
            state.mailbox.server_ping(server.uuid);
        }
    }

    Ok(String::new())
}

#[axum::debug_handler]
/// [GET] /api/servers/@me
pub async fn get_self(
    State(state): State<Arc<AuthServer>>, AuthorizedServer(token, server): AuthorizedServer,
) -> JsonResult<results::Server, String> {
    scopes!(token, [SERVER_READ]);

    let mut profiles = vec![];

    for staff in server.staff.0 {
        if let Ok(p) = state.db.get_profile_by_id(&staff).await {
            profiles.push(hydrate_profile_id(&state.db, p).await);
        }
    }

    Ok(Json(results::Server {
        id: server.uuid,
        name: server.name,
        game: server.game,
        versions: server.versions.0,
        max_players: server.max_players,
        staff: profiles,
    }))
}

/// [PATCH] /api/servers/@me/versions
pub async fn update_versions(
    State(state): State<Arc<AuthServer>>, AuthorizedServer(token, server): AuthorizedServer,
    Json(versions): Json<Vec<String>>,
) -> JsonResult<super::results::Server, String> {
    scopes!(token, [SERVER_READ, SERVER_SELF_MODIFY]);
    let response = state
        .db
        .update_server_versions(&server.uuid, versions.clone())
        .await
        .unwrap();

    state.mailbox.server_update_versions(server.uuid, versions);

    let mut profiles = vec![];

    for staff in response.staff.0 {
        if let Ok(p) = state.db.get_profile_by_id(&staff).await {
            profiles.push(hydrate_profile_id(&state.db, p).await);
        }
    }

    Ok(Json(results::Server {
        id: response.uuid,
        name: response.name,
        game: response.game,
        versions: response.versions.0,
        max_players: response.max_players,
        staff: profiles,
    }))
}
