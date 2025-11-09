use std::{collections::HashSet, sync::Arc};

use axum::{extract::State, Json};
use http::StatusCode;

use super::{profile::hydrate_profile_id, results, JsonResult, StringResult};
use crate::{
    core::types::{
        consts::api_scopes::{SERVER_READ, SERVER_SELF_MODIFY},
        enums::PlayerState,
        structs::{packet::GameServerKeepAlive, Player},
    },
    db::interface::DataSource,
    middleware::server_auth::AuthorizedServer,
    routes::scopes,
    AuthServer,
};

/// [GET] /api/servers/<id>
/// [PATCH] /api/servers/@me/heartbeat
pub async fn keepalive(
    State(state): State<Arc<AuthServer>>, AuthorizedServer(token, server): AuthorizedServer,
    packet: Option<Json<GameServerKeepAlive>>,
) -> StringResult<String> {
    scopes!(token, [SERVER_SELF_MODIFY]);

    let mut eph = state.state.lock().await;
    let db = &state.db;

    let mut server = if let Some(s) = eph.servers.remove(&token.owner) {
        s
    } else {
        server.into()
    };

    if let Some(Json(packet)) = packet {
        let packet_players: HashSet<_> = packet.players.iter().cloned().collect();
        let server_players: HashSet<_> = server.players.keys().cloned().collect();

        let added = &packet_players - &server_players;
        let removed = &server_players - &packet_players;

        for item in added {
            // Check if the player has a profile and if not just set it as a visitor
            let profile = db.get_profile(item.clone()).await.ok();

            let player = match profile {
                Some(profile) => Player {
                    profile: Some(profile.into()),
                    status: PlayerState::PreLogin,
                },
                None => Player { profile: None, status: PlayerState::Visitor },
            };

            server.players.insert(item.clone(), player);
        }
        for player in &removed {
            server.players.remove(player);
        }
    }

    eph.servers.insert(token.owner, server);

    Ok(String::new())
}
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
