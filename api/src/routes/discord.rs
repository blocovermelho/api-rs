use futures::SinkExt;
use oauth2::{reqwest::async_http_client, AuthorizationCode};

use crate::{
    routes::prelude::{
        query_params::{DiscordLink, OfflineUuid},
        responses::LinkResult,
        *,
    },
    websocket::MessageOut,
};

/// [GET] /api/oauth?uuid=<ID>
pub async fn get_oauth_url(
    State(state): State<Arc<AppState>>, Query(uuid): Query<OfflineUuid>,
) -> Res<String> {
    let mut data = state.ephemeral.lock().await;

    let client = oauth::routes::get_client(&state.config).map_err(|e| -> ErrKind {
        ErrKind::Internal(Err::new("Error while getting a BasicClient").with_inner(e))
    })?;

    let (url, token) = oauth::routes::authorize(&client).url();

    data.links.insert(uuid.uuid, token.secret().clone());

    Ok(Json(url.to_string()))
}

/// [GET] /api/link?state=<>&code=<>
pub async fn link_account(
    State(state): State<Arc<AppState>>, Query(link): Query<DiscordLink>,
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
