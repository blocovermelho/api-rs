use db::{data::BanActor, drivers::json::data::BanIssuer, interface::NetworkProvider};
use serenity::all::{GuildId, RoleId, UserId};

use crate::{
    cidr::{lowest_common_prefix, MIN_COMMON_PREFIX},
    routes::prelude::{
        query_params::{AllowIp, BanIp, IpCheck},
        responses::{BanKind, IpKind},
        *,
    },
    shim::discord::DiscordAccess,
    utils::notify,
};

/// [GET] /auth/session?uuid=<ID>&ip=<IP>
pub async fn exists(
    State(state): State<Arc<AppState>>, Query(attempt): Query<IpCheck>,
) -> Res<bool> {
    let now = chrono::offset::Utc::now();

    let entries = state
        .db
        .get_allowlists_with_ip(&attempt.uuid, attempt.ip)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Account not found.")))?;

    if let Some(entry) = entries
        .into_iter()
        .find(|x| (now - x.last_join).num_minutes() <= 10)
    {
        let _ = state.db.bump_allowlist(entry).await;
        let _ = state.db.update_current_join(&attempt.uuid).await;

        return Ok(Json(true));
    }

    let broad = state
        .db
        .get_allowlists_with_range(&attempt.uuid, attempt.ip, MIN_COMMON_PREFIX)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Account not found.")))?;

    for entry in broad {
        let nmask = lowest_common_prefix(&entry.get_network(), &attempt.ip).unwrap();
        let _ = state.db.broaden_allowlist_mask(entry.clone(), nmask).await;

        let diff = now - entry.last_join;

        if diff.num_minutes() <= 10 {
            let _ = state.db.bump_allowlist(entry).await;
            let _ = state.db.update_current_join(&attempt.uuid).await;

            return Ok(Json(true));
        }
    }

    Ok(Json(false))
}

/// [PATCH] /auth/resume?uuid=<ID>&ip=<IP>
pub async fn resume(
    State(state): State<Arc<AppState>>, Query(attempt): Query<IpCheck>,
) -> Res<bool> {
    let user = state
        .db
        .get_user_by_uuid(&attempt.uuid)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("User not found.")))?;

    let entries = state
        .db
        .get_allowlists_with_ip(&attempt.uuid, attempt.ip)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Account not found.")))?;

    for entry in entries {
        let _ = state.db.bump_allowlist(entry).await;
    }

    let cfg = &state.config;
    let client = &state.client.serenity;

    state.db.update_current_join(&attempt.uuid).await.unwrap();

    let _ = client
        .add_member_role(
            GuildId::new(cfg.guild_id.parse().unwrap()),
            UserId::new(user.discord_id.parse().unwrap()),
            RoleId::new(cfg.role_id.parse().unwrap()),
            None,
        )
        .await;

    Ok(Json(true))
}

/// [POST] /auth/ban?uuid=<ID>&ip=<IP>
pub async fn ban_ip(
    State(state): State<Arc<AppState>>, Query(attempt): Query<BanIp>, Json(issuer): Json<BanIssuer>,
) -> Res<BanKind> {
    if let Ok(strict) = state.db.get_blacklists(attempt.ip).await {
        let mut flag = false;
        for entry in strict {
            let _ = state.db.bump_blacklist(entry).await;
            flag = true;
        }

        if flag {
            return Ok(Json(BanKind::Existing));
        }
    }

    if let Ok(broad) = state
        .db
        .get_blacklists_with_range(attempt.ip, MIN_COMMON_PREFIX)
        .await
    {
        if !broad.is_empty() {
            for entry in broad {
                let nmask = lowest_common_prefix(&entry.get_network(), &attempt.ip).unwrap();
                let _ = state.db.broaden_blacklist_mask(entry.clone(), nmask).await;
                let _ = state.db.bump_blacklist(entry).await;
            }
        }

        return Ok(Json(BanKind::Merged));
    }

    let actor = match issuer {
        BanIssuer::Manual(uuid) => BanActor::Staff(uuid),
        BanIssuer::Automatic => {
            BanActor::AutomatedSystem(format!("Logged while {} was online.", attempt.uuid))
        }
    };

    if state.db.create_blacklist(attempt.ip, actor).await.is_ok() {
        return Ok(Json(BanKind::New));
    }

    Ok(Json(BanKind::Invalid))
}

/// [POST] /auth/allow?uuid=<ID>&ip=<IP>
pub async fn whitelist_ip(
    State(state): State<Arc<AppState>>, Query(attempt): Query<AllowIp>,
) -> Res<bool> {
    if let Ok(strict) = state
        .db
        .get_allowlists_with_ip(&attempt.uuid, attempt.ip)
        .await
    {
        if !strict.is_empty() {
            return Ok(Json(true));
        }
    }

    // We always do automatic widening when possible, since the next call will be amortized and returned early.
    if let Ok(broad) = state
        .db
        .get_allowlists_with_range(&attempt.uuid, attempt.ip, MIN_COMMON_PREFIX)
        .await
    {
        if !broad.is_empty() {
            for entry in broad {
                let nmask = lowest_common_prefix(&entry.get_network(), &attempt.ip).unwrap();
                let _ = state.db.broaden_allowlist_mask(entry, nmask).await;
                // We don't bump the allowlist here, since that would lead to counting connections twice.
                // Allowlists are only bumped at `resume` (after (re)logging in) and `get_session` (on the case of a valid existing session).
            }
            return Ok(Json(true));
        }
    }

    let _ = state.db.create_allowlist(&attempt.uuid, attempt.ip).await;
    Ok(Json(true))
}

/// [POST] /auth/cidr?uuid=<id>&ip=<ip>
pub async fn check_ip(
    State(state): State<Arc<AppState>>, Query(attempt): Query<IpCheck>,
) -> Res<IpKind> {
    // This is a trivial "can join" or "is banned check"
    // We should check things broadly for users, but strict for bans.
    // If the user doesn't exist, we allow it in, only if the IP isn't banned.

    // Honestly this should be the place to put all broadening logic, and everything else should just strict-check.
    // Since this everything *should* be CIDR-checked at the Pre-Login phase.

    if let Ok(strict) = state
        .db
        .get_allowlists_with_ip(&attempt.uuid, attempt.ip)
        .await
    {
        if !strict.is_empty() {
            return Ok(Json(IpKind::Allowed));
        }
    }

    if let Ok(broad) = state
        .db
        .get_allowlists_with_range(&attempt.uuid, attempt.ip, MIN_COMMON_PREFIX)
        .await
    {
        if !broad.is_empty() {
            for entry in broad {
                let nmask = lowest_common_prefix(&entry.get_network(), &attempt.ip).unwrap();
                let _ = state.db.broaden_allowlist_mask(entry, nmask).await;
                // We don't bump the allowlist here, since that would lead to counting connections twice.
                // Allowlists are only bumped at `resume` (after (re)logging in) and `get_session` (on the case of a valid existing session).
            }
            return Ok(Json(IpKind::Allowed));
        }
    }

    if let Ok(strict) = state.db.get_blacklists(attempt.ip).await {
        if !strict.is_empty() {
            return Ok(Json(IpKind::Banned));
        }
    }

    if let Ok(broad) = state
        .db
        .get_blacklists_with_range(attempt.ip, MIN_COMMON_PREFIX)
        .await
    {
        if !broad.is_empty() {
            for entry in broad {
                let nmask = lowest_common_prefix(&entry.get_network(), &attempt.ip).unwrap();
                let _ = state.db.broaden_blacklist_mask(entry.clone(), nmask).await;
                let _ = state.db.bump_blacklist(entry).await;
            }

            return Ok(Json(IpKind::Banned));
        }
    }

    let server_name = match attempt.server {
        Some(uuid) => {
            if let Ok(server) = state.db.get_server(&uuid).await {
                server.name
            } else {
                "Servidor Desconhecido".to_string()
            }
        }
        None => "Servidor Desconhecido".to_string(),
    };

    // An user exist and can be notified.
    if let Ok(user) = state.db.get_user_by_uuid(&attempt.uuid).await {
        notify::unknown_ip(
            &state.client.serenity,
            &user,
            &server_name,
            &attempt.ip,
            &state.config.verification_channel_id,
        )
        .await;
    }

    Ok(Json(IpKind::Unknown))
}
