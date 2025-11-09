use std::collections::HashSet;

use poise::serenity_prelude::futures::{future, stream, Stream, StreamExt};

use crate::{db::interface::DataSource, discord::Context};

/// Autocompletion for usernames in from an discord user
pub async fn username<'a>(ctx: Context<'_>, partial: &'a str) -> impl Stream<Item = String> + 'a {
    let target_id = ctx.author().id.to_string();
    let db = &ctx.data().db;
    let users: Vec<_> = db
        .get_profiles_by_discord_id(target_id.clone())
        .await
        .unwrap_or_default()
        .iter()
        .map(|it| it.username.clone())
        .collect();

    stream::iter(users).filter(move |it| future::ready(it.starts_with(partial)))
}

/// Autocompletion for minecraft nicknames
pub async fn players<'a>(ctx: Context<'_>, partial: &'a str) -> impl Stream<Item = String> + 'a {
    let db = &ctx.data().db;
    let user_ids = db.get_all_users().await.unwrap_or_default();

    let mut users: HashSet<_> = HashSet::new();

    for id in user_ids {
        if let Ok(user) = db.get_user_by_uuid(&id).await {
            if partial.is_empty() || user.username.starts_with(partial) {
                users.insert(user.username);
            }
        }
    }

    stream::iter(users)
}

/// Autocompletion for server names
pub async fn servers<'a>(ctx: Context<'_>, partial: &'a str) -> impl Stream<Item = String> + 'a {
    let db = &ctx.data().db;
    let server_ids = db.get_all_servers_v2().await.unwrap_or_default();

    let mut servers: Vec<_> = vec![];

    for id in server_ids {
        if let Ok(server) = db.get_server(&id).await {
            if server.name.starts_with(partial) || partial.is_empty() {
                servers.push(server.name)
            }
        }
    }

    stream::iter(servers)
}

/// Autocompletion for servers in which the current user is a staffer
/// as defined in the server's "staff" field.
pub async fn staff_servers<'a>(
    ctx: Context<'_>, partial: &'a str,
) -> impl Stream<Item = String> + 'a {
    let db = &ctx.data().db;
    let profiles: HashSet<_> = db
        .get_profiles_by_discord_id(ctx.author().id.to_string())
        .await
        .unwrap_or_default()
        .iter()
        .map(|i| i.uuid)
        .collect();

    let server_ids = db.get_all_servers_v2().await.unwrap_or_default();

    let mut candidates: Vec<_> = vec![];

    for id in server_ids {
        if let Ok(server) = db.get_server(&id).await {
            let staff_set: HashSet<_> = server.staff.0.iter().cloned().collect();
            let intersect: HashSet<_> = staff_set.intersection(&profiles).collect();
            if !intersect.is_empty() && (server.name.starts_with(partial) || partial.is_empty()) {
                candidates.push(server.name);
            }
        }
    }

    stream::iter(candidates)
}
