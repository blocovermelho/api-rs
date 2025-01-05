use std::collections::HashSet;

use db::interface::DataSource;
use poise::serenity_prelude::futures::{future, stream, Stream, StreamExt};

use crate::Context;

pub async fn username<'a>(ctx: Context<'_>, partial: &'a str) -> impl Stream<Item = String> + 'a {
    let target_id = ctx.author().id.to_string();
    let db = &ctx.data().db;
    let users: Vec<_> = db
        .get_users_by_discord_id(target_id.clone())
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
    let server_ids = db.get_all_servers().await.unwrap_or_default();

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
