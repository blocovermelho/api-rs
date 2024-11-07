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
