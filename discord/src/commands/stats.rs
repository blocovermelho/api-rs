// Statistics command
// Subcommands:

// [/stats server <server_name>]
// Shows the statistics for a given server

// [/stats server <server_name> playtime (<page>)]
// Shows a ranking of the playtime for server

// [/stats self]
// Shows current user statistics
use std::collections::HashMap;

use db::{
    data::{result::PlaytimeEntry, Server, User},
    interface::DataSource,
};
use poise::{
    serenity_prelude::{CreateEmbed, Member},
    CreateReply,
};
use crate::{render::embed, Context, Error};

/// Mostra as estatíscas das sua(s) conta(s)
#[poise::command(slash_command)]
pub async fn _self(ctx: Context<'_>) -> Result<(), Error> {
    let discord_id = ctx.author().id;
    let db = &ctx.data().db;
    let server_ids = db.get_all_servers().await.unwrap();

    //WARN: This is stupid we should have a cache, but cache invalidation is a bitch.
    let mut servers: HashMap<Uuid, Server> = HashMap::new();
    let mut playtimes: HashMap<Uuid, Vec<PlaytimeEntry>> = HashMap::new();

    for id in server_ids {
        let info = db.get_server(&id).await.unwrap();
        servers.insert(id, info);
        let times = db.get_playtimes(&id).await.unwrap();
        playtimes.insert(id, times);
    }

    let embeds = match db.get_users_by_discord_id(discord_id.to_string()).await {
        Ok(accounts) => {
            let mut embeds: Vec<CreateEmbed> = vec![];

            for account in accounts {
                embeds.push(get_user_embed(account, &playtimes, &servers));
            }

            embeds
        }
        Err(_) => {
            vec![embed::error(
                "Nenhuma conta encontrada",
                "Você não possui contas linkadas ao discord.",
            )]
        }
    };

    let mut reply = CreateReply::default();

    for embed in embeds {
        reply = reply.embed(embed)
    }

    ctx.send(reply).await.unwrap();

    Ok(())
}

// [/stats player <player_name>]
// Show statistics for a player

// [/stats member <@member>]
// Show statistics for all players connected to a discord account
fn get_user_embed(
    user: User, playtimes: &HashMap<Uuid, Vec<PlaytimeEntry>>, servers: &HashMap<Uuid, Server>,
) -> CreateEmbed {
    let mut base = embed::user(
        user.username,
        user.created_at,
        user.discord_id,
        user.last_server
            .map(|it| servers.get(&it).unwrap().name.clone()),
    );

    for (k, v) in servers {
        let pos_iter = playtimes.get(k).unwrap().iter();
        let rank = pos_iter.clone().position(|it| it.player_uuid == user.uuid);
        let time = pos_iter.clone().find(|it| it.player_uuid == user.uuid);

        if let Some(time) = time {
            base = embed::server_field(&base, time.playtime.0, v.name.clone(), rank.unwrap() + 1)
        }
    }

    base
}
