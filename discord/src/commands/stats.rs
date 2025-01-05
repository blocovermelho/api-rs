// Statistics command
// Subcommands:

// [/stats server <server_name>]
// Shows the statistics for a given server

// [/stats server <server_name> playtime (<page>)]
// Shows a ranking of the playtime for server

use std::collections::HashMap;

use db::{
    data::{result::PlaytimeEntry, Server, User},
    interface::DataSource,
};
use poise::{
    serenity_prelude::{CreateEmbed, Member},
    CreateReply,
};
use uuid::Uuid;
use uuid_mc::PlayerUuid;

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
/// Mostra as estatísticas de um nick do minecraft
#[poise::command(slash_command)]
pub async fn player(
    ctx: Context<'_>,
    #[description = "O nick da conta"]
    #[autocomplete = "crate::autocomplete::players"]
    name: String,
) -> Result<(), Error> {
    let db = &ctx.data().db;
    let user_id = PlayerUuid::new_with_offline_username(&name);
    let account = db.get_user_by_uuid(user_id.as_uuid()).await;

    //WARN: This is stupid we should have a cache, but cache invalidation is a bitch.
    let mut servers: HashMap<Uuid, Server> = HashMap::new();
    let mut playtimes: HashMap<Uuid, Vec<PlaytimeEntry>> = HashMap::new();
    let server_ids = db.get_all_servers().await.unwrap();

    for id in server_ids {
        let info = db.get_server(&id).await.unwrap();
        servers.insert(id, info);
        let times = db.get_playtimes(&id).await.unwrap();
        playtimes.insert(id, times);
    }

    let embed = match account {
        Ok(user) => get_user_embed(user, &playtimes, &servers),
        Err(_) => embed::error(
            "Usuário não encontrado",
            format!("A conta de: {} não existe no servidor.", name),
        ),
    };

    let reply = CreateReply::default().embed(embed);

    let _ = ctx.send(reply).await;

    Ok(())
}

// [/stats member <@member>]
/// Mostra as estatíscas da(s) conta(s) de um membre do discord
#[poise::command(slash_command)]
pub async fn member(
    ctx: Context<'_>,
    #[description = "A conta do discord"]
    // #[autocomplete = "crate::autocomplete::members"]
    user: Member,
) -> Result<(), Error> {
    let discord_id = user.user.id;
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
