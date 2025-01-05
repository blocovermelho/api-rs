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
use crate::{render::embed, Context, Error};


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
