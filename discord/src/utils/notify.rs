use std::net::Ipv4Addr;

use chrono::Utc;
use db::data::User;
use poise::serenity_prelude::{
    Channel, Client, CreateActionRow, CreateMessage, Mentionable, PermissionOverwrite, Permissions,
};

use crate::render::embed;

pub async fn unknown_ip(
    client: &Client, user: &User, server_name: &str, ip: &Ipv4Addr, backup_channel: &str,
) {
    let embed = embed::new_ip(user.username.clone(), server_name, ip, Utc::now());
    let btns = embed::new_ip_buttons(ip, Some(user.discord_id.clone()));
    let warning = embed::input("Ação necessária - Permissão Discord",
    "O Bot não foi capaz de te enviar a mensagem de verificação pela sua DM.
     Verifique se a configuração \"Mensagens Diretas\" está **ativada** para o Discord do Bloco Vermelho.")
     .image("https://raw.githubusercontent.com/blocovermelho/assets/refs/heads/main/dm-settings-2024.png");

    // Send a message thats ephemeral, mentioning the user.
    // Heuristics to be followed:
    // - If the user allows direct messages from server members, send a DM
    // - As a backup, use the verification channel on the discord server

    let backup = client
        .http
        .get_channel(backup_channel.parse().unwrap())
        .await
        .expect("Invalid Backup Notification Channel");

    if let Ok(d_user) = client.http.get_user(user.discord_id.parse().unwrap()).await {
        let mut retry = false;

        if let Ok(ch) = d_user.create_dm_channel(&client.http).await {
            let message = CreateMessage::new()
                .embed(embed.clone())
                .components(vec![CreateActionRow::Buttons(btns.clone())])
                .content(d_user.mention().to_string());

            let dm_message = ch.send_message(&client.http, message).await;
            retry = dm_message.is_err();
        }

        if retry {
            if let Channel::Guild(ch) = backup {
                let message = CreateMessage::new()
                    .add_embed(embed)
                    .add_embed(warning)
                    .components(vec![CreateActionRow::Buttons(btns)])
                    .content(d_user.mention().to_string());

                let overwrite = PermissionOverwrite {
                    allow: Permissions::VIEW_CHANNEL | Permissions::READ_MESSAGE_HISTORY,
                    deny: Permissions::SEND_MESSAGES,
                    kind: poise::serenity_prelude::PermissionOverwriteType::Member(d_user.id),
                };

                let _ = ch.create_permission(&client.http, overwrite).await;

                let _ = ch.send_message(&client.http, message).await;
            }
        }
    }
}
