use std::{net::Ipv4Addr, time::Duration};

use db::{
    data::User,
    drivers::err::DriverError,
    helper::{check_cidr, CidrAction},
    interface::DataSource,
};
use poise::{
    serenity_prelude::{
        ButtonStyle, Channel, ComponentInteraction, Context, CreateActionRow, CreateButton,
        CreateInteractionResponse, CreateInteractionResponseMessage, Mentionable,
        PermissionOverwriteType,
    },
    FrameworkContext,
};
use tokio::time::sleep;
use uuid_mc::PlayerUuid;

use crate::{
    id::{Action, Id},
    render::embed,
    utils::CompInterExt,
    Data, Error,
};

enum ActionResult {
    Pass,
    Return,
}

fn misclick_prevention(interaction: &ComponentInteraction, target: Option<String>) -> ActionResult {
    if let Some(target) = target {
        if interaction.user.id.to_string() != target {
            return ActionResult::Return;
        }
    }

    ActionResult::Pass
}

async fn send_missclick_response(
    ctx: &Context, interaction: &ComponentInteraction, user: &User,
) -> Result<(), Error> {
    interaction
        .create_response(
            ctx,
            CreateInteractionResponse::Message(
                CreateInteractionResponseMessage::new()
                    .embed(embed::error(
                        "Conta não pertencente",
                        format!(
                            "A conta: `{}` não pertence ao usuário {}.",
                            user.username,
                            interaction.user.mention()
                        ),
                    ))
                    .components(vec![])
                    .ephemeral(true),
            ),
        )
        .await?;

    Ok(())
}

async fn get_user_from_message(
    fw: &FrameworkContext<'_, Data, Error>, interaction: &ComponentInteraction,
) -> Result<User, Error> {
    let db = fw.user_data().await.db.clone();

    let embed = interaction
        .message
        .embeds
        .first()
        .ok_or_else(|| DriverError::Generic("Unable to get Embed".to_string()))?
        .clone();

    let title = embed
        .title
        .ok_or_else(|| DriverError::Generic("Embed didn't have any title".to_string()))?;

    let username = title
        .split_whitespace()
        .last()
        .ok_or_else(|| DriverError::Generic("Unable to get username from embed".to_string()))?;

    let player_uuid = PlayerUuid::new_with_offline_username(username);
    let uuid = player_uuid.as_uuid();

    let user = db.get_user_by_uuid(uuid).await?;

    Ok(user)
}

// Handler for New IPs
pub async fn ip_accept(
    ctx: &Context, fw: &FrameworkContext<'_, Data, Error>, interaction: &ComponentInteraction,
    ip: Ipv4Addr, target: Option<String>,
) -> Result<(), Error> {
    println!("[Ip Accept] Handling interaction.");
    let db = fw.user_data().await.db.clone();

    let user = get_user_from_message(fw, interaction).await?;

    if matches!(misclick_prevention(interaction, target), ActionResult::Return) {
        send_missclick_response(ctx, interaction, &user).await?;
        return Ok(());
    }

    let candidates = db.get_allowlists_with_range(&user.uuid, ip, 16).await?;

    println!("[Ip Accept] Got Allowlists for {} ({})", user.username, user.uuid);

    match check_cidr(candidates, ip) {
        CidrAction::Match(_) => {
            println!(
                "[Ip Accept] Ip Already matched registry for {} ({})",
                user.username, user.uuid
            );
        }
        CidrAction::MaskUpdate(net, u) => {
            db.broaden_allowlist_mask(net, u).await?;

            println!("[Ip Accept] Broadened mask for {} ({})", user.username, user.uuid);
        }
        CidrAction::Unmatched(_) => {
            db.create_allowlist(&user.uuid, ip).await?;

            println!("[Ip Accept] Created new Allowlist for {} ({})", user.username, user.uuid);
        }
    }

    let embed = embed::info(
        "IP adicionado.",
        format!("O IP: {} foi adicionado a conta: `{}` com sucesso.", ip, user.username),
    );
    let components = vec![];

    let message = CreateInteractionResponseMessage::new()
        .embed(embed)
        .components(components);

    let response = CreateInteractionResponse::UpdateMessage(message);
    interaction.create_response(ctx, response).await?;

    if let Channel::Guild(ch) = ctx.http.get_channel(interaction.channel_id).await? {
        sleep(Duration::from_secs(5)).await;
        _ = ch.delete_messages(ctx, vec![interaction.message.id]).await;
        _ = ch
            .delete_permission(ctx, PermissionOverwriteType::Member(interaction.user.id))
            .await;
    }

    Ok(())
}

pub async fn ip_deny(
    ctx: &Context, fw: &FrameworkContext<'_, Data, Error>, interaction: &ComponentInteraction,
    ip: Ipv4Addr, target: Option<String>,
) -> Result<(), Error> {
    if matches!(misclick_prevention(interaction, target.clone()), ActionResult::Return) {
        let user = get_user_from_message(fw, interaction).await?;
        send_missclick_response(ctx, interaction, &user).await?;
        return Ok(());
    }

    // Denying its so easy...
    let db = fw.user_data().await.db.clone();
    let candidates = db.get_blacklists_with_range(ip, 16).await?;
    let _msg = interaction.message.clone();

    match check_cidr(candidates, ip) {
        CidrAction::Match(_) => {}
        CidrAction::MaskUpdate(net, u) => {
            db.broaden_blacklist_mask(net, u).await?;
        }
        CidrAction::Unmatched(_) => {
            db.create_blacklist(
                ip,
                db::data::BanActor::AutomatedSystem(format!(
                    "[{}] IP was denied via discord manually.",
                    interaction.user.id
                )),
            )
            .await?;
        }
    }

    interaction
        .create_response(
            ctx,
            CreateInteractionResponse::UpdateMessage(
                CreateInteractionResponseMessage::new()
                    .embed(embed::info(
                        "IP adicionado.",
                        format!(
                            "O IP: {} foi bloqueado **permanentemente**.
                            Caso isso tenha sido um engano, entrar em contato com a Staff.

                            Obrigade por deixar o Bloco Vermelho mais seguro.",
                            ip
                        ),
                    ))
                    .components(vec![]),
            ),
        )
        .await?;

    Ok(())
}

pub async fn ip_prompt(
    ctx: &Context, fw: &FrameworkContext<'_, Data, Error>, interaction: &ComponentInteraction,
    ip: Ipv4Addr, target: Option<String>,
) -> Result<(), Error> {
    if matches!(misclick_prevention(interaction, target.clone()), ActionResult::Return) {
        let user = get_user_from_message(fw, interaction).await?;
        send_missclick_response(ctx, interaction, &user).await?;
        return Ok(());
    }

    let nonce = ip.to_bits().to_string();

    let accept = CreateButton::new(
        Id::encode(&Id {
            action: Action::AcceptIp,
            nonce: nonce.clone(),
            target: target.clone(),
        })
        .unwrap(),
    )
    .style(ButtonStyle::Secondary)
    .label("Permitir Acesso")
    .disabled(true);

    let ban = CreateButton::new(
        Id::encode(&Id {
            action: Action::DenyIp,
            nonce: nonce.clone(),
            target: target.clone(),
        })
        .unwrap(),
    )
    .style(ButtonStyle::Danger)
    .label(format!("Banir IP: {}", ip));

    let back =
        CreateButton::new(Id::encode(&Id { action: Action::ReturnIp, nonce, target }).unwrap())
            .style(ButtonStyle::Primary)
            .label("Voltar");

    interaction
        .update_message(
            ctx,
            embed::input(
                "Banir IP",
                format!(
        "Você está prestes a **banir permanentemente** o IP `{}` de **TODOS OS SERVIDORES**.
        
        Clique em **Banir IP** para confirmar, *se você não reconhecer esse login*.
        Clique em **Voltar** para voltar ao menu anterior.
        Clique em **Meu IP** para abrir um site com o seu IP (use isso para comparar com o IP a ser banido: `{}`).
        ", ip, ip),
            ),
            vec![CreateActionRow::Buttons(vec![
                accept,
                ban,
                back,
                CreateButton::new_link("https://whatismyipaddress.com/").label("Seu IP Atual"),
            ])],
        )
        .await?;

    Ok(())
}

pub async fn ip_back(
    ctx: &Context, fw: &FrameworkContext<'_, Data, Error>, interaction: &ComponentInteraction,
    ip: Ipv4Addr, target: Option<String>,
) -> Result<(), Error> {
    if matches!(misclick_prevention(interaction, target.clone()), ActionResult::Return) {
        let user = get_user_from_message(fw, interaction).await?;
        send_missclick_response(ctx, interaction, &user).await?;
        return Ok(());
    }

    interaction
        .update_message(
            ctx,
            embed::new_ip(
                interaction.user.clone().name,
                "Bloco Vermelho",
                &ip,
                interaction.message.timestamp.to_utc(),
            ),
            vec![CreateActionRow::Buttons(vec![
                CreateButton::new(
                    Id::encode(&Id {
                        action: crate::id::Action::AcceptIp,
                        nonce: ip.to_bits().to_string(),
                        target: target.clone(),
                    })
                    .unwrap(),
                )
                .label("Permitir Acesso")
                .style(ButtonStyle::Success),
                CreateButton::new(
                    Id::encode(&Id {
                        action: crate::id::Action::PromptBanIp,
                        nonce: ip.to_bits().to_string(),
                        target,
                    })
                    .unwrap(),
                )
                .label("Recusar Acesso")
                .style(ButtonStyle::Danger),
                CreateButton::new_link("https://whatismyipaddress.com/").label("Seu IP Atual"),
            ])],
        )
        .await?;
    Ok(())
}
