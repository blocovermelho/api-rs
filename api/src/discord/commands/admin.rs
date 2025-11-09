use std::{collections::HashSet, num::NonZeroU64};

use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use poise::CreateReply;
use serenity::all::{
    ComponentInteractionCollector, ComponentInteractionDataKind, CreateActionRow, CreateMessage,
    CreateSelectMenu, CreateSelectMenuKind, CreateSelectMenuOption, ReactionType,
};

use crate::{
    core::types::consts::api_scopes::{
        PROFILE_CREATE, PROFILE_OTHERS_MODIFY, PROFILE_READ, SERVER_READ, SERVER_SELF_MODIFY,
    },
    db::interface::DataSource,
    discord::{
        render::embed::{admin, admin_token, info},
        utils::CompInterExt,
        AppContext, Error,
    },
};

/// Controle geral da API
#[poise::command(slash_command, subcommands("grant"))]
pub async fn apictl(ctx: AppContext<'_>) -> Result<(), Error> {
    Ok(())
}

/* Será adicionado no futuro. Fazer comando avançado pro discord
 * é a ruína da minha existência e isso tem q ser interativo pra evitar
 * que eu apague algo sem querer.
 *
 * /// Apaga um servidor
 * #[poise::command(slash_command, owners_only)]
 * pub async fn delete(ctx: AppContext<'_>) -> Result<(), Error> {}
 *
 */

/// Altera as permissões de acesso de um servidor
#[poise::command(slash_command, owners_only)]
pub async fn grant(
    ctx: AppContext<'_>, #[autocomplete = "crate::discord::autocomplete::servers"] server: String,
) -> Result<(), Error> {
    let db = &ctx.data.db;

    if let Ok(server) = db.get_server_by_name(server).await {
        let hashed_time = BASE64_URL_SAFE_NO_PAD.encode(Utc::now().timestamp().to_be_bytes());
        let header = format!("bvadmin:grant@{}_{}", server.uuid, hashed_time);

        let components = vec![CreateActionRow::SelectMenu(
            CreateSelectMenu::new(
                header.clone(),
                CreateSelectMenuKind::String {
                    options: [
                        as_menu_option(
                            SERVER_READ,
                            "O servidor pode ler dados de todos os servidores.",
                            true,
                            false,
                        ),
                        as_menu_option(
                            SERVER_SELF_MODIFY,
                            "O servidor pode atualizar seus próprios dados.",
                            true,
                            false,
                        ),
                        as_menu_option(
                            PROFILE_READ,
                            "O servidor pode ler dados dos perfis. Isso inclui a capacidade de verificar senhas.",
                            true,
                            false,
                        ),
                        as_menu_option(
                            PROFILE_CREATE,
                            "O servidor pode criar perfis de jogadores novos.",
                            false,
                            true,
                        ),
                        as_menu_option(
                            PROFILE_OTHERS_MODIFY,
                            "O servidor pode alterar os dados de quaisquer perfis.",
                            false,
                            true,
                        )
                    ]
                    .to_vec(),
                },
        ).placeholder("Selecione algum scope.").max_values(5).min_values(0))];

        let reply = CreateReply::default()
            .embed(admin(
                "Alterando scopes",
                format!("Selecione os scopes à serem permitidos para o servidor {}", server.name),
            ))
            .components(components)
            .ephemeral(true);

        ctx.send(reply).await?;

        while let Some(mci) = ComponentInteractionCollector::new(ctx)
            .author_id(ctx.author().id)
            .timeout(std::time::Duration::from_secs(120))
            .await
        {
            if mci.data.custom_id == header {
                if let ComponentInteractionDataKind::StringSelect { values } = mci.clone().data.kind
                {
                    if db.create_token(&server.uuid, values.clone()).await.is_ok() {
                        // Send a message to all unique admins for that server on their direct messages.
                        // If they arent the one who started the command.
                        let mut already_sent = HashSet::new();

                        for staff in server.staff.0.clone() {
                            if let Ok(profile) = db.get_profile_by_id(&staff).await {
                                if let Ok(member) = ctx
                                    .http()
                                    .get_user(
                                        profile.discord_id.parse::<NonZeroU64>().unwrap().into(),
                                    )
                                    .await
                                {
                                    if already_sent.contains(&profile.discord_id) {
                                        continue;
                                    }

                                    if member.id != ctx.author().id {
                                        member
                                            .dm(
                                                &ctx,
                                                CreateMessage::new()
                                                    .add_embed(admin_token(&server, &values)),
                                            )
                                            .await?;
                                    } else {
                                        let reply = CreateReply::default()
                                            .embed(admin_token(&server, &values))
                                            .ephemeral(true);

                                        ctx.send(reply).await?;
                                    }
                                    already_sent.insert(profile.discord_id);
                                }
                            }
                        }
                        mci.update_message(
                            ctx.serenity_context(),
                            info(
                                "Permissões Atualizadas",
                                format!(
                                    "As permissões para o servidor {} agora são: {}",
                                    server.name,
                                    values.clone().join(", ")
                                ),
                            ),
                            vec![],
                        )
                        .await?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn as_menu_option(
    constant: &str, description: &str, default: bool, restricted: bool,
) -> CreateSelectMenuOption {
    CreateSelectMenuOption::new(constant.to_string(), constant.to_string())
        .description(description)
        .emoji(if restricted {
            ReactionType::Unicode("⚠️".to_string())
        } else {
            ReactionType::Unicode("✅".to_string())
        })
        .default_selection(default)
}
