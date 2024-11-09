use db::interface::DataSource;
use poise::{serenity_prelude::Mentionable, CreateReply, Modal};

use crate::{
    render::{embed, modal::NewPassword},
    AppContext, Error,
};

/// Change the password of an registered account.
#[poise::command(
    slash_command,
    name_localized("pt-BR", "mudarsenha"),
    description_localized("pt-BR", "Muda a senha de uma conta registrada.")
)]
pub async fn changepw(
    ctx: AppContext<'_>,
    #[description = "O username da conta do Minecraft"]
    #[autocomplete = "crate::autocomplete::username"]
    username: String,
) -> Result<(), Error> {
    // We need to check if the given username was owned by that user.

    let target_id = ctx.author().id.to_string();
    let db = &ctx.data().db;
    let users: Vec<_> = db
        .get_users_by_discord_id(target_id.clone())
        .await
        .unwrap_or_default();

    if users.is_empty() {
        ctx.send(
            CreateReply::default()
                .embed(embed::info(
                    "Novo jogador",
                    "Você não possui nenhum usuário linkada com a sua conta do discord.",
                ))
                .ephemeral(true),
        )
        .await?;
        return Ok(());
    }

    let user = users.iter().find(|it| it.username == username);

    match user {
        Some(u) => {
            if let Some(new_password) = NewPassword::execute(ctx).await? {
                let hash = bcrypt::hash(new_password.password, 12)?;
                db.update_password(&u.uuid, hash).await?;

                ctx.send(CreateReply::default()
                    .embed(embed::info(
                        "Senha alterada.",
                         format!("A senha da conta `{}` foi alterada com sucesso. Caso tenha esquecido da senha, execute esse comando novamente.", 
                         u.username
                        )
                    ))
                .ephemeral(true)
                ).await?;
            } else {
                ctx.send(CreateReply::default().embed(embed::error(
                    "Tempo esgotado.",
                    "O comando foi terminado por que se passou mais de 60 minutos.",
                )))
                .await?;
            }
        }
        None => {
            ctx.send(
                CreateReply::default()
                    .embed(embed::no_permissions(
                        format!("A conta de {} não é sua.", username),
                        format!(
                        "{} possui {} conta(s) linkada(s) com o discord, porém {} não é uma delas.",
                        ctx.author().mention(),
                        users.len(),
                        username
                    ),
                    ))
                    .ephemeral(false),
            )
            .await?;
        }
    }

    Ok(())
}
