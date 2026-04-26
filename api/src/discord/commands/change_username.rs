use poise::{serenity_prelude::Mentionable, CreateReply, Modal};
use regex::Regex;

use crate::{
    db::interface::DataSource,
    discord::{
        render::{embed, modal::NewPassword},
        AppContext, Error,
    },
};

/// Change the username of an registered account.
#[poise::command(
    slash_command,
    name_localized("pt-BR", "mudarnome"),
    description_localized("pt-BR", "Muda o username de uma conta registrada.")
)]
pub async fn changename(
    ctx: AppContext<'_>,
    #[description = "O nome atual da conta"]
    #[autocomplete = "crate::discord::autocomplete::username"]
    old: String,
    #[description = "O novo nome a ser utilizado"] new: String,
) -> Result<(), Error> {
    let mc_acct_re: Regex = Regex::new(r"^[a-zA-Z0-9_]{2,16}$").unwrap();
    if !mc_acct_re.is_match(&new) {
        ctx.send(
            CreateReply::default()
                .embed(embed::error(
                    "O novo nome da conta é inválido.",
                    "Verifique se o nick:\n- Tem de 2 à 16 caracteres\n- Não possui espaços\n- Começa com uma letra, numero ou underline",
                ))
                .ephemeral(true),
        )
        .await?;
        return Ok(());
    }

    if let Ok(acct) = ctx.data.db.get_profile(new.clone()).await {
        let standing = if acct.discord_id == ctx.author().id.to_string() {
            "é você. A operação de unificar duas contas em uma ainda não foi implementada.
            Caso deseje usar esse nick no lugar do anterior, contate <@155774074885242880> e peça por uma migração manual."
        } else {
            "não é você. Utilize outro nick e tente novamente."
        };

        ctx.send(
            CreateReply::default()
                .embed(embed::error(
                    format!("O nick: \"{}\" já está sendo utilizado.", acct.username),
                    format!("O dono da conta {}", standing),
                ))
                .ephemeral(true),
        )
        .await?;
        return Ok(());
    }

    if let Ok(old_acct) = ctx.data.db.get_profile(old).await {
        if old_acct.discord_id != ctx.author().id.to_string() {
            ctx.send(
                CreateReply::default()
                    .embed(embed::error(
                        format!("O nick \"{}\" não é seu", old_acct.username),
                        "Utilize outro nick e tente novamente.",
                    ))
                    .ephemeral(true),
            )
            .await?;

            return Ok(());
        }

        let message = match ctx.data.db.update_username(&old_acct.uuid, new).await {
            Ok(_) => embed::info("O nome da conta foi alterado com sucesso.", "Use a mesma senha e logue nos servidores.\nSeu histórico de conexões, stats e itens serão transferidos na próxima vez que conectar no servidor."),
            Err(_) => embed::error("Um erro aconteceu na migração para o seu nick novo","Contate a staff para resolver o ocorrido."),
        };

        ctx.send(CreateReply::default().embed(message).ephemeral(true))
            .await?;
    }

    Ok(())
}
