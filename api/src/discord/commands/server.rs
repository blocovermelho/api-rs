use poise::{CreateReply, Modal};

use crate::{
    core::types::{
        consts::api_scopes::{PROFILE_READ, SERVER_READ, SERVER_SELF_MODIFY},
        structs::stub::GameServerStub,
    },
    db::interface::DataSource,
    discord::{
        render::{
            embed::{error, info, new_server, server_token},
            modal::NewServer,
        },
        AppContext, Error,
    },
};

/// Comandos de administração para servidores.
///
/// Esses comandos estão disponíveis para quaisquer membres que queiram
/// criar/editar/atualizar os seus respectivos servidores.
#[poise::command(slash_command, subcommands("token", "create"))]
pub async fn server(ctx: AppContext<'_>) -> Result<(), Error> {
    Ok(())
}

/// Cria um novo servidor. Nota: Após a criação não será possivel apagá-lo.
///
/// Crie um servidor apenas se tiver certeza.
#[poise::command(slash_command)]
pub async fn create(ctx: AppContext<'_>) -> Result<(), Error> {
    let db = &ctx.data.db;
    let profiles = db
        .get_profiles_by_discord_id(ctx.author().id.to_string())
        .await?;

    if profiles.is_empty() {
        ctx.send(CreateReply::default().embed(info("Perfil não reconhecido", "A sua conta do discord é nova por aqui. Seja bem-vinde! Este comando só pode ser utilizado por membros que possuem perfis."))).await?;
        return Ok(());
    }

    match NewServer::execute(ctx).await? {
        Some(server) => {
            let name = server.name.trim().to_string();
            let game = server.game.trim().to_string();
            let versions: Vec<_> = server
                .versions
                .trim()
                .split(",")
                .map(|it| it.trim().to_string())
                .collect();

            let max_players: i32 = server.max_players.trim().to_string().parse()?;

            let staff = profiles.iter().map(|it| it.uuid).collect();

            if (db.get_server_by_name(name.clone()).await).is_ok() {
                ctx.send(CreateReply::default().embed(error("Criação de servidor - Nome repetido", "O servidor que você estava tentando criar já existe. Tente novamente com um outro nome.")).ephemeral(true)).await?;
                return Ok(());
            }

            let server = db
                .create_server(GameServerStub { name, game, versions, max_players, staff })
                .await?;

            let token = db
                .create_token(&server.uuid, vec![
                    PROFILE_READ.to_string(),
                    SERVER_READ.to_string(),
                    SERVER_SELF_MODIFY.to_string(),
                ])
                .await?;

            ctx.send(
                CreateReply::default()
                    .embed(new_server(&server, &token))
                    .ephemeral(true),
            )
            .await?;

            Ok(())
        }
        None => Ok(()),
    }
}

/// Alterações relacionadas ao token da API do bloco vermelho para servidores.
///
/// O token é necessário para que um servidor se atualize, autentique um perfil
/// e atualize os perfis dos jogadores (acesso restrito).
#[poise::command(slash_command, subcommands("reset"))]
pub async fn token(ctx: AppContext<'_>) -> Result<(), Error> {
    Ok(())
}

/// Reseta o token de um servidor que você seja staff.
///
/// Esta é a *unica* forma de conseguir um novo token caso esqueça o antigo.
/// Rodar esse comando fará com que o servidor perca acesso a API o que a depender
/// da implementação requerirá um restart do servidor.
#[poise::command(slash_command)]
pub async fn reset(
    ctx: AppContext<'_>,
    #[autocomplete = "crate::discord::autocomplete::staff_servers"] server: String,
) -> Result<(), Error> {
    let db = &ctx.data.db;
    let server = db.get_server_by_name(server).await?;
    let profiles = db
        .get_profiles_by_discord_id(ctx.author().id.to_string())
        .await?;

    let intersection = profiles.iter().filter(|it| server.staff.contains(&it.uuid));

    if intersection.count() == 0 {
        ctx.send(
            CreateReply::default()
                .embed(error("Ação não permitida", "Você não é staffer deste servidor.")),
        )
        .await?;
        return Ok(());
    }

    let token = match db.reset_token(&server.uuid).await {
        Ok(t) => t,
        Err(_) => {
            db.create_token(&server.uuid, vec![
                PROFILE_READ.to_string(),
                SERVER_READ.to_string(),
                SERVER_SELF_MODIFY.to_string(),
            ])
            .await?
        }
    };

    ctx.send(
        CreateReply::default()
            .embed(server_token(&server, &token))
            .ephemeral(true),
    )
    .await?;

    Ok(())
}
