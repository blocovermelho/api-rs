use std::{fmt::Display, net::Ipv4Addr};

use chrono::{DateTime, Utc};
use poise::{
    serenity_prelude::{
        ButtonStyle, CreateActionRow, CreateButton, CreateEmbed, CreateEmbedAuthor,
        CreateEmbedFooter,
    },
    CreateReply,
};

use crate::{id::Id, AppContext, Error};

mod colors {
    type Rgb = (u8, u8, u8);
    pub const INFO: Rgb = (0, 121, 216);
    pub const INPUT: Rgb = (209, 230, 57);
    pub const ERROR: Rgb = (232, 26, 26);
    pub const NO_PERM: Rgb = (232, 94, 26);
}

pub const BV_GITHUB_ICON: &str = "https://avatars.githubusercontent.com/u/120765338?s=200&v=4";

fn base() -> CreateEmbed {
    CreateEmbed::new().footer(CreateEmbedFooter::new("Bloco Vermelho").icon_url(BV_GITHUB_ICON))
}

pub fn info(brief: impl Display, data: impl Display) -> CreateEmbed {
    base()
        .title(format!("ℹ️ {}", brief))
        .description(data.to_string())
        .color(colors::INFO)
}

pub fn error(brief: impl Display, data: impl Display) -> CreateEmbed {
    base()
        .title(format!("❌  {}", brief))
        .description(data.to_string())
        .color(colors::ERROR)
}

pub fn input(brief: impl Display, data: impl Display) -> CreateEmbed {
    base()
        .title(format!("✏️ {}", brief))
        .description(data.to_string())
        .color(colors::INPUT)
}

pub fn no_permissions(brief: impl Display, data: impl Display) -> CreateEmbed {
    base()
        .title(format!("📝 {}", brief))
        .description(data.to_string())
        .footer(CreateEmbedFooter::new("Este incidente será reportado."))
        .color(colors::NO_PERM)
}

pub fn user(
    username: impl Display, creation_date: DateTime<Utc>, discord_id: impl Display,
    last_server: Option<String>,
) -> CreateEmbed {
    info(
        format!("Estatísticas de {}", username),
        format!(
            "
        **Conta criada em**: <t:{}:f>
        **Discord**: <@{}>
        **Último Servidor**: {}
        ",
            creation_date.timestamp(),
            discord_id,
            last_server.unwrap_or_else(|| "Desconhecido".to_string())
        ),
    )
}

pub fn duration_format(duration: &chrono::Duration) -> String {
    let days = duration.num_days();
    let hours = duration.num_hours();
    let mins = duration.num_minutes() - (hours * 60);
    let secs = duration.num_seconds() - (duration.num_minutes() * 60);

    if days > 0 {
        format!("{:04}d{:02}h{:02}m ({:03}h)", days, (hours - days * 24), mins, hours)
    } else if hours > 0 {
        format!("{:02}h{:02}m{:02}s", hours, mins, secs)
    } else {
        format!(
            "{:02}m:{:02}s.{:03}",
            mins,
            secs,
            duration.num_milliseconds() - (duration.num_seconds() * 1000)
        )
    }
}

pub fn server_field(
    embed: &CreateEmbed, playtime: std::time::Duration, name: impl Display, rank: usize,
) -> CreateEmbed {
    let duration = chrono::Duration::from_std(playtime).unwrap();
    let duration_str = duration_format(&duration);

    embed.clone().field(
        format!("Servidor: {}", name),
        format!("**Tempo de Jogo**: {} `#{}`", duration_str, rank),
        false,
    )
}

pub fn new_ip(
    username: impl Display, server_name: impl Display, ip: &Ipv4Addr, when: DateTime<Utc>,
) -> CreateEmbed {
    base()
        .author(CreateEmbedAuthor::new("Bloco Vermelho - Autenticação").icon_url(BV_GITHUB_ICON))
        .title(format!("Alerta de segurança critico para {}", username))
        .description(format!(
        "Uma tentativa de conexão com o servidor \"{}\" foi realizada em <t:{}:f> com um IP que não foi reconhecido pelo servidor.
        
        Clique no botão \"Permitir Acesso\" se for você que estiver entrando no servidor.
        
        Clique no botão \"Recusar Acesso\" para adicionar esse IP ao sistema de infrações e **barrar a entrada desse IP permanentemente**.
        ", server_name, when.timestamp()))
        .field("Servidor", server_name.to_string(), true)
        .field("IP", ip.to_string(), true)
        .color(colors::ERROR)
}

pub fn new_ip_buttons(addr: &Ipv4Addr, target: Option<String>) -> Vec<CreateButton> {
    vec![
        CreateButton::new(
            Id::encode(&Id {
                action: crate::id::Action::AcceptIp,
                nonce: addr.to_bits().to_string(),
                target: target.clone(),
            })
            .unwrap(),
        )
        .label("Permitir Acesso")
        .style(ButtonStyle::Success),
        CreateButton::new(
            Id::encode(&Id {
                action: crate::id::Action::PromptBanIp,
                nonce: addr.to_bits().to_string(),
                target,
            })
            .unwrap(),
        )
        .label("Recusar Acesso")
        .style(ButtonStyle::Danger),
        CreateButton::new_link("https://whatismyipaddress.com/").label("Seu IP Atual"),
    ]
}

async fn send_embed(ctx: AppContext<'_>, embed: CreateEmbed) -> Result<(), Error> {
    ctx.send(CreateReply::default().embed(embed)).await?;
    Ok(())
}

#[poise::command(slash_command)]
pub async fn embed_test(
    ctx: AppContext<'_>,
    #[choices("info", "err", "no_permissions", "new_ip", "new_ip_btns")] name: &'static str,
) -> Result<(), Error> {
    match name {
        "info" => send_embed(ctx, info("Info Embed", "Test Data")).await?,
        "err" => send_embed(ctx, error("Error Embed", "Test Data")).await?,
        "no_permissions" => {
            send_embed(ctx, no_permissions("No Permissions Embed", "Test Data")).await?
        }
        "new_ip" => {
            send_embed(
                ctx,
                new_ip("alikindsys", "Embed Test Server", &Ipv4Addr::new(0, 0, 0, 0), Utc::now()),
            )
            .await?
        }
        "new_ip_btns" => {
            let ip = Ipv4Addr::new(169, 254, 69, 69);
            let reply = CreateReply::default()
                .embed(new_ip("alikindsys", "Embed Test Server", &ip, Utc::now()))
                .components(vec![CreateActionRow::Buttons(new_ip_buttons(&ip, None))]);

            ctx.send(reply).await?;
        }
        _ => send_embed(ctx, error("Invalid Embed Type", name)).await?,
    }

    Ok(())
}
