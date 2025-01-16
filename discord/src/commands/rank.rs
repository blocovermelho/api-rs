use db::{data::result::PlaytimeEntry, interface::DataSource};
use poise::{serenity_prelude::CreateEmbedFooter, CreateReply};

use crate::{
    render::embed::{self, duration_format},
    Context, Error,
};

/// Mostra um ranking de tempo de jogo por servidor
#[poise::command(slash_command)]
pub async fn rank(
    ctx: Context<'_>,
    #[description = "O nome do servidor"]
    #[autocomplete = "crate::autocomplete::servers"]
    server: String,
    #[description = "Pagina do ranking"]
    #[min = 1]
    #[max = 10]
    page: Option<usize>,
) -> Result<(), Error> {
    let db = &ctx.data().db;
    let server_ = db.get_server_by_name(server.clone()).await;
    let page = page.unwrap_or(1);
    let start = (page - 1) * 10;
    let mut end = (page * 10) - 1;

    let embed = match server_ {
        Ok(s) => {
            let mut playtimes = db.get_playtimes(&s.uuid).await.unwrap();
            playtimes.sort_by(|a, b| b.playtime.0.cmp(&a.playtime.0));

            let mut strs = vec![];
            for (idx, entry) in playtimes.iter().enumerate() {
                strs.push(format_entry(entry, idx));
            }

            if end > strs.len() {
                end = strs.len() - 1;
            }

            if let Some(strs) = strs.get(start..=end) {
                embed::info(format!("Ranking: {}", s.name), strs.join("\n")).footer(
                    CreateEmbedFooter::new(format!(
                        "Página {}/10 - #{:02} à #{:02}",
                        page,
                        start + 1,
                        end + 1
                    )),
                )
            } else {
                embed::error("Página Inexistente",
			     format!("A Página {} precisaria de {} ou mais membres, o que é mais {} do que a quantidade atual ({}).",
				     page, start, start - strs.len(), strs.len()))
            }
        }
        Err(_) => {
            embed::error("Servidor não encontrado", format!("O servidor: {} não existe.", server))
        }
    };

    let reply = CreateReply::default().embed(embed);
    let _ = ctx.send(reply).await;

    Ok(())
}

fn format_entry(entry: &PlaytimeEntry, position: usize) -> String {
    let duration = chrono::Duration::from_std(entry.playtime.0).unwrap();
    format!(
        "`#{:02}` - **{}** | {}",
        position + 1,
        entry.username,
        duration_format(&duration)
    )
}
