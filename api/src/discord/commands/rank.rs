use std::{collections::BTreeMap, time::Duration};

use poise::{serenity_prelude::CreateEmbedFooter, CreateReply};
use tracing::{event, span, Level};

use crate::{
    core::{
        trans::db::TryIngest,
        types::{enums::ConnectionData, structs::Connection},
    },
    db::interface::DataSource,
    discord::{
        render::embed::{self, duration_format},
        Context, Error,
    },
};

/// Mostra um ranking de tempo de jogo por servidor
#[poise::command(slash_command)]
pub async fn rank(
    ctx: Context<'_>,
    #[description = "O nome do servidor"]
    #[autocomplete = "crate::discord::autocomplete::servers"]
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
            let mut total_time = Duration::ZERO;
            let db_playtimes = db.get_connections_by_kind("bv:playtime").await.unwrap();
            let mut ranking: BTreeMap<Duration, Vec<String>> = BTreeMap::new();
            for dbd in db_playtimes {
                if let Ok(c) = Connection::try_ingest(dbd, db.clone()).await {
                    if let ConnectionData::Playtime(times) = c.extra {
                        if let Some(time) = times.get(&s.uuid) {
                            total_time += *time;
                            if let Some(old) = ranking.get(time) {
                                let mut tie = old.clone();
                                tie.push(c.profile.username);
                                ranking.insert(*time, tie);
                            } else {
                                ranking.insert(*time, vec![c.profile.username]);
                            }
                        }
                    }
                }
            }

            let mut strs = vec![];

            for (idx, (k, v)) in ranking.iter().rev().enumerate() {
                strs.push(format_entry(k, v, idx));
            }

            if end > strs.len() {
                end = strs.len() - 1;
            }

            if let Some(strs) = strs.get(start..=end) {
                embed::info(format!("Ranking: {}", s.name), strs.concat().join("\n")).footer(
                    CreateEmbedFooter::new(format!(
                        "Página {}/10 - #{:02} à #{:02} | Tempo total: {}",
                        page,
                        start + 1,
                        end + 1,
                        duration_format(&chrono::Duration::from_std(total_time).unwrap())
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

fn format_entry(duration: &Duration, players: &Vec<String>, position: usize) -> Vec<String> {
    let duration = chrono::Duration::from_std(*duration).unwrap();
    let mut strs = vec![];

    for player in players {
        strs.push(format!(
            "`#{:02}` - **{}** | {}",
            position + 1,
            player,
            duration_format(&duration)
        ));
    }
    strs
}
