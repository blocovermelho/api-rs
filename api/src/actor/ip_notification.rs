use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use serenity::all::{
    CreateActionRow, CreateButton, CreateEmbed, CreateEmbedAuthor, CreateEmbedFooter, EditMessage,
};

use super::{
    livemessage::LiveMessageActorHandle, new_connection::NewConnectionCommand, prelude::*,
};
use crate::{
    core::types::enums::Heuristic,
    db::data::BanIssuer,
    discord::render::embed::{self, colors, BV_GITHUB_ICON},
};

/*
 * New Ip Notification Actor
 */
struct IpNotifA {
    ip: Ipv4Addr,
    username: String,
    server: String,
    when: DateTime<Utc>,
    count: usize,
    istate: InteractionState,
    database_hnd: DatabaseActorHandle,
    message_hnd: LiveMessageActorHandle,
    parent_hnd: WeakUnboundedSender<NewConnectionCommand>,
}

impl IpNotifA {
    fn increase(&mut self) {
        debug!(
            "[a:IpNotification({},{})] Event:Increase RECV | count={}",
            self.ip, self.username, self.count
        );
        self.count += 1;
        self.message_hnd.edit_instantly(self.as_edit());
        debug!(
            "[a:IpNotification({},{})] Event:Increase HANDLE | count={}",
            self.ip, self.username, self.count
        );
    }

    async fn handle_allow(&mut self) {
        debug!(
            "[a:IpNotification({},{})] Event:HandleAllow RECV | istate={:?}",
            self.ip, self.username, self.istate
        );
        match self.istate {
            InteractionState::PendingBlock => self.istate = InteractionState::Neutral,
            InteractionState::PendingAllow => self.istate = InteractionState::Allow,
            InteractionState::Neutral => self.istate = InteractionState::PendingAllow,
            // The rest do nothing cause they are already "Finished states"
            // and the actor would have died by then.
            _ => {}
        }

        self.message_hnd.edit_instantly(self.as_edit());

        if matches!(self.istate, InteractionState::Allow) {
            if let Some(profile) = self.database_hnd.get_profile(self.username.clone()).await {
                self.database_hnd
                    .create_allowlist(profile.id, self.ip)
                    .await;
            }

            info!(
                "[a:IpNotification({},{})] Event:HandleAllow | Created Allowlist",
                self.ip, self.username
            );
        }
        debug!(
            "[a:IpNotification({},{})] Event:HandleAllow RECV | istate={:?}",
            self.ip, self.username, self.istate
        );
    }

    async fn handle_disallow(&mut self) {
        debug!(
            "[a:IpNotification({},{})] Event:HandleDisallow RECV | istate={:?}",
            self.ip, self.username, self.istate
        );
        match self.istate {
            InteractionState::PendingBlock => self.istate = InteractionState::Block,
            InteractionState::PendingAllow => self.istate = InteractionState::Neutral,
            InteractionState::Neutral => self.istate = InteractionState::PendingBlock,
            // The rest do nothing cause they are already "Finished states"
            // and the actor would have died by then.
            _ => {}
        }

        self.message_hnd.edit_instantly(self.as_edit());

        if matches!(self.istate, InteractionState::Block) {
            self.database_hnd
                .create_blacklist(
                    self.ip,
                    BanIssuer::AutomatedSystem(format!(
                        "[Discord] Manually blocked for profile={}",
                        self.username
                    )),
                )
                .await;

            warn!(
                "[a:IpNotification({},{})] Event:HandleDisallow | Created Blacklist",
                self.ip, self.username
            );
        }
        debug!(
            "[a:IpNotification({},{})] Event:HandleDisallow HANDLE | istate={:?}",
            self.ip, self.username, self.istate
        );
    }

    async fn heuristic_solve(&self, heuristic: Heuristic) {
        debug!(
            "[a:IpNotification({},{})] Event:HeuristicSolve RECV | istate={:?}",
            self.ip, self.username, self.istate
        );

        let edit = EditMessage::new()
            .embed(self.heuristics_embed(heuristic))
            .components(vec![]);

        self.message_hnd.edit_instantly(edit);
    }

    fn as_edit(&self) -> EditMessage {
        let (embed, btns) = match self.istate {
            InteractionState::Allow => (self.get_alowed_embed(), vec![]),
            InteractionState::Block => (self.get_blocked_embed(), vec![]),
            _ => (self.get_start_embed(), self.get_buttons()),
        };

        let mut edit = EditMessage::new().embed(embed);

        if !btns.is_empty() {
            edit = edit.components(vec![CreateActionRow::Buttons(btns)]);
        } else {
            edit = edit.components(vec![]);
        }

        edit
    }

    fn get_alowed_embed(&self) -> CreateEmbed {
        embed::info(
            "IP adicionado.",
            format!("O IP {} foi adicionado ao perfil: `{}` com sucesso.", self.ip, self.username),
        )
        .color(colors::SERVER_ONLINE)
    }

    fn get_blocked_embed(&self) -> CreateEmbed {
        embed::info(
            "IP bloqueado.",
            format!(
                "O IP {} foi bloqueado **permanentemente**.
                    Caso considere isto um engano, entre em contato com a Staff.

                    Obrigade por deixar o Bloco Vermelho mais seguro.",
                self.ip
            ),
        )
        .color(colors::ERROR)
    }

    fn get_start_embed(&self) -> CreateEmbed {
        embed::base()
            .author(CreateEmbedAuthor::new("Bloco Vermelho - Autenticação").icon_url(BV_GITHUB_ICON))
            .title(format!("Alerta de segurança critico para {}", self.username))
            .description(format!(
            "Uma tentativa de conexão com o servidor \"{}\" foi realizada em <t:{}:f> com um IP que não foi reconhecido pelo servidor.

            Clique no botão \"Permitir\" se for você que estiver entrando no servidor.

            Clique no botão \"Bloquear\" para adicionar esse IP ao sistema de infrações e **barrar a entrada desse IP permanentemente**.
            ", self.server, self.when.timestamp()))
            .field("Servidor", self.server.clone(), true)
            .field("IP", self.ip.to_string(), true)
            .field("Tentativa(s)", self.count.to_string(), true)
            .color(colors::ERROR)
    }

    fn get_buttons(&self) -> Vec<CreateButton> {
        let mut allow_btn = CreateButton::new(format!("ip_allow:{}", self.ip))
            .style(serenity::all::ButtonStyle::Success);
        let mut deny_btn = CreateButton::new(format!("ip_deny:{}", self.ip))
            .style(serenity::all::ButtonStyle::Danger);
        // [Confirm? Allow] [Confirm? Disallow] [Link to MyIp]
        match self.istate {
            InteractionState::PendingBlock => {
                deny_btn = deny_btn.label("Confirmar Bloqueio").emoji('❎');
                allow_btn = allow_btn
                    .label("Cancelar Bloqueio")
                    .emoji('⏪')
                    .style(serenity::all::ButtonStyle::Secondary);
            }
            InteractionState::PendingAllow => {
                deny_btn = deny_btn
                    .label("Cancelar Permitir")
                    .emoji('⏪')
                    .style(serenity::all::ButtonStyle::Secondary);
                allow_btn = allow_btn.label("Confirmar Permitir").emoji('✅');
            }
            _ => {
                deny_btn = deny_btn.label("Bloquear").emoji('❎');
                allow_btn = allow_btn.label("Permitir").emoji('✅');
            }
        }
        vec![
            allow_btn,
            deny_btn,
            CreateButton::new_link("https://www.whatismyip.com").label("Meu Ip"),
        ]
    }

    fn heuristics_embed(&self, heuristic: Heuristic) -> CreateEmbed {
        let mut embed = embed::base()
            .color(colors::INFO)
            .author(
                CreateEmbedAuthor::new("Bloco Vermelho - Autenticação - Nenhuma ação necessária")
                    .icon_url(BV_GITHUB_ICON),
            )
            .description(
                "Uma tentativa de conexão com a sua conta foi bloqueada automaticamente.
                Caso considere isto um erro entre em contato com a staff e reverteremos isto.",
            )
            .field("IP", self.ip.to_string(), true)
            .field("Servidor", self.server.clone(), true);

        match heuristic {
            Heuristic::SpammedAttempt { count, usernames } => {
                embed = embed.field(
                    "Motivo",
                    "[SPAM] Conexão em várias contas distintas vindas de um IP não reconhecido.",
                    true,
                ).field("Tentativa(s)", count.to_string(), true)
                .field("Perfil(is) afetado(s)", usernames.join(", "), true)
                .footer(CreateEmbedFooter::new("Nota: Isso normalmente ocorre com \"scanners\" e raramente é um alarme falso."));
            }
            Heuristic::LoggedKickAttempt { .. } => {
                embed = embed.field("Motivo",
                    "[KICK] Conexão de um IP não reconhecido no seu perfil enquanto jogava no servidor.", true)
                .footer(CreateEmbedFooter::new("Nota: Isso normalmente ocorre com mods/hacks que permitem logar com o nick de alguem que está online (O que normalmente causaria o erro \"You logged in from a different location\" e te kickaria do servidor). Raramente pode ser falso-positivo."));
            }
        }

        embed
    }
}
#[derive(Debug)]
enum InteractionState {
    PendingBlock,
    PendingAllow,
    Neutral,
    Allow,
    Block,
}

pub enum IpNotifCommand {
    Increase,
    HandleAllow,
    HandleDisallow,
    HeuristicSolve(Heuristic),
}

pub struct IpNotifActor {
    state: IpNotifA,
    queue: mpsc::UnboundedReceiver<IpNotifCommand>,
}

impl IpNotifActor {
    pub fn spawn(
        ip: Ipv4Addr, username: String, server: String, database_hnd: DatabaseActorHandle,
        message_hnd: LiveMessageActorHandle, parent_hnd: WeakUnboundedSender<NewConnectionCommand>,
    ) -> IpNotifActorHandle {
        let (tx, rx) = mpsc::unbounded_channel();

        let actor = Self {
            state: IpNotifA {
                ip,
                username,
                server,
                when: Utc::now(),
                count: 0,
                istate: InteractionState::Neutral,
                database_hnd,
                message_hnd,
                parent_hnd,
            },
            queue: rx,
        };

        tokio::spawn(async move { actor.run().await });

        IpNotifActorHandle { queue: tx }
    }

    async fn run(mut self) {
        while let Some(cmd) = self.queue.recv().await {
            match cmd {
                IpNotifCommand::Increase => {
                    self.state.increase();
                }
                IpNotifCommand::HandleAllow => {
                    self.state.handle_allow().await;

                    if matches!(self.state.istate, InteractionState::Allow) {
                        break;
                    }
                }
                IpNotifCommand::HandleDisallow => {
                    self.state.handle_disallow().await;

                    if matches!(self.state.istate, InteractionState::Block) {
                        break;
                    }
                }
                IpNotifCommand::HeuristicSolve(h) => {
                    self.state.heuristic_solve(h).await;
                    return;
                }
            }
        }

        if let Some(hnd) = self.state.parent_hnd.upgrade() {
            let _ = hnd.send(NewConnectionCommand::CleanupHandle(self.state.username));
        }
    }
}

#[derive(Clone)]
pub struct IpNotifActorHandle {
    queue: mpsc::UnboundedSender<IpNotifCommand>,
}

impl IpNotifActorHandle {
    pub fn increase(&self) {
        notify_actor!(self.queue, IpNotifCommand::Increase);
    }

    pub fn handle_allow(&self) {
        notify_actor!(self.queue, IpNotifCommand::HandleAllow);
    }

    pub fn handle_disallow(&self) {
        notify_actor!(self.queue, IpNotifCommand::HandleDisallow);
    }

    pub fn heuristic_solve(&self, heuristic: Heuristic) {
        notify_actor!(self.queue, IpNotifCommand::HeuristicSolve(heuristic));
    }
}
