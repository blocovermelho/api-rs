use bimap::BiHashMap;
use serenity::all::UserId;
use uuid::Uuid;

use super::prelude::*;
use crate::core::utils::generation::ptbr_wordlist;

/*
 * One-Time-Passphrase Actor
 */

struct SingleUseTokenA {
    /* OTP for Logging in to profiles */
    profile: BiHashMap<Uuid, String>,
    /* Discord-initiated linking attempt */
    discord: BiHashMap<UserId, String>,
    /* Oauth-based discord linking attempt */
    csrf: BiHashMap<String, String>,
}

impl SingleUseTokenA {
    fn request_profile(&mut self, profile_id: Uuid) -> String {
        let otp = ptbr_wordlist().generate();
        self.profile.insert(profile_id, otp.clone());
        otp
    }

    fn query_profile(&self, otp: &String) -> Option<Uuid> {
        self.profile.get_by_right(otp).copied()
    }

    fn request_discord(&mut self, user_id: UserId) -> String {
        let otp = ptbr_wordlist().generate();
        self.discord.insert(user_id, otp.clone());
        otp
    }

    fn query_discord(&self, otp: &String) -> Option<UserId> {
        self.discord.get_by_right(otp).copied()
    }

    fn submit_csrf(&mut self, username: String, csrf_token: String) {
        self.csrf.insert(username, csrf_token);
    }

    fn query_username(&self, csrf: &String) -> Option<String> {
        self.csrf.get_by_right(csrf).cloned()
    }

    fn clear(&mut self, otp: &String) {
        self.profile.remove_by_right(otp);
        self.discord.remove_by_right(otp);
        self.csrf.remove_by_right(otp);
    }
}

pub enum SingleUseTokenCommand {
    RequestProfile(Uuid, RespCell<String>),
    QueryProfile(String, RespCell<Option<Uuid>>),
    RequestDiscord(UserId, RespCell<String>),
    QueryDiscord(String, RespCell<Option<UserId>>),
    SubmitCsrf(String, String),
    QueryUsername(String, RespCell<Option<String>>),
    /* Removes a given OTP from any map */
    Clear(String),
}

pub struct SingleUseTokenActor {
    state: SingleUseTokenA,
    queue: mpsc::UnboundedReceiver<SingleUseTokenCommand>,
}

impl SingleUseTokenActor {
    pub fn spawn() -> SingleUseTokenActorHandle {
        let (tx, rx) = mpsc::unbounded_channel();
        let actor = Self {
            state: SingleUseTokenA {
                profile: BiHashMap::new(),
                discord: BiHashMap::new(),
                csrf: BiHashMap::new(),
            },
            queue: rx,
        };

        tokio::spawn(async move { actor.run().await });

        SingleUseTokenActorHandle { queue: tx }
    }

    pub async fn run(mut self) {
        while let Some(cmd) = self.queue.recv().await {
            match cmd {
                SingleUseTokenCommand::RequestProfile(id, res) => {
                    let k = self.state.request_profile(id);
                    res.send(k).unwrap_or(())
                }
                SingleUseTokenCommand::QueryProfile(otp, res) => {
                    let k = self.state.query_profile(&otp);
                    res.send(k).unwrap_or(())
                }
                SingleUseTokenCommand::RequestDiscord(id, res) => {
                    let k = self.state.request_discord(id);
                    res.send(k).unwrap_or(())
                }
                SingleUseTokenCommand::QueryDiscord(otp, res) => {
                    let k = self.state.query_discord(&otp);
                    res.send(k).unwrap_or(())
                }
                SingleUseTokenCommand::SubmitCsrf(uname, csrf) => {
                    self.state.submit_csrf(uname, csrf);
                }
                SingleUseTokenCommand::QueryUsername(otp, res) => {
                    let k = self.state.query_username(&otp);
                    res.send(k).unwrap_or(())
                }
                SingleUseTokenCommand::Clear(otp) => self.state.clear(&otp),
            }
        }
    }
}

#[derive(Clone)]
pub struct SingleUseTokenActorHandle {
    queue: mpsc::UnboundedSender<SingleUseTokenCommand>,
}

impl SingleUseTokenActorHandle {
    pub async fn request_profile(&self, profile_id: Uuid) -> String {
        ask_actor!(self.queue, SingleUseTokenCommand::RequestProfile(profile_id));
    }

    pub async fn query_profile(&self, otp: String) -> Option<Uuid> {
        ask_actor!(self.queue, SingleUseTokenCommand::QueryProfile(otp));
    }

    pub async fn request_discord(&self, user_id: UserId) -> String {
        ask_actor!(self.queue, SingleUseTokenCommand::RequestDiscord(user_id));
    }

    pub async fn query_discord(&self, otp: String) -> Option<UserId> {
        ask_actor!(self.queue, SingleUseTokenCommand::QueryDiscord(otp));
    }

    pub fn submit_csrf(&self, username: String, csrf: String) {
        notify_actor!(self.queue, SingleUseTokenCommand::SubmitCsrf(username, csrf));
    }

    pub async fn query_username(&self, csrf: String) -> Option<String> {
        ask_actor!(self.queue, SingleUseTokenCommand::QueryUsername(csrf));
    }

    pub fn clear(&self, otp: String) {
        notify_actor!(self.queue, SingleUseTokenCommand::Clear(otp));
    }
}
