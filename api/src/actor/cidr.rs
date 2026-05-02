use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
};

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use super::prelude::*;
use crate::{
    actor::mailbox::MailboxActorHandle,
    core::{types::enums::Heuristic, utils::cidr},
    db::{
        data::{Allowlist, BanIssuer, Blacklist},
        interface::NetworkProvider,
    },
};

/*
 * CIDR Checking Actor
 * Also does heuristics checking for bad IPs
 */

struct Attempt {
    timestamp: DateTime<Utc>,
    username: String,
}

pub enum CidrResolution {
    AllowedIp(Allowlist),
    UnknownIp,
    BannedIp(Blacklist),
    BlockedWithHeuristic(Heuristic),
}

pub struct CidrA {
    recent_attempts: HashMap<Ipv4Addr, Vec<Attempt>>,
    bad_names: Vec<String>,
    database_hnd: DatabaseActorHandle,
    mailbox_hnd: WeakMailboxSender,
}

impl CidrA {
    pub async fn check(
        &mut self, ip: Ipv4Addr, username: String, server: Uuid, is_active: bool,
    ) -> CidrResolution {
        // Check blacklist
        debug!(
            "[a:Cidr] Event:Check RECV | ip={}, username={}, server={}, is_active={}",
            ip, username, server, is_active
        );
        let blacklists = self.database_hnd.get_blacklists(ip).await;

        for bl in &blacklists {
            if let cidr::PrefixLenMatch::Grows { current, .. } =
                cidr::match_prefix(&bl.get_network(), &ip)
            {
                self.database_hnd.broaden_blacklist(bl.clone(), current);
            }

            self.database_hnd.bump_blacklist(bl.clone());
        }

        if let Some(blacklist) = blacklists.into_iter().max_by_key(|it| it.hits) {
            trace!(
                "[a:Cidr] Event:Check HANDLE | ip={}, username={}, server={} | Found Blacklist.",
                ip,
                username,
                server
            );
            return CidrResolution::BannedIp(blacklist);
        }

        trace!(
            "[a:Cidr] Event:Check HANDLE | ip={}, username={}, server={} | Searched Blacklists.",
            ip,
            username,
            server
        );
        // Check whitelists
        let profile = self.database_hnd.get_profile(username.clone()).await;

        if let Some(profile) = profile {
            let whitelists = self.database_hnd.get_allowlists(profile.id, ip).await;

            for wl in &whitelists {
                if let cidr::PrefixLenMatch::Grows { current, .. } =
                    cidr::match_prefix(&wl.get_network(), &ip)
                {
                    self.database_hnd.broaden_allowlist(wl.clone(), current);
                }

                self.database_hnd.bump_allowlist(wl.clone());
            }

            if let Some(wl) = whitelists.into_iter().max_by_key(|it| it.hits) {
                trace!(
                    "[a:Cidr] Event:Check HANDLE | ip={}, username={}, server={} | Found Allowlist.",
                    ip, username, server
                );
                return CidrResolution::AllowedIp(wl);
            }
        }

        trace!(
            "[a:Cidr] Event:Check HANDLE | ip={}, username={}, server={} | Searched Allowlists.",
            ip,
            username,
            server
        );
        // At this point the ip is neither known nor banned. It is a new IP connection.
        // We always add new connection attempts
        let entry = self.recent_attempts.entry(ip).or_default();
        entry.push(Attempt { timestamp: Utc::now(), username: username.clone() });

        if let Some(heuristic) = self.heuristic_check(ip, username.clone(), server, is_active) {
            let message = match &heuristic {
                Heuristic::SpammedAttempt { count, usernames } => format!(
                    "[Cidr:SpammedAttempt] Blocked after {} attempts affecting {} users.",
                    count,
                    usernames.len()
                ),
                Heuristic::LoggedKickAttempt { username, server } => format!(
                    "[Cidr:LoggedKickAttempt] Blocked after trying to kick {} at {}",
                    username.clone(),
                    server
                ),
                Heuristic::BadName => "[Cidr::BadName] Blocked username used for login".to_string(),
            };

            self.database_hnd
                .create_blacklist(ip, BanIssuer::AutomatedSystem(message))
                .await;

            if let Some(hnd) = self.mailbox_hnd.upgrade() {
                let _ = hnd.send(MailboxCommand::NotifyHeurisiticSolve(ip, heuristic.clone()));
            }

            trace!(
                "[a:Cidr] Event:Check HANDLE | ip={}, username={}, server={} | Blocked by heuristic.",
                ip, username, server
            );
            return CidrResolution::BlockedWithHeuristic(heuristic);
        }

        if let Some(hnd) = self.mailbox_hnd.upgrade() {
            let _ = hnd.send(MailboxCommand::NotifyUnknownIp {
                ip,
                username: username.clone(),
                server,
            });
        }

        trace!(
            "[a:Cidr] Event:Check HANDLE | ip={}, username={}, server={} | New Ip.",
            ip,
            username,
            server
        );

        CidrResolution::UnknownIp
    }

    fn heuristic_check(
        &mut self, ip: Ipv4Addr, username: String, server: Uuid, is_active: bool,
    ) -> Option<Heuristic> {
        trace!(
            "[HeuristicCheck]  ip={}, username={}, server={}, is_active={} RECV ",
            ip,
            username,
            server,
            is_active
        );
        let now = Utc::now();
        let attempts = self.recent_attempts.entry(ip).or_default();
        attempts.retain(|a| (now - a.timestamp) < Duration::minutes(5));

        let distinct_usernames: HashSet<_> = attempts.iter().map(|a| a.username.clone()).collect();

        if attempts.len() >= 5 && distinct_usernames.len() > 2 {
            trace!(
                "[HeuristicCheck]  ip={}, username={}, server={}, is_active={} | Resolved: SpammedAttempt",
                ip,
                username,
                server,
                is_active
            );
            return Some(Heuristic::SpammedAttempt {
                count: attempts.len(),
                usernames: distinct_usernames.into_iter().collect(),
            });
        }

        if is_active {
            trace!(
                "[HeuristicCheck]  ip={}, username={}, server={}, is_active={} | Resolved: LoggedKickAttempt",
                ip,
                username,
                server,
                is_active
            );
            return Some(Heuristic::LoggedKickAttempt { username, server });
        }

        if self.bad_names.contains(&username) {
            trace!(
                "[HeuristicCheck]  ip={}, username={}, server={}, is_active={} | Resolved: BadName",
                ip,
                username,
                server,
                is_active
            );

            return Some(Heuristic::BadName);
        }

        trace!(
            "[HeuristicCheck]  ip={}, username={}, server={} | Resolved: None",
            ip,
            username,
            server
        );

        None
    }
}

pub struct CidrActor {
    state: CidrA,
    queue: mpsc::UnboundedReceiver<CidrCommand>,
}

impl CidrActor {
    pub fn spawn(
        database: DatabaseActorHandle, mailbox: WeakMailboxSender, bad_names: Vec<String>,
    ) -> CidrActorHandle {
        let (tx, rx) = mpsc::unbounded_channel();
        let actor = Self {
            state: CidrA {
                recent_attempts: HashMap::new(),
                database_hnd: database,
                mailbox_hnd: mailbox,
                bad_names,
            },
            queue: rx,
        };

        tokio::spawn(async move { actor.run().await });

        CidrActorHandle { queue: tx }
    }

    async fn run(mut self) {
        while let Some(cmd) = self.queue.recv().await {
            match cmd {
                CidrCommand::Check { ip, username, server, is_active, tx } => {
                    let k = self.state.check(ip, username, server, is_active).await;
                    tx.send(k).unwrap_or(());
                }
            }
        }
    }
}

pub struct CidrActorHandle {
    queue: mpsc::UnboundedSender<CidrCommand>,
}

impl CidrActorHandle {
    pub async fn check(
        &self, ip: Ipv4Addr, username: String, server: Uuid, is_active: bool,
    ) -> CidrResolution {
        ask_actor!(self.queue, CidrCommand::Check { ip, username, server, is_active });
    }

    pub fn mock() -> (Self, mpsc::UnboundedReceiver<CidrCommand>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { queue: tx }, rx)
    }
}

pub enum CidrCommand {
    Check {
        ip: Ipv4Addr,
        username: String,
        server: Uuid,
        is_active: bool,
        tx: RespCell<CidrResolution>,
    },
}

// Test Coverage for the CIDR actor.

#[test]
fn heuristic_check() {
    let (db_hnd, db_rx) = DatabaseActorHandle::mock();
    let (mbox_hnd, mbox_rx) = MailboxActorHandle::mock();
    let localhost = Ipv4Addr::new(127, 0, 0, 1);
    let mut state = CidrA {
        recent_attempts: HashMap::new(),
        database_hnd: db_hnd,
        bad_names: vec!["fail2ban".to_string()],
        mailbox_hnd: mbox_hnd.as_weak(),
    };

    // Login while the player is active
    let logged_kick = state.heuristic_check(localhost, "alikindsys".into(), Uuid::new_v4(), true);
    assert!(matches!(logged_kick, Some(Heuristic::LoggedKickAttempt { .. })));
    state.recent_attempts.clear();
    // Multiple logins on different players.
    // Distinct Usernames > 2, Attempts >= 5.
    state.recent_attempts.insert(localhost, vec![
        Attempt {
            timestamp: Utc::now(),
            username: "alikindsys".into(),
        },
        Attempt { timestamp: Utc::now(), username: "roridev".into() },
        Attempt {
            timestamp: Utc::now(),
            username: "ONickRamos".into(),
        },
        Attempt {
            timestamp: Utc::now(),
            username: "SofiAzeda".into(),
        },
        Attempt {
            timestamp: Utc::now(),
            username: "SofiAzeda".into(),
        },
    ]);
    // Spammed Attempt
    let spammed = state.heuristic_check(localhost, "alikindsys".into(), Uuid::new_v4(), false);
    assert!(matches!(spammed, Some(Heuristic::SpammedAttempt { .. })));
    state.recent_attempts.clear();

    let good_path = state.heuristic_check(localhost, "alikindsys".into(), Uuid::new_v4(), false);
    assert!(good_path.is_none());
}
