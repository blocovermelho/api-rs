use std::{collections::HashMap, net::Ipv4Addr, time::Duration};

use chrono::{DateTime, Utc};
use ipnet::Ipv4Net;
use serde::Serialize;
use uuid::Uuid;

use super::structs::*;

#[derive(Debug, Clone)]
pub enum PlayerState {
    Visitor,  /* Previously known as "unregistered" */
    PreLogin, /* Has a profile but is pending log-in */
    LoggedIn,
    ResumedSession,
    Banned,
}

pub enum Rejection {
    BadCIDRBlock {
        heuristics: Vec<Heuristic>,
    },
    Banned {
        reason: String,
    },
    InvalidPassword {
        count: usize,
        limit: usize,
    },
    UnknownIP,
    AuthorizationProvider {
        kind: String,
        action: AuthorizationRespose,
    },
}
#[derive(Clone, Debug)]
pub enum Heuristic {
    /// When a bad actor tries to either:
    /// - Connect to the same logged in profile multiple times in a short period of time
    /// - Connect to different previously logged profiles in a short period of time
    ///
    /// Since either of these options are quite intentional, no warnings will be given and said IP will be banned immediately.
    /// Confirmation messages that would've been sent to the affected users should be edited to say that no action is needed and that attempt got blocked.
    SpammedAttempt {
        count: usize,
        usernames: Vec<String>,
    },
    /// When a probable bad actor tries to connect to an profile which was already logged in
    /// Since this can happen by accident, IPs will not be immediately banned unless multiple attempts are done
    LoggedKickAttempt {
        username: String,
        server: uuid::Uuid,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConnectionData {
    BedrockUsername { name: String, xuid: Option<u64> },
    MojangUuid { name: String, id: uuid::Uuid },
    Playtime(HashMap<uuid::Uuid, Duration>),
}

pub enum AuthorizationProvider {
    UserOnGuild {
        guild_id: String,
        action: AuthorizationRespose,
    },
    Whitelist {
        profiles: Vec<Uuid>,
    },
}

pub enum AuthorizationRespose {
    BAN,
    KICK,
    WARN,
    ALLOW,
}

pub enum UserNotification {
    NoDMPermissionPreamble,
    NewIPConnection {
        profile: Profile,
        block: Ipv4Net,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
        attempts: usize,
        state: NewIPState,
    },
    IPBlockedByHeuristic {
        heuristic: Heuristic,
        ip: Ipv4Addr,
        attempt_at: DateTime<Utc>,
        blocked_at: DateTime<Utc>,
    },
    OneTimePassphrase(Profile, String),
}

pub enum NewIPState {
    Notified,
    ConfirmingAllow,
    ConfirmingBlock,
    Allowed,
    Blocked,
}

pub enum NewIpUserReply {
    AllowIP { message_id: String },
    DenyIP { message_id: String },
}
