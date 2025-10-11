use uuid::Uuid;

pub enum ConnectionState {
    Visitor, /* Previously known as "unregistered" */
    LoggedIn,
    ServerTransfered,
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

pub enum Heuristic {
    /// When a bad actor tries to either:
    /// - Connect to the same logged in profile multiple times in a short period of time
    /// - Connect to different previously logged profiles in a short period of time
    ///     Since either of these options are quite intentional, no warnings will be given and said IP will be banned immediately.
    ///     Confirmation messages that would've been sent to the affected users should be edited to say that no action is needed and that attempt got blocked.
    SpammedAttempt {
        count: usize,
        profiles: Vec<uuid::Uuid>,
    },
    /// When a probable bad actor tries to connect to an profile which was already logged in
    /// Since this can happen by accident, IPs will not be immediately banned unless multiple attempts are done
    LoggedKickAttempt {
        profile: uuid::Uuid,
        server: uuid::Uuid,
    },
}
pub enum Connection {
    BedrockUsername(String),
    MojangUuid(uuid::Uuid),
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
