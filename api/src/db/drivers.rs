#[allow(unused_variables)] pub mod json;
pub mod sqlite;

pub const MAX_SESSION_TIME_MINUTE: i64 = 15;

pub mod err {
    use anyhow::Result;
    use thiserror::Error;
    pub mod base {
        use thiserror::Error;
        use uuid::Uuid;

        /// When information can't be found on the database.
        #[derive(Debug, Error)]
        pub enum NotFoundError {
            #[error("Server not found.")]
            Server, // Equivalent to: Server{Join,Leave}::InvalidServer, {Viewport,Playtime}Update::InvalidServer
            #[error("Profile with UUID: `{0}` not found")]
            User(Uuid), // Equivalent to: Server{Join,Leave}::InvalidUser, {Viewport,Playtime}Update::InvalidUser
            #[error("Discord Account not found")]
            DiscordAccount, // Didn't exist.
            #[error("Account with UUID: `{0}` not found")]
            Account(Uuid), // Equivalent to: Password{Check,Modify}::Unregistered
            #[error("Profile with username: `{0}` not found")]
            Profile(String),
            #[error(
                "No data associated on the server `{server_uuid}` for the user `{player_uuid}`"
            )]
            UserData {
                server_uuid: Uuid,
                player_uuid: Uuid,
            }, // Didn't exist
            #[error("No session found for the profile: `{0}`")]
            Session(Uuid), // Equivalent to: SessionCheck::Deny
            #[error("No allowed IPs found")]
            WhitelistEntry, // Didn't exist.
            #[error("No blocked IPs found")]
            BlacklistEntry, // Equivalent to: PardonAttempt::NotBanned
            #[error("The connection: `{1}` does not exist for `{0}`")]
            Connection(Uuid, String),
            #[error("No token was issued for server `{0}`")]
            TokenServer(Uuid),
            #[error("Invalid Token.")]
            Token,
        }

        /// When user input is invalid.
        #[derive(Debug, Error)]
        pub enum InvalidError {
            #[error("Invalid password")]
            Password, // Equivalent to: Password{Check,Modify}::InvalidPassword
            #[error("Invalid old password")]
            OldPassword, // Didn't exist
        }

        #[derive(Debug, Error)]
        pub enum PermissionError {
            #[error("This action cannot be rolled back with an automated system. Please contact the server staff.")]
            AutomatedSystem, // Equivalent to: PardonAttempt::InsufficientPermissions
        }
    }

    #[derive(Debug, Error)]
    pub enum DriverError {
        #[error("Database Error: ")]
        DatabaseError(#[from] base::NotFoundError),
        #[error("Duplicate Key Insertion")]
        DuplicateKeyInsertion,
        #[error("Invalid Input: ")]
        InvalidInput(#[from] base::InvalidError),
        #[error("Insufficient Permissions: ")]
        InsufficientPermissions(#[from] base::PermissionError),
        #[error("Generic Error: {0}")]
        Generic(String),
        #[error(transparent)]
        SqlxError(#[from] sqlx::Error),
        #[error("UNREACHABLE! This shouldn't happen. UNREACHABLE!")]
        Unreachable,
    }

    unsafe impl Sync for DriverError {}
    unsafe impl Send for DriverError {}

    pub type Response<T> = anyhow::Result<T, DriverError>;
}
