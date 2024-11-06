#[allow(unused_variables)]
#[cfg(feature = "legacy")]
pub mod json;

#[cfg(feature = "sqlite")]
pub mod sqlite;

pub const MAX_SESSION_TIME_MINUTE : i64 = 15;

pub mod err {
    pub mod base {
        use uuid::Uuid;

        /// When information can't be found on the database.
        #[derive(Debug)]
        pub enum NotFoundError {
            Server, // Equivalent to: Server{Join,Leave}::InvalidServer, {Viewport,Playtime}Update::InvalidServer
            User(Uuid), // Equivalent to: Server{Join,Leave}::InvalidUser, {Viewport,Playtime}Update::InvalidUser
            DiscordAccount, // Didn't exist.
            Account(Uuid), // Equivalent to: Password{Check,Modify}::Unregistered
            UserData { server_uuid: Uuid, player_uuid: Uuid }, // Didn't exist
            Session, // Equivalent to: SessionCheck::Deny
            WhitelistEntry, // Didn't exist.
            BlacklistEntry, // Equivalent to: PardonAttempt::NotBanned
        }

        /// When user input is invalid.
        #[derive(Debug)]
        pub enum InvalidError {
            Password, // Equivalent to: Password{Check,Modify}::InvalidPassword
            OldPassword, // Didn't exist.
        }

        #[derive(Debug)]
        pub enum PermissionError {
            AutomatedSystem, // Equivalent to: PardonAttempt::InsufficientPermissions
        }
    }

    #[derive(Debug)]
    pub enum DriverError {
        DatabaseError(base::NotFoundError),
        DuplicateKeyInsertion,
        InvalidInput(base::InvalidError),
        InsufficientPermissions(base::PermissionError),
        Generic(String),
        Unreachable,
    }

    pub type Response<T> = Result<T, DriverError>;
}
