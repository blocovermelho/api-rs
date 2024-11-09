#[allow(unused_variables)]
#[cfg(feature = "legacy")]
pub mod json;

#[cfg(feature = "sqlite")]
pub mod sqlite;

pub const MAX_SESSION_TIME_MINUTE: i64 = 15;

pub mod err {
    use std::fmt::Display;

    pub mod base {
        use std::fmt::Display;

        use uuid::Uuid;

        /// When information can't be found on the database.
        #[derive(Debug)]
        pub enum NotFoundError {
            Server, // Equivalent to: Server{Join,Leave}::InvalidServer, {Viewport,Playtime}Update::InvalidServer
            User(Uuid), // Equivalent to: Server{Join,Leave}::InvalidUser, {Viewport,Playtime}Update::InvalidUser
            DiscordAccount, // Didn't exist.
            Account(Uuid), // Equivalent to: Password{Check,Modify}::Unregistered
            UserData {
                server_uuid: Uuid,
                player_uuid: Uuid,
            }, // Didn't exist
            Session(Uuid), // Equivalent to: SessionCheck::Deny
            WhitelistEntry, // Didn't exist.
            BlacklistEntry, // Equivalent to: PardonAttempt::NotBanned
        }

        impl Display for NotFoundError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Self::Server => write!(f, "Server not found"),
                    Self::User(uuid) => {
                        write!(f, "User for uuid: {} not found.", uuid)
                    }
                    Self::DiscordAccount => write!(f, "Discord Account not found"),
                    Self::Account(uuid) => {
                        write!(f, "Accoount for uuid: {} not found", uuid)
                    }
                    Self::UserData { server_uuid, player_uuid } => write!(
                        f,
                        "The user data for the user ({}) was not found in the server ({})",
                        player_uuid, server_uuid
                    ),
                    Self::Session(uuid) => {
                        write!(f, "Session for uuid: {} not found", uuid)
                    }
                    Self::WhitelistEntry => write!(f, "No whitelist entries found"),
                    Self::BlacklistEntry => write!(f, "No blacklist entries found"),
                }
            }
        }

        impl std::error::Error for NotFoundError {}

        /// When user input is invalid.
        #[derive(Debug)]
        pub enum InvalidError {
            Password,    // Equivalent to: Password{Check,Modify}::InvalidPassword
            OldPassword, // Didn't exist.
        }

        impl Display for InvalidError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Self::Password => write!(f, "Invalid password."),
                    Self::OldPassword => write!(f, "Invalid old password."),
                }
            }
        }

        impl std::error::Error for InvalidError {}

        #[derive(Debug)]
        pub enum PermissionError {
            AutomatedSystem, // Equivalent to: PardonAttempt::InsufficientPermissions
        }

        impl Display for PermissionError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Self::AutomatedSystem => write!(f, "This action cannot be performed by an automated system. Please contact the server staff."),
                }
            }
        }

        impl std::error::Error for PermissionError {}
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

    impl Display for DriverError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::DatabaseError(not_found_error) => {
                    write!(f, "Database Error: {}", not_found_error)
                }
                Self::DuplicateKeyInsertion => write!(f, "Duplicate Key Insertion"),
                Self::InvalidInput(invalid_error) => {
                    write!(f, "Invalid Input: {}", invalid_error)
                }
                Self::InsufficientPermissions(permission_error) => {
                    write!(f, "Insufficient Permissions: {}", permission_error)
                }
                Self::Generic(e) => write!(f, "Error: {e}"),
                Self::Unreachable => {
                    write!(f, "UNREACHABLE! This shouldn't happen. UNREACHABLE!")
                }
            }
        }
    }

    impl std::error::Error for DriverError {}
    unsafe impl Sync for DriverError {}
    unsafe impl Send for DriverError {}

    pub type Response<T> = Result<T, DriverError>;
}
