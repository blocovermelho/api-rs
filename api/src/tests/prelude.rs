pub use crate::routes::prelude::*;

pub fn get_state() -> State<Arc<AppState>> {
    State(Arc::new(AppState::mock()))
}

pub mod stub {
    use std::net::Ipv4Addr;

    use db::data::stub::{AccountStub, ServerStub, UserStub};
    use uuid::Uuid;

    use crate::tests::prelude::query_params::{IpCheck, LoginAttempt};

    pub fn login_attempt(name: &str, password: &str) -> LoginAttempt {
        LoginAttempt {
            uuid: uuid_mc::PlayerUuid::new_with_offline_username(name)
                .as_uuid()
                .clone(),
            ip: Ipv4Addr::LOCALHOST.into(),
            password: password.to_string(),
        }
    }

    pub fn ip_check(uuid: Uuid, ip: Ipv4Addr) -> IpCheck {
        IpCheck { uuid, ip, server: None }
    }

    pub fn user(name: &str, discord_id: &str) -> UserStub {
        UserStub {
            uuid: uuid_mc::PlayerUuid::new_with_offline_username(name)
                .as_uuid()
                .clone(),
            username: name.to_string(),
            discord_id: discord_id.to_string(),
        }
    }

    /// This function *hashes* the password
    /// To be used with database functions that expect hashed input.
    pub fn account_hashed(uuid: Uuid, password: &str) -> AccountStub {
        AccountStub {
            uuid,
            password: bcrypt::hash(password, 12).unwrap().into(),
        }
    }
    /// This function *does not* hash the password.
    /// To be used with API handlers.
    pub fn account(uuid: Uuid, password: &str) -> AccountStub {
        AccountStub { uuid, password: password.into() }
    }

    pub fn server(name: &str) -> ServerStub {
        ServerStub {
            name: name.into(),
            supported_versions: vec!["1.21.5".into()],
            current_modpack: None,
        }
    }
}

