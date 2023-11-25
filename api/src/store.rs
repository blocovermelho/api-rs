use std::{collections::HashMap, net::Ipv4Addr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use traits::json::JsonSync;

use crate::models::{Account, Server, User};

pub const MAX_ATTEMPTS_PER_ACC: i32 = 5;

#[derive(Serialize, Deserialize, Clone)]
pub struct Store {
    users: HashMap<Uuid, User>,
    accounts: HashMap<Uuid, Account>,
    servers: HashMap<Uuid, Server>,
    current_attempts: HashMap<Uuid, i32>,
    current_nonces: HashMap<String, Uuid>,
}

impl JsonSync for Store {
    type T = Self;

    fn new() -> Self::T {
        Self {
            users: HashMap::new(),
            accounts: HashMap::new(),
            servers: HashMap::new(),
            current_attempts: HashMap::new(),
            current_nonces: HashMap::new()
        }
    }

    fn is_empty(this: &Self::T) -> bool {
        this.users.is_empty() &&
        this.accounts.is_empty() &&
        this.servers.is_empty() &&
        this.current_attempts.is_empty() &&
        this.current_nonces.is_empty()
    }
}

impl Store {
    pub fn get_user(&self, id: &Uuid) -> Option<&User> {
        self.users.get(id)
    }

    pub fn get_users(&self) -> Vec<User> {
        self.users
            .values()
            .into_iter()
            .map(|it| it.to_owned())
            .collect()
    }

    pub fn get_server(&self, id: &Uuid) -> Option<&Server> {
        self.servers.get(id)
    }

    pub fn get_servers(&self) -> Vec<Server> {
        self.servers
            .values()
            .into_iter()
            .map(|it| it.to_owned())
            .collect()
    }

    pub fn get_server_from_name(&self, name: &String) -> Option<&Server> {
        self.servers.values().find(|x| x.name == name.to_owned())
    }

    pub fn get_account(&self, id: &Uuid) -> Option<&Account> {
        self.accounts.get(id)
    }

    pub fn has_valid_session(&self, user: &User, ip: &Ipv4Addr, when: DateTime<Utc>) -> bool {
        match self.get_account(&user.uuid) {
            Some(acc) => {
                let diff = when - acc.last_login.unwrap_or(when);
                acc.previous_ips.contains(ip) && diff.num_minutes() < 10
            }
            None => false,
        }
    }

    pub fn invalidate_session(&mut self, account: &mut Account) -> bool {
        account.last_login = None;

        self.update_account(account.clone())
    }

    pub fn add_user(&mut self, user: User) -> bool {
        match self.get_user(&user.uuid) {
            Some(_) => false,
            None => {
                self.users.insert(user.uuid, user);
                true
            }
        }
    }

    pub fn drop_user(&mut self, uuid: &Uuid) -> Option<User> {
        self.users.remove(uuid)
    }

    pub fn add_server(&mut self, server: Server) -> bool {
        match self.get_server(&server.uuid) {
            Some(_) => false,
            None => {
                self.servers.insert(server.uuid, server);
                true
            }
        }
    }

    pub fn drop_server(&mut self, uuid: &Uuid) -> Option<Server> {
        self.servers.remove(uuid)
    }

    pub fn add_account(&mut self, account: Account) -> bool {
        match self.get_account(&account.uuid) {
            Some(_) => false,
            None => {
                self.accounts.insert(account.uuid, account);
                true
            }
        }
    }

    pub fn drop_account(&mut self, uuid: &Uuid) -> Option<Account> {
        self.accounts.remove(uuid)
    }

    pub fn update_user(&mut self, user: User) -> bool {
        match self.get_user(&user.uuid) {
            Some(a) => {
                self.users.insert(a.uuid, user);
                true
            }
            None => false,
        }
    }

    pub fn update_server(&mut self, server: Server) -> bool {
        match self.get_server(&server.uuid) {
            Some(a) => {
                self.servers.insert(a.uuid, server);
                true
            }
            None => false,
        }
    }

    pub fn update_account(&mut self, account: Account) -> bool {
        match self.get_account(&account.uuid) {
            Some(a) => {
                self.accounts.insert(a.uuid, account);
                true
            }
            None => false,
        }
    }

    pub fn wrong_password(&mut self, account: &Account) -> i32 {
        let attempts = self
            .current_attempts
            .get(&account.uuid)
            .unwrap_or(&0)
            .clone();
        self.current_attempts.insert(account.uuid, attempts + 1);

        attempts + 1
    }

    pub fn correct_password(&mut self, account: &Account) {
        self.current_attempts.remove(&account.uuid);
    }

    pub fn add_nonce(&mut self, nonce: String, uuid: Uuid) {
        let current = self.get_nonce_for(&uuid);

        match current {
            Some(k) => {
                self.current_nonces.remove(&k);
                self.current_nonces.insert(nonce, uuid);
            }
            None => {
                self.current_nonces.insert(nonce, uuid);
            }
        }
    }

    pub fn get_nonce_for(&self, uuid: &Uuid) -> Option<String> {
        self.current_nonces
            .iter()
            .find(|(_, x)| x == &uuid)
            .map(|x| x.0.to_owned())
    }

    pub fn get_uuid_from_nonce(&self, nonce: &String) -> Option<&Uuid> {
        self.current_nonces.get(nonce)
    }

    pub fn drop_nonce(&mut self, nonce: &String) {
        self.current_nonces.remove(nonce);
    }
}
