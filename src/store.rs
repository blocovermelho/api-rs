use std::{collections::HashMap, net::Ipv4Addr};

use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

use crate::models::{User, Account, Server};

pub const MAX_ATTEMPTS_PER_ACC : i32 = 5;

#[derive(Serialize, Deserialize, Clone)]
pub struct Store {
    users: HashMap<Uuid, User>,
    accounts: HashMap<Uuid, Account>,
    servers: HashMap<Uuid, Server>,
    current_attempts: HashMap<Uuid,i32>
}

impl Store {
    pub fn new() -> Store {
        Store { users: HashMap::new(), accounts: HashMap::new(), servers: HashMap::new(), current_attempts: HashMap::new() }
    }

    pub fn get_user(&self, id: &Uuid) -> Option<&User> { 
        self.users.get(id)
    }

    pub fn get_users(&self) -> Vec<User> {
        self.users.values().into_iter().map(|it| it.to_owned()).collect()
    }

    pub fn get_server(&self, id: &Uuid) -> Option<&Server> {
        self.servers.get(id)
    }

    pub fn get_servers(&self) -> Vec<Server> {
        self.servers.values().into_iter().map(|it| it.to_owned()).collect()
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
                let diff = when - acc.last_login;
                acc.previous_ips.contains(ip) && diff.num_minutes() < 10
            },
            None => { false },
        }
    }

    pub fn invalidate_session(&mut self, account: &mut Account) -> bool {
        account.last_login = DateTime::UNIX_EPOCH;
        
        self.update_account(account.clone())
    }

    pub fn add_user(&mut self, user: User) -> bool {
        match self.get_user(&user.uuid) {
            Some(_) => {
                false
            },
            None => {
                self.users.insert(user.uuid, user);
                true
            },
        }   
    }

    pub fn add_server(&mut self, server: Server) -> bool {
        match self.get_server(&server.uuid) {
            Some(_) => {
                false
            },
            None => {
                self.servers.insert(server.uuid, server);
                true
            },
        }   
    }

    pub fn add_account(&mut self, account: Account) -> bool {
        match self.get_account(&account.uuid) {
            Some(_) => {
                false
            },
            None => {
                self.accounts.insert(account.uuid, account);
                true
            },
        }   
    }


    pub fn update_user(&mut self, user: User) -> bool {
        match self.get_user(&user.uuid) {
            Some(a) => {
                self.users.insert(a.uuid, user);
                true
            },
            None => false,
        }
    }

    pub fn update_server(&mut self, server: Server) -> bool {
        match self.get_server(&server.uuid) {
            Some(a) => {
                self.servers.insert(a.uuid, server);
                true
            },
            None => false,
        }
    }

    pub fn update_account(&mut self, account: Account) -> bool {
        match self.get_account(&account.uuid) {
            Some(a) => {
                self.accounts.insert(a.uuid, account);
                true
            },
            None => false,
        }
    }

    pub fn wrong_password(&mut self, account: &Account) -> i32 {
        let attempts = self.current_attempts.get(&account.uuid).unwrap_or(&0).clone();
        self.current_attempts.insert(account.uuid, attempts + 1);

        attempts + 1
    }

    pub fn correct_password(&mut self, account: &Account) {
        self.current_attempts.remove(&account.uuid);
    }
}