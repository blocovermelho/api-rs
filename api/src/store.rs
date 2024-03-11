use std::{collections::{HashMap, HashSet}, net::Ipv4Addr};

use chrono::{DateTime, Utc};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use textnonce::TextNonce;
use traits::json::JsonSync;
use uuid::Uuid;

use crate::{cidr::{any_match, decode, encode, get_exact_match, match_with_merge, new_host, try_merge}, models::{Account, BanIssuer, BanResponse, CidrKind, GraceResponse, Server, User}};

pub const MAX_ATTEMPTS_PER_ACC: i32 = 5;

#[derive(Serialize, Deserialize, Clone)]
pub struct Store {
    users: HashMap<Uuid, User>,
    accounts: HashMap<Uuid, Account>,
    servers: HashMap<Uuid, Server>,
    current_attempts: HashMap<Uuid, i32>,
    current_nonces: HashMap<String, Uuid>,
    current_handshakes: HashMap<String, u64>,
    ledger: HashMap<String, Vec<CidrKind>>
}

impl JsonSync for Store {
    type T = Self;

    fn new() -> Self::T {
        Self {
            users: HashMap::new(),
            accounts: HashMap::new(),
            servers: HashMap::new(),
            current_attempts: HashMap::new(),
            current_nonces: HashMap::new(),
            current_handshakes: HashMap::new(),
            ledger: HashMap::new()
        }
    }

    fn is_empty(this: &Self::T) -> bool {
        this.users.is_empty()
            && this.accounts.is_empty()
            && this.servers.is_empty()
            && this.current_attempts.is_empty()
            && this.current_nonces.is_empty()
            && this.current_handshakes.is_empty()
            && this.ledger.is_empty()
    }
}

impl Store {
    pub fn get_user(&self, id: &Uuid) -> Option<&User> {
        self.users.get(id)
    }

    pub fn get_user_from_discord(&self, id: u64) -> Option<&User> {
        let u = self.users.iter().find(|(_, it)| it.discord_id == id.to_string())?;
        Some(u.1)
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
                any_match(&acc.cidr, ip) && diff.num_minutes() < 10
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

    pub fn add_handshake(&mut self, id: u64) -> String {
        let nonce = TextNonce::new().0;
        self.current_handshakes.insert(nonce.clone(), id);
        nonce
    }

    pub fn get_handshake_holder(&self, nonce: &String) -> Option<User> {
        let uid = self.current_handshakes.get(nonce)?.to_owned();
        let u = self.get_users().into_iter().find(|i| i.discord_id == uid.clone().to_string())?;
        Some(u)
    }

    pub fn clear_handshake(&mut self, nonce: &String) {
        self.current_handshakes.remove(nonce);
    }

    pub fn has_handshake(&self, id: u64) -> bool {
        self.current_handshakes.values().any(|it| it == &id)
    }

    pub fn get_all_banned_cidr(&self) -> HashSet<Ipv4Net> {
        self.ledger.keys().map(|f| decode(f).unwrap()).collect()
    }

    pub fn ban_cidr(&mut self, ip: String, kind: CidrKind) -> BanResponse {
        match kind {
            CidrKind::Allowed {..} =>  {
                BanResponse::Invalid
            }
            CidrKind::Banned {..}=> {
                // Iterate through each legder entry to see if they match the current IP.
                let keys : HashSet<Ipv4Net> =  self.ledger.keys().map(|it| decode(it).unwrap()).collect();
                let net : Ipv4Addr = ip.parse().unwrap();
                
                // Base-Case: A CIDR that maches that IP already exists
                if let Some(addr) = get_exact_match(&keys, &net) {
                    let key = encode(&addr);
                    let mut entries = self.ledger.get(&key).unwrap().clone();
                    entries.push(kind);

                    let _ = self.ledger.insert(key, entries);
                    return BanResponse::Existing;
                }

                // Here be dragons. 
                // Case: CIDR-Reduction
                // There exists a CIDR that can be merged with the current IP
                if let Some((old, new)) = match_with_merge(&keys, &net) {
                    let old_key = encode(&old);
                    let new_key = encode(&new);

                    let mut entries = self.ledger.get(&old_key).unwrap().clone();
                    entries.push(kind);
                    let _ = self.ledger.remove(&old_key);
                    let _ = self.ledger.insert(new_key, entries);
                    return BanResponse::Merged;
                }
                // This one is *brand new*
                self.ledger.insert(encode(&new_host(&net)), vec![kind]);
                
                return BanResponse::New;
            }
        }
    }

    pub fn get_bans(&self, ip: String) -> Option<Vec<CidrKind>> {
        let keys : HashSet<Ipv4Net> =  self.ledger.keys().map(|it| decode(it).unwrap()).collect();
        let net : Ipv4Addr = ip.parse().unwrap();

        if let Some(addr) = get_exact_match(&keys, &net) {
            let key = encode(&addr);
            let entries = self.ledger.get(&key).unwrap().clone();

            return Some(entries);
        }

        None
    }

    pub fn get_last_automatic_ban_key(&self, uuid: &Uuid) -> Option<(String, Ipv4Addr)> {
        // Get all ip bans for this user which were issued automatically
        let items : HashMap<&String, &Vec<CidrKind>> = self.ledger.iter().filter(|(k,v)| {
            let cond = v.iter().any(|entry| {
                if let CidrKind::Banned { uuid: ban_uuid, time: _, issuer, ip: _ } = entry {
                    return uuid == ban_uuid && matches!(issuer, BanIssuer::Automatic);
                } else {
                    return false;
                }
            });

            cond
        }).collect();

        let mut last_time : DateTime<Utc> = DateTime::UNIX_EPOCH;
        let mut last_ip : Option<Ipv4Addr> = None;
        let mut last_key : Option<String> = None; 
        for (k, entries) in items {
            for entry in entries {
                if let CidrKind::Banned { uuid: _, time, ip, issuer: _} = entry {
                    if last_time < time.clone() {
                        last_time = time.clone();
                        last_ip = Some(ip.clone());
                        last_key = Some(k.clone());
                    }
                }
            }
        }

        if let Some(key) = last_key {
            return Some((key, last_ip.unwrap()));
        }
        None
    }

    pub fn grace_user(&mut self, kind: CidrKind) -> GraceResponse {
        match kind {
            CidrKind::Allowed { user_id, self_registered: _, time: _ } => {
                if let Some(user) = self.get_user_from_discord(user_id) {
                    let uuid = user.uuid;
                    let last_ban_key = self.get_last_automatic_ban_key(&uuid);

                    if let Some((key,last_ip)) = last_ban_key {
                        let mut entries = self.ledger.get(&key).unwrap().clone();
                        entries.retain(|elem| {
                            if let CidrKind::Banned { uuid: _, time: _, issuer: _, ip } = elem {
                                ip != &last_ip
                            } else {
                                true
                            }
                        });

                        if entries.is_empty() {
                            self.ledger.remove(&key);
                        } else {
                            // Base Case: The Set only has one key.
                            if entries.len() == 1 {
                                let first = entries.get(0).unwrap();
                                if let CidrKind::Banned { uuid: _, time: _, issuer: _, ip } = first {
                                    let host = new_host(ip);
                                    self.ledger.insert(encode(&host), entries);
                                    self.ledger.remove(&key);
                                }
                                return GraceResponse::Grace(last_ip);
                            }

                            // Re-evaluate the CIDR based on the entry being removed.
                            let new_set : HashSet<Ipv4Net> = entries.iter().map(|it| 
                                if let CidrKind::Banned { uuid: _, time: _, issuer: _, ip } = it {
                                   return Some(new_host(ip));
                                } else {
                                    return None;
                                }
                            ).flatten().collect();

                            if let Some(merged) = try_merge(&new_set) {
                                let arr : Vec<&Ipv4Net> = merged.iter().collect();
                                // Base Case: Was able to fold completely into a single address.
                                if merged.len() == 1 {
                                    let new_net = *arr.first().unwrap();
                                    self.ledger.insert(encode(new_net), entries);
                                    return GraceResponse::Grace(last_ip);  
                                }
                                
                                for net in arr {
                                    self.ledger.insert(encode(net), entries.clone());
                                }

                                self.ledger.remove(&key); 

                            } else {
                                self.ledger.insert(key, entries);
                            }
                        }

                        return GraceResponse::Grace(last_ip);
                    }
                }
                return GraceResponse::Invalid;
            },
            CidrKind::Banned {..} => return GraceResponse::Invalid,
        }
    }
}
