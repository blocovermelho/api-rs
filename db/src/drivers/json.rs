// The old JSON-based storage. It's wierd, but it "worked" and we need to migrate the data
// This serves as a lesson on what *not* to do.

use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    sync::Arc,
    time::Duration,
};

// The worst parts is that data-representation is different from what the new database format expects.
// This will need a bunch of conversions and dummy objects.
// This is not a place of honor
pub mod data;
use chrono::{DateTime, Utc};
use data::{self as old_data};
use ipnet::Ipv4Net;
use sqlx::types::Json;
use uuid::Uuid;

use super::err::Response;
use crate::{
    data::{
        result::{self, PlaytimeEntry},
        stub, Account, Allowlist, BanActor, Blacklist, Loc, Migration, Modpack, Pronoun, SaveData,
        Server, User, Viewport,
    },
    drivers::err::{base::NotFoundError, DriverError},
    interface::DataSource,
};

/// This driver is read-only. Most functions will be unimplemented. This is here to migrate data and nothing else.
fn get_highest_mask(nets: &[Ipv4Net]) -> Ipv4Net {
    let mut current_prefix_len = nets.iter().map(Ipv4Net::prefix_len).min().unwrap();
    let first_addr = nets.first().unwrap().addr();
    let mut current_net = Ipv4Net::new(first_addr, current_prefix_len).unwrap();
    let mut all_match = false;
    while !all_match || current_prefix_len > 16 {
        all_match = nets.iter().all(|it| current_net.contains(&it.addr()));

        if all_match {
            break;
        }

        current_prefix_len -= 1;
        current_net = Ipv4Net::new(first_addr, current_prefix_len).unwrap();
    }

    current_net
}

// How deduping will work is that we will get one of the IPv4Net from the set, create a new one with /16 and the base ip and see if
// any subsequent IPs match that netmask. If any does it means we can deduplicate that block and find the lowest common mask between them
// hopefully that isnt 16.
fn deduplicate_entries(nets: &HashSet<Ipv4Net>) -> HashSet<Ipv4Net> {
    let mut dedup_map: HashMap<Ipv4Net, Vec<Ipv4Net>> = HashMap::new();
    let mut networks: HashSet<Ipv4Net> = HashSet::new();
    let initial_network_size = nets.len();

    if initial_network_size > 1 {
        for old_net in nets.clone() {
            if dedup_map.is_empty() {
                dedup_map.insert(Ipv4Net::new(old_net.addr(), 16).unwrap(), vec![old_net]);
            } else {
                let mut tripped = false;

                // The deduplication pass
                dedup_map
                    .iter_mut()
                    .filter(|(k, _)| k.contains(&old_net.addr()))
                    .for_each(|(_, v)| {
                        v.push(old_net);
                        tripped = true;
                    });

                if !tripped {
                    dedup_map.insert(Ipv4Net::new(old_net.addr(), 16).unwrap(), vec![old_net]);
                }
            }
        }

        for (_, v) in dedup_map {
            networks.insert(get_highest_mask(&v));
        }
    } else {
        networks.extend(nets.iter());
    }

    networks
}

pub struct JsonDriver(Arc<old_data::Datum>);

impl From<old_data::Datum> for JsonDriver {
    fn from(value: data::Datum) -> Self {
        Self(Arc::new(value))
    }
}

#[async_trait::async_trait]
impl DataSource for JsonDriver {
    async fn get_user_by_uuid(&self, uuid: &Uuid) -> Response<User> {
        if let Some(old_user) = self.0.clone().users.get(uuid) {
            Ok(User {
                uuid: old_user.uuid,
                username: old_user.username.clone(),
                discord_id: old_user.discord_id.clone(),
                created_at: Utc::now(),       // We don't have created_at. LEL.
                pronouns: Default::default(), // We know pronouns are empty for all ysers since it was a work in progress.
                last_server: old_user.last_server,
                current_migration: None,
            })
        } else {
            Err(DriverError::DatabaseError(NotFoundError::User(*uuid)))
        }
    }

    async fn get_all_users(&self) -> Response<Vec<Uuid>> {
        Ok(self.0.users.keys().copied().collect())
    }

    async fn get_account(&self, uuid: &Uuid) -> Response<Account> {
        if let Some(old_account) = self.0.clone().accounts.get(uuid) {
            Ok(Account {
                uuid: old_account.uuid,
                password: old_account.password.clone(),
                current_join: old_account.last_login.unwrap_or_default(),
                // We're using unwrap_or_default cause if we dont have a login, you'll go back to unix 0 which is safe.
            })
        } else {
            Err(DriverError::DatabaseError(NotFoundError::Account(*uuid)))
        }
    }

    async fn get_all_accounts(&self) -> Response<Vec<Uuid>> {
        Ok(self.0.accounts.keys().copied().collect())
    }

    async fn get_allowlists(&self, player_uuid: &Uuid) -> Response<Vec<Allowlist>> {
        // Oh boy this one is involved. What we call an allowlist is stored... Inside the Account, iirc.
        if let Some(old_account) = self.0.clone().accounts.get(player_uuid) {
            // The idea is quite simple. Unix Time 0 All the last_joins, sets hits to 0.
            // We do, by a miracle have an Hashset<Ipv4Net> which should make getting the base ip and mask relatively easy.
            // Instead of converting things one-to-one, what I will do, is de-duplicate the IP blocks before sending stuff to the database.
            let networks = deduplicate_entries(&old_account.cidr);

            println!(
                "Finished deduplicating networks for {}. Initial Size: {}, Deduplicated: {}",
                player_uuid,
                old_account.cidr.len(),
                networks.len()
            );

            Ok(networks
                .iter()
                .map(|it| Allowlist {
                    uuid: *player_uuid,
                    base_ip: it.addr().to_bits(),
                    mask: it.prefix_len(),
                    last_join: DateTime::default(),
                    hits: 0,
                })
                .collect())
        } else {
            Err(DriverError::DatabaseError(NotFoundError::Account(*player_uuid)))
        }
    }

    async fn get_users_by_discord_id(&self, discord_id: String) -> Response<Vec<User>> {
        Ok(self
            .0
            .clone()
            .users
            .iter()
            .filter(|(_, it)| it.discord_id == discord_id)
            .map(|(k, v)| User {
                uuid: *k,
                username: v.username.clone(),
                discord_id: v.discord_id.clone(),
                created_at: Utc::now(),
                pronouns: Default::default(),
                last_server: v.last_server,
                current_migration: None,
            })
            .collect())
    }

    async fn get_server(&self, server_uuid: &Uuid) -> Response<Server> {
        if let Some(old_server) = self.0.clone().servers.get(server_uuid) {
            Ok(Server {
                uuid: old_server.uuid,
                name: old_server.name.clone(),
                supported_versions: Json(old_server.supported_versions.clone()),
                current_modpack: Json(old_server.current_modpack.clone().map(|it| Modpack {
                    name: it.name.clone(),
                    source: it.source.into(),
                    version: it.version.clone(),
                    uri: it.uri,
                })),
                online: Json(true),
                players: Default::default(),
            })
        } else {
            Err(DriverError::DatabaseError(NotFoundError::Server))
        }
    }

    async fn get_all_servers(&self) -> Response<Vec<Uuid>> {
        Ok(self.0.servers.keys().copied().collect())
    }

    async fn get_playtime(&self, player_uuid: &Uuid, server_uuid: &Uuid) -> Response<Duration> {
        if let Some(old_user) = self.0.users.get(player_uuid) {
            if let Some(playtime) = old_user.playtime.get(server_uuid) {
                Ok(*playtime)
            } else {
                Err(DriverError::DatabaseError(NotFoundError::UserData {
                    server_uuid: *server_uuid,
                    player_uuid: *player_uuid,
                }))
            }
        } else {
            Err(DriverError::DatabaseError(NotFoundError::Account(*player_uuid)))
        }
    }

    // Uninmplemented

    async fn get_playtimes(&self, server_uuid: &Uuid) -> Response<Vec<PlaytimeEntry>> {
        unimplemented!();
    }

    /// The original system behind blacklisting was severely flawed.
    /// I decided to start from a blank slate where only infractors beyond any reasonable doubt
    /// get blacklisted. This data will **not** be migrated, even though it existed.
    ///
    /// The risk of accidentally banning a player forever due to a flaw on the system and it
    /// being a pain to fix is high enough that I just wont do it.
    async fn get_blacklists(&self, ip: Ipv4Addr) -> Response<Vec<Blacklist>> {
        unimplemented!();
    }

    #[allow(clippy::cast_precision_loss, clippy::as_conversions)]
    /// This information wasn't saved.
    async fn get_viewport(&self, player_uuid: &Uuid, server_uuid: &Uuid) -> Response<Viewport> {
        if let Some(user) = self.0.users.get(player_uuid) {
            if let Some(pos) = user.last_pos.get(server_uuid) {
                return Ok(Viewport {
                    loc: Loc {
                        dim: pos.dim.clone(),
                        x: pos.x as f64,
                        y: pos.y as f64,
                        z: pos.z as f64,
                    },
                    yaw: 0.0, // This is what we actually didn't save.
                    pitch: 0.0,
                });
            }
        }

        return Err(DriverError::DatabaseError(NotFoundError::UserData {
            server_uuid: *server_uuid,
            player_uuid: *player_uuid,
        }));
    }

    async fn create_user(&self, stub: stub::UserStub) -> Response<User> {
        unimplemented!();
    }

    async fn delete_user(&self, uuid: &Uuid) -> Response<User> {
        unimplemented!();
    }

    async fn migrate_user(&self, from: &Uuid, into: &Uuid) -> Response<User> {
        unimplemented!();
    }

    async fn create_account(&self, stub: stub::AccountStub) -> Response<()> {
        unimplemented!();
    }

    async fn update_password(&self, player_uuid: &Uuid, new_password: String) -> Response<()> {
        unimplemented!();
    }

    async fn update_current_join(&self, player_uuid: &Uuid) -> Response<()> {
        unimplemented!();
    }

    async fn migrate_account(&self, from: &Uuid, to: &Uuid) -> Response<()> {
        unimplemented!();
    }

    async fn delete_account(&self, player_uuid: &Uuid) -> Response<()> {
        unimplemented!();
    }

    async fn create_allowlist(&self, player_uuid: &Uuid, ip: Ipv4Addr) -> Response<Allowlist> {
        unimplemented!();
    }

    async fn get_server_by_name(&self, name: String) -> Response<Server> {
        unimplemented!();
    }

    async fn get_allowlists_with_ip(
        &self, player_uuid: &Uuid, ip: Ipv4Addr,
    ) -> Response<Vec<Allowlist>> {
        unimplemented!();
    }

    async fn get_allowlists_with_range(
        &self, player_uuid: &Uuid, ip: Ipv4Addr, mask: u8,
    ) -> Response<Vec<Allowlist>> {
        unimplemented!();
    }

    async fn bump_allowlist(&self, entry: Allowlist) -> Response<()> {
        unimplemented!();
    }

    async fn broaden_allowlist_mask(&self, entry: Allowlist, new_mask: u8) -> Response<()> {
        unimplemented!();
    }

    async fn delete_allowlist(&self, entry: Allowlist) -> Response<()> {
        unimplemented!();
    }

    async fn create_blacklist(&self, ip: Ipv4Addr, actor: BanActor) -> Response<Blacklist> {
        unimplemented!();
    }

    async fn get_blacklists_with_range(&self, ip: Ipv4Addr, mask: u8) -> Response<Vec<Blacklist>> {
        unimplemented!();
    }

    async fn bump_blacklist(&self, entry: Blacklist) -> Response<()> {
        unimplemented!();
    }

    async fn broaden_blacklist_mask(&self, entry: Blacklist, new_mask: u8) -> Response<()> {
        unimplemented!();
    }

    async fn delete_blacklist(&self, entry: Blacklist) -> Response<()> {
        unimplemented!();
    }

    async fn create_server(&self, stub: stub::ServerStub) -> Response<Server> {
        unimplemented!();
    }

    async fn delete_server(&self, server_uuid: &Uuid) -> Response<Server> {
        unimplemented!();
    }

    async fn join_server(
        &self, server_uuid: &Uuid, player_uuid: &Uuid,
    ) -> Response<result::ServerJoin> {
        unimplemented!();
    }

    async fn leave_server(
        &self, server_uuid: &Uuid, player_uuid: &Uuid,
    ) -> Response<result::ServerLeave> {
        unimplemented!();
    }

    async fn update_server_status(&self, server_uuid: &Uuid, online: bool) -> Response<bool> {
        unimplemented!();
    }

    async fn update_viewport(
        &self, player_uuid: &Uuid, server_uuid: &Uuid, viewport: Viewport,
    ) -> Response<Viewport> {
        unimplemented!();
    }

    async fn update_playtime(
        &self, player_uuid: &Uuid, server_uuid: &Uuid, new_playtime: Duration,
    ) -> Response<()> {
        unimplemented!();
    }

    async fn add_pronoun(&self, player_uuid: &Uuid, pronoun: Pronoun) -> Response<Vec<Pronoun>> {
        unimplemented!();
    }

    async fn remove_pronoun(&self, player_uuid: &Uuid, pronoun: Pronoun) -> Response<Vec<Pronoun>> {
        unimplemented!();
    }

    async fn update_pronoun(
        &self, player_uuid: &Uuid, old: &Pronoun, new: Pronoun,
    ) -> Response<Vec<Pronoun>> {
        unimplemented!();
    }

    async fn create_savedata(&self, player_uuid: &Uuid, server_uuid: &Uuid) -> Response<SaveData> {
        unimplemented!();
    }

    async fn get_savedatas(&self, player_uuid: &Uuid) -> Response<Vec<SaveData>> {
        unimplemented!();
    }

    async fn get_user_by_name(&self, name: String) -> Response<User> {
        unimplemented!()
    }

    async fn create_migration(
        &self, old_account: String, new_account: String, parent: Option<Uuid>,
    ) -> Response<Migration> {
        unimplemented!();
    }

    async fn get_migration(&self, migration: &Uuid) -> Response<Migration> {
        unimplemented!()
    }

    async fn add_completed_server(&self, migration: &Uuid, server: &Uuid) -> Response<Vec<Uuid>> {
        unimplemented!()
    }

    async fn set_current_migration(&self, user: &Uuid, migration: &Uuid) -> Response<Uuid> {
        unimplemented!()
    }

}
