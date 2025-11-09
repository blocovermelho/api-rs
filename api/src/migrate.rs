// The migration process from the old JSON-based data store to a SQLite database
// Should be relatively simple to do, since we're only migrating User/Account/Server data.

use std::{collections::HashMap, fs::File, io::BufReader, path::PathBuf, time::Duration};

use uuid::Uuid;

use crate::{
    core::types::{
        enums::ConnectionData,
        structs::stub::{GameServerStub, ProfileStub},
    },
    db::{
        data::Connection,
        drivers::{
            err::{base::NotFoundError, DriverError, Response},
            json::{data::Datum, JsonDriver},
            sqlite::Sqlite,
        },
        interface::DataSource,
    },
};

pub async fn migrate(database_path: &PathBuf, json_path: &PathBuf) -> Response<Sqlite> {
    // Temporary server id mappings table
    let mut mappings: HashMap<Uuid, Uuid> = HashMap::new();

    // Database initialization
    let db = Sqlite::new(database_path).await;
    db.run_migrations().await;

    // Json-backed store reading
    let file = File::open(json_path).unwrap();
    let rdr = BufReader::new(file);
    let datum: Datum = serde_json::from_reader(rdr).unwrap();
    let old_store = JsonDriver::from(datum);

    migrate_server_data(&db, &old_store, &mut mappings).await?;
    migrate_user_data(&db, &old_store, &mappings).await?;

    Ok(db)
}

// Let's start by the easiest part. Server data
pub async fn migrate_server_data(
    sqlite: &Sqlite, old: &JsonDriver, mappings: &mut HashMap<Uuid, Uuid>,
) -> Response<()> {
    let servers = old.get_all_servers_v1().await?;
    println!("[Server Data] Migration Started. Count: {}", servers.len());
    for id in servers {
        let server = old.get_server(&id).await?;
        let new_server = sqlite
            .create_server(GameServerStub {
                name: server.name,
                game: "Minecraft".into(),
                versions: server.versions.0,
                max_players: 0,
                staff: vec![],
            })
            .await?;

        // We need to store mappings from old server ids into new server ids.
        mappings.insert(id, new_server.uuid);

        println!("[Server Data] Migration for {id} finished.");
    }
    Ok(())
}

// Now onto User data. This is done prior to accounts since accounts needs an user to already exist.
pub async fn migrate_user_data(
    sqlite: &Sqlite, old: &JsonDriver, server_id_mappings: &HashMap<Uuid, Uuid>,
) -> Response<()> {
    let users = old.get_all_users().await?;
    let servers = old.get_all_servers_v1().await?;
    let mut user_id_mappings: HashMap<Uuid, Uuid> = HashMap::new();
    println!("[User Data] Migration Started. Count: {}", users.len());
    println!("[User Data] Server Id Mappings: {}", server_id_mappings.len());
    println!("[Mappings] {:?}", server_id_mappings);

    for id in users {
        println!("[User Data] Migration for {id} started.");
        // From the user, we need to gather a bunch of things
        let user = old.get_user_by_uuid(&id).await?;
        if let Ok(account) = old.get_account(&id).await {
            let profile = sqlite
                .create_profile(
                    ProfileStub {
                        username: user.username,
                        discord_id: user.discord_id,
                        password: account.password,
                    },
                    Some(user.created_at),
                )
                .await?;

            user_id_mappings.insert(user.uuid, profile.uuid);

            let entries = old.get_allowlists(&id).await?;
            for entry in &entries {
                let temp = sqlite
                    .create_allowlist(&profile.uuid, entry.base_ip.into())
                    .await?;
                sqlite.broaden_allowlist_mask(temp, entry.mask).await?;
            }
        }

        // We do not have a way to set last_server yet. :(
        // But we can restore at least their playtime.
        for server_id in servers.clone() {
            // We cant be sure if an user has a playtime on that server.
            // We have to handle this correctly.
            let mapped_id = *server_id_mappings
                .get(&server_id)
                .ok_or(DriverError::DatabaseError(NotFoundError::Server))?;

            let mut playtimes: HashMap<Uuid, Duration> = HashMap::new();

            println!("[User Data] Mapped Server: {id} -> {mapped_id}");

            if let Ok(playtime) = old.get_playtime_v1(&id, &server_id).await {
                println!("[User Data] Got playtime for {}: {}s", server_id, playtime.as_secs());
                playtimes.insert(mapped_id, playtime);
            }

            if let Some(profile_id) = user_id_mappings.get(&id) {
                let (kind, data) = ConnectionData::Playtime(playtimes).into();
                let conn = sqlite
                    .create_connection(Connection {
                        profile: *profile_id,
                        issuer: None,
                        kind,
                        data,
                    })
                    .await?;

                println!("[Connection] Created kind={}: {}", conn.kind, conn.data);
            }
        }

        println!("[User Data] Migration for {id} finished.");
    }
    Ok(())
}
