// The migration process from the old JSON-based data store to a SQLite database
// Should be relatively simple to do, since we're only migrating User/Account/Server data.

use std::{collections::HashMap, fs::File, io::BufReader, path::PathBuf};

use db::{
    data::stub::{AccountStub, ServerStub, UserStub},
    drivers::{
        err::{base::NotFoundError, DriverError, Response},
        json::{data::Datum, JsonDriver},
        sqlite::Sqlite,
    },
    interface::DataSource,
};
use uuid::Uuid;

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
    migrate_account_data(&db, &old_store).await?;

    Ok(db)
}

// Let's start by the easiest part. Server data
pub async fn migrate_server_data(
    sqlite: &Sqlite, old: &JsonDriver, mappings: &mut HashMap<Uuid, Uuid>,
) -> Response<()> {
    let servers = old.get_all_servers().await?;
    println!("[Server Data] Migration Started. Count: {}", servers.len());
    for id in servers {
        let server = old.get_server(&id).await?;
        let new_server = sqlite
            .create_server(ServerStub {
                name: server.name,
                supported_versions: server.supported_versions.0,
                current_modpack: server.current_modpack.0,
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
    let servers = old.get_all_servers().await?;
    println!("[User Data] Migration Started. Count: {}", users.len());
    println!("[User Data] Server Id Mappings: {}", server_id_mappings.len());
    println!("[Mappings] {:?}", server_id_mappings);

    for id in users {
        println!("[User Data] Migration for {id} started.");
        // From the user, we need to gather a bunch of things
        let user = old.get_user_by_uuid(&id).await?;
        sqlite
            .create_user(UserStub {
                uuid: user.uuid,
                username: user.username,
                discord_id: user.discord_id,
            })
            .await?;

        // We do not have a way to set last_server yet. :(
        // But we can restore at least their playtime.
        for server_id in servers.clone() {
            // We cant be sure if an user has a playtime on that server.
            // We have to handle this correctly.
            let mapped_id = *server_id_mappings
                .get(&server_id)
                .ok_or(DriverError::DatabaseError(NotFoundError::Server))?;

            println!("[User Data] Mapped Server: {id} -> {mapped_id}");

            let mut created = false;

            if let Ok(viewport) = old.get_viewport(&id, &server_id).await {
                println!("[User Data] Got Viewport for: {}", server_id);
                sqlite.create_savedata(&id, &mapped_id).await?;
                println!("[SaveData] Created for user: {} @ server: {}", id, &mapped_id);
                created = true;

                _ = sqlite.update_viewport(&id, &mapped_id, viewport).await;
                println!("[SaveData] Updated viewport.");
            }

            if let Ok(playtime) = old.get_playtime(&id, &server_id).await {
                println!("[User Data] Got playtime for {}: {}s", server_id, playtime.as_secs());

                if !created {
                    sqlite.create_savedata(&id, &mapped_id).await?;
                    println!("[SaveData] Created for user: {} @ server: {}", id, &mapped_id);
                }

                sqlite.update_playtime(&id, &mapped_id, playtime).await?;
                println!("[SaveData] Updated playime.");
            }
        }

        println!("[User Data] Migration for {id} finished.");
    }
    Ok(())
}

// Now finally we can migrate account data.
// This should also include all previous ip addresses that that player connected.
pub async fn migrate_account_data(sqlite: &Sqlite, old: &JsonDriver) -> Response<()> {
    let accounts = old.get_all_accounts().await?;
    println!("[Account Data] Migration Started. Count: {}", accounts.len());

    for id in &accounts {
        let account = old.get_account(id).await?;
        let entries = old.get_allowlists(id).await?;

        sqlite
            .create_account(AccountStub { uuid: account.uuid, password: account.password })
            .await?;

        for entry in &entries {
            let temp = sqlite.create_allowlist(id, entry.base_ip.into()).await?;
            sqlite.broaden_allowlist_mask(temp, entry.mask).await?;
        }

        println!("[Account Data] Migration for {id} finished.");
    }
    Ok(())
}
