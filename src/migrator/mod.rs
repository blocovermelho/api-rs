mod m20230503_000001_create_nonce_table;
mod m20230503_000002_create_account_table;
mod m20230503_000003_create_session_table;

use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20230503_000001_create_nonce_table::Migration),
            Box::new(m20230503_000002_create_account_table::Migration),
            Box::new(m20230503_000003_create_session_table::Migration),
        ]
    }
}
