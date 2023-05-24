use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Map::Table)
                    .col(ColumnDef::new(Map::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Map::Name).string().not_null())
                    .col(ColumnDef::new(Map::Places).string().not_null())
                    .col(ColumnDef::new(Map::Players).string().not_null())
                    .col(ColumnDef::new(Map::Places).string().not_null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Map::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
pub enum Map {
    Table,
    Id,
    Name,
    Players,
    Places,
}
