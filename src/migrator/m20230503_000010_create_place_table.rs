use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Place::Table)
                    .col(ColumnDef::new(Place::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Place::Map).uuid().not_null())
                    .col(ColumnDef::new(Place::WorldPos).string().not_null())
                    .col(ColumnDef::new(Place::Name).string().not_null())
                    .col(ColumnDef::new(Place::Tags).string().not_null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Place::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
pub enum Place {
    Table,
    Id,
    Map,
    WorldPos,
    Name,
    Tags,
}
