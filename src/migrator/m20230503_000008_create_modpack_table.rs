use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Modpack::Table)
                    .col(ColumnDef::new(Modpack::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Modpack::Level).string().not_null())
                    .col(ColumnDef::new(Modpack::Loader).string().not_null())
                    .col(ColumnDef::new(Modpack::Url).string())
                    .col(ColumnDef::new(Modpack::DownloadUrl).string())
                    .col(ColumnDef::new(Modpack::Source).string())
                    .col(ColumnDef::new(Modpack::Version).string())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Modpack::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
pub enum Modpack {
    Table,
    Id,
    Level,
    Loader,
    Url,
    DownloadUrl,
    Source,
    Version,
}
