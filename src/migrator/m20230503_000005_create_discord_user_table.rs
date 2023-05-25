use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(DiscordUser::Table)
                    .col(
                        ColumnDef::new(DiscordUser::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(DiscordUser::Status).string().not_null())
                    .col(ColumnDef::new(DiscordUser::Username).string().not_null())
                    .col(ColumnDef::new(DiscordUser::Email).string().not_null())
                    .col(ColumnDef::new(DiscordUser::Nickname).string())
                    .col(ColumnDef::new(DiscordUser::Discriminator).integer())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(DiscordUser::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
pub enum DiscordUser {
    Table,
    Id,
    Status,
    Username,
    Email,
    Nickname,
    Discriminator,
}
