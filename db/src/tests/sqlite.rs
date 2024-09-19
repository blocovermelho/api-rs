// Unit Tests for the Sqlite Driver.
use test_log::test;
use uuid::Uuid;

use crate::{data::{stub::UserStub, Pronoun}, drivers::{err::{DriverError, Response}, sqlite::Sqlite}, interface::DataSource};

async fn get_wrapper(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<Sqlite> {
    Ok(Sqlite::new(pool.acquire().await?.detach()))
}

// CREATE

#[test(sqlx::test(migrations = "src/migrations"))]
async fn create_user(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let uuid = Uuid::new_v4();
    let mut db = get_wrapper(pool).await.unwrap();

    let stub = UserStub {
        uuid: uuid.clone(),
        username: "alikindsys".to_owned(),
        discord_id: "-Discord ID-".to_owned(),
    };

    let save = db.create_user(stub.clone()).await.unwrap();

    assert_eq!(stub, save);
    Ok(())
}

// READ
#[test(sqlx::test(migrations = "src/migrations"))]
async fn get_user_by_uuid(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let uuid = Uuid::new_v4();
    let mut db = get_wrapper(pool).await.unwrap();

    let stub = UserStub {
        uuid: uuid.clone(),
        username: "alikindsys".to_owned(),
        discord_id: "-Discord ID-".to_owned(),
    };

    db.create_user(stub.clone()).await.unwrap();
    let save = db.get_user_by_uuid(&uuid).await.unwrap();

    assert_eq!(stub, save);
    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn get_users_by_discord_id(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let discord_id = "-Discord ID-".to_owned();
    let mut db = get_wrapper(pool).await.unwrap();

    let stub = UserStub {
        uuid: Uuid::new_v4(),
        username: "alikindsys".to_owned(),
        discord_id: discord_id.clone(),
    };

    let stub2 = UserStub {
        uuid: Uuid::new_v4(),
        username: "another_user".to_owned(),
        discord_id: discord_id.clone(),
    };


    db.create_user(stub).await.unwrap();
    db.create_user(stub2).await.unwrap();
    let save = db.get_users_by_discord_id(discord_id).await.unwrap();

    assert_eq!(save.len(), 2);
    Ok(())
}

// UPDATE

#[test(sqlx::test(migrations = "src/migrations"))]
async fn add_pronoun(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let uuid = Uuid::new_v4();
    let mut db = get_wrapper(pool).await.unwrap();

    let stub = UserStub {
        uuid: uuid.clone(),
        username: "alikindsys".to_owned(),
        discord_id: "-Discord ID-".to_owned(),
    };

    let pronoun = Pronoun { pronoun: "ela/dela".to_owned(), color: "#F5A9B8".to_owned() };

    db.create_user(stub.clone()).await.unwrap();
    let pronouns = db.add_pronoun(&uuid, pronoun).await.unwrap();

    assert_eq!(pronouns.len(), 1);

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn remove_pronoun(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let uuid = Uuid::new_v4();
    let mut db = get_wrapper(pool).await.unwrap();

    let stub = UserStub {
        uuid: uuid.clone(),
        username: "alikindsys".to_owned(),
        discord_id: "-Discord ID-".to_owned(),
    };

    let pronoun = Pronoun { pronoun: "ela/dela".to_owned(), color: "#F5A9B8".to_owned() };

    db.create_user(stub.clone()).await.unwrap();
    db.add_pronoun(&uuid, pronoun.clone()).await.unwrap();

    let pronouns = db.remove_pronoun(&uuid, pronoun).await.unwrap();

    assert_eq!(pronouns.len(), 0);

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn update_pronoun(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let uuid = Uuid::new_v4();
    let mut db = get_wrapper(pool).await.unwrap();

    let stub = UserStub {
        uuid: uuid.clone(),
        username: "alikindsys".to_owned(),
        discord_id: "-Discord ID-".to_owned(),
    };

    let pronoun = Pronoun { pronoun: "ela/dela".to_owned(), color: "#F5A9B8".to_owned() };
    let update = Pronoun { pronoun: "ela/dela".to_owned(), color: "#5BCEFA".to_owned()};

    db.create_user(stub.clone()).await.unwrap();
    db.add_pronoun(&uuid, pronoun.clone()).await.unwrap();

    let pronouns = db.update_pronoun(&uuid, &pronoun, update.clone()).await.unwrap();

    assert_eq!(pronouns.get(0).unwrap().color, update.color);
    assert_eq!(pronouns.len(), 1);

    Ok(())
}

// DELETE

#[test(sqlx::test(migrations = "src/migrations"))]
async fn delete_user(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let uuid = Uuid::new_v4();
    let mut db = get_wrapper(pool).await.unwrap();

    let stub = UserStub {
        uuid: uuid.clone(),
        username: "alikindsys".to_owned(),
        discord_id: "-Discord ID-".to_owned(),
    };

    db.create_user(stub.clone()).await.unwrap();
    let save = db.delete_user(&uuid).await.unwrap();

    assert_eq!(stub, save);
    Ok(())
}

