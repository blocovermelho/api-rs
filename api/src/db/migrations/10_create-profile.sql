CREATE TABLE IF NOT EXISTS profiles (
    uuid TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    discord_id TEXT NOT NULL,
    password TEXT NOT NULL,
    PRIMARY KEY (uuid, username)
)
