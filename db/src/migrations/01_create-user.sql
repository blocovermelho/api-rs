CREATE TABLE IF NOT EXISTS users (
    uuid TEXT NOT NULL UNIQUE,
    discord_id TEXT NOT NULL,
    username TEXT UNIQUE,
    created_at DATE,
    pronouns TEXT,
    last_server TEXT,

    PRIMARY KEY (uuid, discord_id)
);