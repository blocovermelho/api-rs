CREATE TABLE IF NOT EXISTS allowlist (
    uuid TEXT NOT NULL,
    discord_id TEXT NOT NULL,
    base_ip INTEGER NOT NULL,
    mask INTEGER NOT NULL,
    last_join DATE,
    hits INTEGER,

    FOREIGN KEY (uuid, discord_id) REFERENCES users(uuid, discord_id),
    PRIMARY KEY (uuid, last_join)
);