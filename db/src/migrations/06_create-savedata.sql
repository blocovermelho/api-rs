CREATE TABLE IF NOT EXISTS savedata (
    server_uuid TEXT,
    player_uuid TEXT,
    player_discord_id TEXT,
    playtime TEXT,
    viewport TEXT,

    FOREIGN KEY (server_uuid) REFERENCES servers (uuid),
    FOREIGN KEY (player_uuid, player_discord_id) REFERENCES users (uuid, discord_id),

    PRIMARY KEY (server_uuid, player_uuid)
);