CREATE TABLE IF NOT EXISTS savedata (
    server_uuid TEXT,
    player_uuid TEXT,
    playtime TEXT,
    viewport TEXT,

    FOREIGN KEY (server_uuid) REFERENCES servers (uuid),
    FOREIGN KEY (player_uuid) REFERENCES users (uuid),

    PRIMARY KEY (server_uuid, player_uuid)
);