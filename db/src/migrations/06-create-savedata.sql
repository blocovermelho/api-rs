CREATE TABLE savedata (
    server_uuid TEXT,
    player_uuid TEXT,
    playtime TEXT,
    viewport TEXT,

    FOREIGN KEY (server_uuid) REFERENCES server(uuid),
    FOREIGN KEY (player_uuid) REFERENCES user(uuid),

    PRIMARY KEY (server_uuid, player_uuid)
);