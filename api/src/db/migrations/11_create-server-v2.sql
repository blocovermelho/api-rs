CREATE TABLE IF NOT EXISTS server_v2 (
    uuid TEXT,
    name TEXT UNIQUE,
    versions TEXT,
    game TEXT,
    max_players INTEGER,
    staff TEXT,

    PRIMARY KEY(uuid)
);
