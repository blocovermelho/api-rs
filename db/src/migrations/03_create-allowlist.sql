CREATE TABLE IF NOT EXISTS allowlist (
    uuid TEXT NOT NULL,
    base_ip INTEGER NOT NULL,
    mask INTEGER NOT NULL,
    last_join DATE,
    hits INTEGER,

    FOREIGN KEY (uuid) REFERENCES user(uuid),
    PRIMARY KEY (uuid, last_join)
);