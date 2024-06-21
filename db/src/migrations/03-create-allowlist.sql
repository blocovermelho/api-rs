CREATE TABLE IF NOT EXISTS allowlist (
    uuid TEXT NOT NULL,
    ip_range TEXT NOT NULL,
    last_join DATE,

    FOREIGN KEY (uuid) REFERENCES user(uuid),
    PRIMARY KEY (uuid, last_join)
);