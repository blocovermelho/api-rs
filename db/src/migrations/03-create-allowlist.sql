CREATE TABLE allowlist (
    uuid TEXT NOT NULL,
    password TEXT NOT NULL,
    last_join DATE,

    FOREIGN KEY (uuid) REFERENCES user(uuid),
    PRIMARY KEY (uuid, last_join)
);