CREATE TABLE IF NOT EXISTS accounts (
    uuid TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    current_join DATE,

    FOREIGN KEY (uuid) REFERENCES users(uuid),
    PRIMARY KEY (uuid)
);