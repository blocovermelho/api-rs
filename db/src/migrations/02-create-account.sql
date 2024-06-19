CREATE TABLE IF NOT EXISTS accounts (
    uuid TEXT NOT NULL,
    password TEXT NOT NULL,
    current_join DATE,

    FOREIGN KEY (uuid) REFERENCES user(uuid),
    PRIMARY KEY (uuid)
);