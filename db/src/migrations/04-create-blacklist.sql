CREATE TABLE IF NOT EXISTS blacklist (
    subnet TEXT UNIQUE,
    created_at DATE,
    actor TEXT NOT NULL,

    PRIMARY KEY (subnet)
);