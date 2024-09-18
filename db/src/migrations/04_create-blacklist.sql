CREATE TABLE IF NOT EXISTS blacklist (
    base_ip INTEGER UNIQUE,
    mask INTEGER UNIQUE,
    created_at DATE,
    actor TEXT NOT NULL,
    hits INTEGER, 

    PRIMARY KEY (base_ip, mask)
);