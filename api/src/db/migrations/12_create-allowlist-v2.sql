-- I'm only doing this since foreign keys can't be updated on sqlite.
-- And adding that constraint bite me in the back. If I knew this before hand
-- I wouldn't had added this.
CREATE TABLE IF NOT EXISTS allowlist_v2 (
    uuid TEXT NOT NULL,
    base_ip INTEGER NOT NULL,
    mask INTEGER NOT NULL,
    last_join DATE,
    hits INTEGER,

    PRIMARY KEY (uuid, base_ip, mask)
);
