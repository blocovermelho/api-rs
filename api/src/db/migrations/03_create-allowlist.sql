CREATE TABLE IF NOT EXISTS allowlist (
    uuid TEXT NOT NULL,
    base_ip INTEGER NOT NULL,
    mask INTEGER NOT NULL,
    last_join DATE,
    hits INTEGER,
    -- Deleting an account will also remove any prior connection history.
    -- This should only be done if there is no way to recover the account
    -- Or if the user decides to remove it.
    FOREIGN KEY (uuid) REFERENCES accounts(uuid) ON UPDATE CASCADE ON DELETE CASCADE,
    PRIMARY KEY (uuid, base_ip, mask)
);