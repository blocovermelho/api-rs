CREATE TABLE IF NOT EXISTS server (
    uuid TEXT,
    name TEXT unique,
    actor TEXT NOT NULL,
    supported_versions TEXT,
    current_modpack TEXT,
    online INTEGER,
    players TEXT,

    PRIMARY KEY (uuid)
);
