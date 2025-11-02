CREATE TABLE IF NOT EXISTS servers (
    uuid TEXT,
    name TEXT unique,
    supported_versions TEXT,
    current_modpack TEXT,
    online TEXT,
    players TEXT,

    PRIMARY KEY (uuid)
);
