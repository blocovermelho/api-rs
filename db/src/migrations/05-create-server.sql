CREATE TABLE server (
    uuid TEXT,
    name TEXT unique,
    actor TEXT NOT NULL,
    supported_versions TEXT,
    current_modpack TEXT,
    online INTEGER,

    PRIMARY KEY (uuid)
);