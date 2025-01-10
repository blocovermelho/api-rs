CREATE TABLE IF NOT EXISTS namehist (
    id TEXT NOT NULL UNIQUE,
    parent TEXT,
    old TEXT,
    new TEXT,
    started_at DATE NOT NULL,
    finished_at DATE,
    affected_servers TEXT,
    finished_servers TEXT,
    visible TEXT,

    PRIMARY KEY (id)
);

ALTER TABLE users ADD COLUMN current_migration TEXT;
