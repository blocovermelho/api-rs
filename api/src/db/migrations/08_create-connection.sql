CREATE TABLE IF NOT EXISTS connections (
    profile TEXT NOT NULL,
    issuer TEXT,
    kind TEXT NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (profile, kind)
);
