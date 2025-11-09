CREATE TABLE IF NOT EXISTS tokens (
    -- The UUID of the server which owns said token.
    owner TEXT NOT NULL UNIQUE,
    -- The issued token for authenticating with the API
    token TEXT NOT NULL,
    -- The scopes for accessing resources:
    -- Ex: servers.read servers.self.modify
    --     profiles.read profiles.create profiles.modify
    --     profiles.modify.connections
    scopes TEXT NOT NULL,
    created_at DATE NOT NULL,
    PRIMARY KEY (owner)
)
