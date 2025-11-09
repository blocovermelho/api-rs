-- GameServer: Staff (Vec<Profile UUID>)
ALTER TABLE servers ADD COLUMN staff TEXT;
-- GameServer: Game (String)
ALTER TABLE servers ADD COLUMN game TEXT;
-- GameSever: MaxPlayers (i64)
ALTER TABLE servers ADD COLUMN max_players INTEGER;

-- Maybe drop some fields (e.g. "created_at", "last_seen") after the migration is completed.
-- The reason for this is that those information change constantly and shouldn't be persisted.
-- They can (and should) be derived from the new keep-alive packet.

ALTER TABLE servers DROP COLUMN players;
ALTER TABLE servers DROP COLUMN online;
