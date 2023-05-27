# Api do Bloco Vermelho
Versão 2

## Modelos

```rs
mod types {
    struct Account {
        owner: Uuid, //fk User
        discord_id: Option<u64>, //fk Discord
        password: String,
    }

    struct Session {
        owner: Uuid, //fk user
        ip_address: Ipv4Addr,
        expires_at: DateTime<Utc>,
    }

    struct User {
        uuid: Uuid, //Source
        nickname: String,
        joined_at: DateTime<Utc>,
        linked_at: Option<DateTime<Utc>>,
        last_seen: DateTime<Utc>,
        trust: Trust,
        referer: Option<Uuid>, //fk user
    }

    enum Trust {
        Unlinked,
        Linked,
        Referred,
        Trusted,
    }

    enum DiscordStatus {
        DiscordApiError,
        OutsideGuild,
        JoinedGuild,
    }

    struct DiscordUser {
        id: u64, // Source Discord
        status: DiscordStatus,
        username: String,
        nickname: Option<String>,
        discriminator: u16,
    }

    struct Server {
        id: Uuid, // source server
        name: String,
        supported_versions: Vec<String>,
        ip: String,
        modded: bool,
        modpacks: Vec<Uuid>,
        multimap: bool,
        maps: Vec<Uuid>,
        player_count: u64,
        max_players: u64,
    }

    struct Connection {
        player: Uuid, //fk user
        server: Uuid, //fk server
        version: String,
    }

    struct Modpack {
        id: Uuid, //source modpack
        level: ModpackLevel,
        loader: Modloader,
        url: String,
        download_url: String,
        source: Option<String>,
        version: String,
    }

    enum ModpackLevel {
        Optional,
        Recommended,
        Obligatory,
    }

    enum Modloader {
        Quilt,
        Fabric,
        Forge,
    }

    struct Map {
        id: Uuid, // source map
        name: String,
        players: Vec<Uuid>, //fk user
        places: Vec<Uuid>,  //fk place
    }

    struct Place {
        id: Uuid, // source place
        map: Uuid,
        x: String,
        y: String,
        z: String,
        dimension: String,
        name: String,
        tags: Vec<String>,
    }

    struct Nonce {
        code: String,
        minecraft_uuid: Uuid,
    }
}
```

## Status

- [x] Implementação dos modelos
  - [x] Migrations
  - [x] Geração dos Entities usando `sea-orm-cli`
  - [x] De-stringificação (Utilização de Tipos JSON na tabela usando Serde/SeaORM)

- [ ] Criação dos endpoints - `api.blocovermelho.org`
  - [ ] Rest - `/v2/`
	- [ ] Login e Registro - `/server-auth/`
	- [ ] Link com o OAUTH2 do Discord - `/link`
	- [ ] Perfis - `/profile/`
	- [ ] Servidores - `/server/`
	- [ ] Mapas - `/map/`
   - [ ] WS
	- [ ] Link `wss://link` 
   - [ ] GraphQL (Em consideração)

- [ ] Migração dos projetos que usem a API V1 (api.soberanacraft.net) para a V2
  - [ ] [Quilt Mod](https://github.com/blocovermelho/quilt-mod)
