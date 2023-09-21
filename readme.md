# Api do Bloco Vermelho
Versão 2

## Configurando o ambiente de desenvolvimento
Com a adição de suporte ao Nix, qualquer um pode ter todo o ambiente de desenvolvimento com apenas um comando.

- Primeiro, baixe o [nix](https://nixos.org/download) se já não o possui.
- Depois, execute `nix-shell` na raiz do projeto.

O Nix irá baixar todas as dependencias necessárias para compilar o projeto, sem ter que instalar nada permanente no seu computador.

Execute os seguintes comandos apos as dependencias serem baixadas.
- `rustup default nightly`
- `rustup toolchain install nightly`
- `rustup component add rust-src rust-analyzer`

Você agora deve estar com um ambiente de desenvolvimento configurado.

## Features

- Necessário: 
  - Login  [Global]
  - Perfis [Global]
    - Settings
  - Sessão [Global]
  - Estatísticas [Global/Per-Server]
  - Integração com o OAUTH do discord. [Global]

- Adicionais
  - Waypoints [Per-Server]
  - Comunicação com o Discord [Per-Server]
  - Board de Planejamento [Per-Server]

## Rotas
  - POST   `/api/auth?uuid=<uuid>`
  - PATCH  `/api/auth?uuid=<uuid>`
  - DELETE `/api/auth?uuid=<uuid>`
  - POST   `/api/profile/create?uuid=<uuid>`
  - PATCH  `/api/profile/update?uuid=<uuid>`
  - GET    `/api/profile/<uuid>`
  - POST   `/api/server/create`
  - GET    `/api/server/<uuid>`
  - GET    `/api/stats`
  - GET    `/api/stats?server=<uuid>`
  - GET    `/api/oauth?key=<key>`


## Rotas planejadas

<details> 
<summary> Place API: </summary> 
  - GET   `/api/place/<uuid>`
  - POST  `/api/place/create`
  - PATCH `/api/place/update?uuid=<uuid>`
  - GET   `/api/place/nearby?server=<uuid>&dim=<dimension>&pos=<x,y,z>&range=<1...2000>`
  - GET   `/api/place/when?tags=<tags[]>`
</details>
<details>
<summary> Board API: </summary>
  - POST   `/api/board/create`
  - GET    `/api/board/<uuid>`
  - PATCH  `/api/board/update?uuid=<uuid>`
  - DELETE `/api/board/<uuid>`

  - POST   `/api/board/<uuid>/post`
  - GET    `/api/board/<uuid>/post/<uuid>`
  - DELETE `/api/board/<uuid>/post/<uuid>`

  
  - GET    `/api/board/<uuid>/post/<uuid>/comment/<uuid>`
  - POST   `/api/board/<uuid>/post/<uuid>/comment`
  - PATCH  `/api/board/<uuid>/post/<uuid>/comment/update?uuid=<uuid>`
  - DELETE `/api/board/<uuid>/post/<uuid>/comment/<uuid>`
</details>
## Objetos

Profile:

```rust
  struct Profile {
    uuid: Uuid, // O UUID do minecraft
    username: String,
    discord_id: String,
    pronouns: Vec<String>,        
    last_seen: DateTime<Utc>,
    joined_at: DateTime<Utc>,
    session: Option<Uuid>
  }
```

Session:
```rust
  struct Session {
    uuid: Uuid, // Id aleatório que representa a sessão
    owner: Uuid, // UUID do minecraft
    ip_address: Ipv4Addr,
    expires_at: DateTime<Utc>,
    use_counter: usize,
    server: Uuid
  }
```
- Se `DateTime.now() > profile.session?.expires_at`, remover a sessão.
- Uma sessão só é criada quando o jogador autenticado se desconecta.
- Sessões são checkadas quando o jogador loga. 
- A inexistência de uma sessão envia ao jogador a mensagem que pede para ele logar.
- No caso de uma sessão válida ser utilizada mais que 10 vezes, essa sessão é descartada. 
- No caso de uma mudança entre servidores com uma sessão válida, o contador de usos irá
  se incrementar por dois.


Auth:
```rust
  struct Auth {
    owner: Uuid, //UUID do minecraft
    password: String,
    discord_id: String,
  }
```
- Se `SELECT * from Auth WHERE owner == player.uuid` retornar null, esse jogador não foi registrado ainda.
- Auth é criado internamente e só pode ser destruido por um administrador ou um jogador autenticado.
- Senhas podem ser alteradas com a confirmação de dois fatores pelo discord, ou por um jogador autenticado.


Server:
```rust
  struct Server {
    uuid: Uuid,
    name: String,
    supported_versions: Vec<String>,
    ip: String,
    modded: bool,
    modpacks: Vec<Uuid>,
    maps: Vec<Uuid>
  }
```

Modpack:
```rust
  struct Modpack {
    uuid: Uuid,
    required: bool,
    loader: String,
    download_url: String,
    version: String
  }
```

Map:
```rust
  struct Map {
    uuid: Uuid.
    name: String,
    players: Vec<Uuid>,
    places: Vec<Uuid>
  }
```

Place:
```rust
  struct Place {
    id: Uuid,
    owner: Uuid, //Id of Map
    x: String,
    y: String,
    z: String,
    dim: String,
    name: String,
    tags: Vec<String>
  }
```

Nonce:
```rust
  struct Nonce {
    code: String,
    owner: Uuid // Minecraft UUID
  }
 ```

 
Statistics:
 ```rust
  struct Statistics {
    owner: Uuid, // Server UUID
    unique_players: usize,
    total_logins: usize,
    total_playtime: DateTime<Utc>,
    online_players: usize
  }
 ```
