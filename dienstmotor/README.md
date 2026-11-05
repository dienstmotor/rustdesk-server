# Dienstmotor Remote: autenticación obligatoria de operadores (Authentik OIDC)

Este directorio y los cambios en `src/` convierten el `rustdesk-server` OSS en un servidor que
solo establece **nuevas** conexiones de operadores con sesión iniciada en Authentik. Las sesiones ya
establecidas no se vuelven a comprobar nunca.

Repositorios implicados:

| Repositorio | Contenido |
|---|---|
| `dienstmotor/rustdesk-server` (este) | hbbs con autorización, API FastAPI (`dienstmotor/auth-api`), imágenes Docker, workflow |
| `MrYaello/rustdesk` (cliente) | login OIDC + PKCE, tickets en cada conexión nueva, verificación en el equipo receptor |
| `dienstmotor/services` | `rustdesk/docker-compose.dienstmotor-auth.yaml`, `nginx/remote-api.dienstmotor.com` |

## 1. Diseño

```
Operador (Dienstmotor Remote)          remote-api.dienstmotor.com        auth.dienstmotor.com
  │ 1. Login: navegador del sistema, Authorization Code + PKCE S256,
  │    redirect loopback http://127.0.0.1:<puerto>/callback  ─────────────────▶ Authentik
  │ 2. Conexión nueva a ID X:
  │    POST /auth/ticket {peer_id: X}  Bearer <access token> ──▶ valida JWT (JWKS, iss, aud,
  │                                                              azp, exp) + userinfo/introspección
  │    ◀── ticket dm1 (Ed25519, 60 s, sub, tgt=X, jti, iat, exp)
  │ 3. PunchHoleRequest / RequestRelay {token: ticket} ──▶ hbbs ──▶ POST /internal/authorize
  │                                                        (falla cerrado; jti ligado a IP y destino)
  │ 4. hbbs reenvía PunchHole / FetchLocalAddr / RequestRelay al host X solo si se autorizó
  │ 5. LoginRequest {dm_ticket} cifrado extremo a extremo ──▶ host X (Dienstmotor Remote)
  │                                                         verifica firma, tgt = su ID, jti de un solo uso
  ▼ 6. Sesión ESTABLISHED: ningún componente vuelve a mirar tokens ni tickets.
```

Estados del operador: `UNAUTHENTICATED` (sin credenciales, conectar bloqueado) → `AUTHENTICATED`
(se pueden pedir tickets) → `CONNECTING` (`Client::start` obtiene ticket, hbbs y host lo verifican) →
`ESTABLISHED` (independiente del token) → `DISCONNECTED`. Una reconexión vuelve a pasar por
`Client::start`, pide un ticket nuevo y por tanto exige autorización vigente; un ticket anterior
no sirve (caduca en 60 s, y el host lo ata a la primera conexión que lo presentó).

Puntos de control:

* **hbbs** (`src/dm_auth.rs`, dos ganchos en `src/rendezvous_server.rs`): `PunchHoleRequest` y
  `RequestRelay` son los únicos mensajes que hacen que hbbs contacte al equipo destino
  (PunchHole, FetchLocalAddr, RequestRelay). Ambos exigen ticket válido. Los `PunchHoleRequest`
  por UDP ya están deshabilitados en upstream. El registro de equipos (`RegisterPeer`,
  `RegisterPk`) sigue abierto: los hosts no necesitan login.
* **hbbr** sin cambios: el host solo se conecta al relay cuando hbbs le reenvía un `RequestRelay`
  autorizado, con un uuid aleatorio que solo conoce el operador autorizado.
* **Host Dienstmotor Remote** (`src/dienstmotor_auth.rs::verify_login_ticket`, ganchos en
  `src/server/connection.rs`): rechaza cualquier login sin ticket válido para su ID. Esto cubre
  también los caminos que no pasan por hbbs (IP directa, LAN) y el cambio de lado.
* **Operador** (`Client::start`): sin sesión, o si no puede renovarla, la conexión falla antes de
  contactar con hbbs. Las conexiones por IP directa, `host:puerto` o `id@otro-servidor` están
  deshabilitadas en el cliente administrado.

Un ticket sirve para **un intento de conexión**. Un intento manda legítimamente varios mensajes con
el mismo ticket (hasta 3 reintentos de punch en dos sockets paralelos y la caída a relay), por eso
hbbs lo acepta repetido solo desde la misma IP de origen y para el mismo destino, como máximo
`TICKET_MAX_USES` veces y hasta su expiración. El host aplica uso único estricto.

## 2. Configuración de Authentik

1. **Providers → Create → OAuth2/OpenID Provider**
   * Name: `dienstmotor-remote`
   * Authorization flow: `default-provider-authorization-explicit-consent` (o implicit)
   * Client type: **Public** (no hay client secret en los escritorios)
   * Redirect URIs: modo **Regex**, valor `^http://127\.0\.0\.1:[0-9]+/callback$`
     (RFC 8252: el puerto del listener loopback es aleatorio)
   * Signing Key: un certificado (p. ej. *authentik Self-signed Certificate*). Es obligatorio:
     la API valida la firma RS256 de los access tokens con el JWKS del provider.
   * Scopes: `openid`, `profile`, `email`, `offline_access` (este último emite refresh tokens)
   * Access token validity: `minutes=10`. Refresh token validity: p. ej. `days=30`.
2. **Applications → Create**: name `Dienstmotor Remote`, slug `dienstmotor-remote`, provider
   anterior. El issuer queda `https://auth.dienstmotor.com/application/o/dienstmotor-remote/`.
3. **Acceso**: en la aplicación, *Policy / Group / User Bindings* → enlazar el grupo de operadores
   (p. ej. `Dienstmotor Remote Operators`). Authentik no emite tokens a usuarios no enlazados.
   Las altas y bajas de operadores se hacen solo aquí.
4. Copiar el *Client ID* del provider a `OIDC_CLIENT_ID`.
5. Opcional: para comprobar revocación por introspección (RFC 7662) en vez de `userinfo`, rellenar
   `OIDC_INTROSPECTION_CLIENT_ID/SECRET` con credenciales que Authentik acepte en
   `/application/o/introspect/`. Sin ellas se usa `userinfo`, que Authentik rechaza para tokens
   revocados o de sesiones terminadas.

## 3. Variables de entorno

`auth-api` (`services/rustdesk/.env.auth`, ver `.env.auth.example`):

| Variable | Obligatoria | Descripción |
|---|---|---|
| `OIDC_ISSUER` | sí | Issuer del provider, con `/` final |
| `OIDC_CLIENT_ID` | sí | Client ID del provider público |
| `OIDC_SCOPES` | no | Scopes que pide el cliente (`openid profile email offline_access`) |
| `OIDC_REQUIRED_SCOPES` | no | Scopes que debe incluir el claim `scope` del access token |
| `OIDC_INTROSPECTION_CLIENT_ID` / `_SECRET` | no | Activan introspección en lugar de userinfo |
| `TICKET_SIGNING_KEY` | sí | Semilla Ed25519 en base64 (`scripts/gen_ticket_key.py`). **Secreta** |
| `TICKET_ISSUER` | no | `https://remote-api.dienstmotor.com`; debe coincidir con `AUTH_API_URL` del cliente |
| `TICKET_TTL_SECONDS` | no | Vida del ticket (60) |
| `TICKET_MAX_USES` | no | Usos por intento en hbbs (16) |
| `TICKET_BIND_SOURCE_IP` | no | Ata el ticket a la IP del primer uso (`true`) |
| `INTERNAL_API_TOKEN` | sí | Credencial de servicio hbbs → API (≥ 32 caracteres) |
| `RATE_LIMIT_PER_MINUTE` | no | Peticiones por IP y minuto en `/auth/*` (60) |
| `TRUSTED_PROXIES` | no | Redes desde las que se acepta `X-Real-IP` |
| `HTTP_TIMEOUT_SECONDS`, `LOG_LEVEL` | no | Timeout hacia Authentik (5), nivel de log |

hbbs: `DM_AUTH_URL` (`http://127.0.0.1:8000/internal/authorize`) y `DM_AUTH_TOKEN`
(= `INTERNAL_API_TOKEN`). Si faltan, hbbs rechaza todas las conexiones nuevas.

Compose (`services/rustdesk/.env`): `DM_VERSION` (tag de imagen) e `INTERNAL_API_TOKEN`.

Cliente (`src/branding.rs`): `AUTH_API_URL` y `DM_TICKET_PUBKEYS` (clave pública del ticket).

## 4. Despliegue

El orden evita cortar el servicio: **API → clientes → hbbs**. Un cliente nuevo funciona con el hbbs
de upstream (que ignora el ticket), pero un hbbs nuevo rechaza a los clientes antiguos.

1. **Claves**
   ```sh
   python3 dienstmotor/auth-api/scripts/gen_ticket_key.py   # requiere `cryptography`
   openssl rand -hex 32                                      # INTERNAL_API_TOKEN
   ```
   `TICKET_SIGNING_KEY` va solo a `.env.auth`. La clave pública va a `DM_TICKET_PUBKEYS` en
   `src/branding.rs` del cliente. Las claves `id_ed25519` de hbbs **no se tocan**.
2. **Imágenes**: `git tag dm-v1.1.17-auth1 && git push origin dm-v1.1.17-auth1` en este repo. El
   workflow *Dienstmotor images* pasa las pruebas y publica
   `ghcr.io/dienstmotor/{dm-hbbs,dm-hbbr,dm-remote-auth-api}:v1.1.17-auth1`. Si los paquetes de
   GHCR son privados, `docker login ghcr.io` en el servidor con un token `read:packages`.
3. **DNS y TLS**: registro A/AAAA `remote-api.dienstmotor.com`. Comprobar que el certificado de
   `/etc/letsencrypt/live/dienstmotor.com/` cubre el nombre (si no es comodín:
   `certbot --expand -d ... -d remote-api.dienstmotor.com`).
4. **Nginx**: copiar `services/nginx/remote-api.dienstmotor.com` a `sites-available`, enlazarlo en
   `sites-enabled`, `nginx -t && systemctl reload nginx`.
5. **API**: en `services/rustdesk/` crear `.env` y `.env.auth` desde los `.example` y arrancar solo la
   API: `docker compose -f docker-compose.dienstmotor-auth.yaml up -d auth-api`.
   Comprobar: `curl https://remote-api.dienstmotor.com/health` y
   `curl -i https://remote-api.dienstmotor.com/internal/authorize` (debe dar 404).
6. **Clientes**: lanzar *Dienstmotor Build* en el repo del cliente (ver §5) e instalar la versión
   nueva en operadores **y** en los equipos receptores.
7. **hbbs/hbbr**: `docker compose -f docker-compose.dienstmotor-auth.yaml up -d`. Mismo `./data`,
   mismos nombres de contenedor, `network_mode: host` como antes.

## 5. GitHub Actions

* **Cliente, *Dienstmotor Build*** (`workflow_dispatch`): el nuevo job `preflight` falla si
  `DM_TICKET_PUBKEYS` aún tiene la clave de ejemplo. Un cliente así rechazaría todas las conexiones
  entrantes. Después compila con `flutter-build.yml` como antes. La codegen del bridge en CI
  genera los wrappers Dart de `main_dm_auth_*`. La publicación como `dienstmotor-remote-*` no cambia.
* **Servidor, *Dienstmotor images*** (`.github/workflows/dienstmotor-images.yml`): en PR y
  `workflow_dispatch` solo ejecuta las pruebas. Con un tag `dm-v*` (o `workflow_dispatch` con
  `publish`) publica las tres imágenes. No despliega nada: producción fija `DM_VERSION`.

Versionado: el formato de ticket es `dm1`. Las imágenes `*-auth1` y los clientes que incluyen
`src/dienstmotor_auth.rs` hablan `dm1`. Un cambio incompatible del ticket debe subir ambos a `dm2`/`auth2`.

## 6. Pruebas

Automáticas:

| Suite | Comando | Cubre |
|---|---|---|
| hbbs unit (`src/dm_auth.rs`) | `cargo test --bin hbbs --lib` | sin ticket, ticket aceptado/rechazado, API caída o 5xx → rechazo |
| API (`tests/test_auth_api.py`) | `pytest tests/test_auth_api.py` | sin login, login válido, token falsificado/expirado/otra app/otro issuer, revocado, IdP caído, IDs no válidos, tickets falsificados/manipulados/de otro equipo, replay, credenciales internas |
| E2E protocolo (`tests/test_e2e_hbbs.py`) | `HBBS_BIN=target/release/hbbs pytest tests/test_e2e_hbbs.py` | hbbs real + API real por TCP/UDP: lo que llega al host con y sin ticket, punch y relay, replay desde otra IP, API caída |
| Cliente (`src/dienstmotor_auth.rs`) | `cargo test --lib dienstmotor_auth` | verificación en host: ticket válido, reintento en la misma conexión, replay en otra, sin ticket, falsificado, otro ID, expirado, manipulado; callback loopback y PKCE (vector RFC 7636) |

Escenarios de aceptación:

| Escenario | Esperado | Dónde se comprueba |
|---|---|---|
| Operador sin login intenta conectarse | Rechazado | cliente (`MSG_LOGIN_REQUIRED`), API 401, E2E sin ticket |
| Operador con login válido | Permitido | API + E2E `authorized_operator_reaches_host` |
| Token expirado antes de conectar | Rechazado si no se renueva | API (expirado) + cliente (`fetch_ticket` → refresh → `MSG_SESSION_EXPIRED`) |
| Token falsificado | Rechazado | API (`invalid_access_tokens`) |
| Cliente oficial sin autenticación | Rechazado | E2E `official_client_without_ticket_is_refused`, host (sin ticket) |
| Backend caído antes de conectar | Rechazado | E2E `auth_api_down_fails_closed`, hbbs unit |
| Usuario pierde sesión Authentik | Rechazado | API (`revoked_or_logged_out`) |
| Sesión establecida y vence/revoca/cae access token, refresh token, logout, FastAPI, Authentik, ticket | Continúa | por construcción: ni hbbs, ni hbbr, ni el host consultan nada tras el login. Manual abajo |
| Se desconecta y el token ya venció | Nueva conexión rechazada | `Client::start` siempre pide ticket nuevo |
| Atacante reutiliza ticket | Rechazado | E2E replay, API replay, host `ticket already used` |
| Relay sin autorización | Rechazado | E2E `relay_requires_ticket` |
| Conexión directa no autorizada | Rechazado | host (`verify_login_ticket` en todo LoginRequest), cliente bloquea IP directa |
| Receptor sin login | Recibe sesión autorizada | el host solo verifica la firma, no necesita sesión (E2E: host falso sin login) |

Pruebas manuales (con dos equipos A=operador, B=receptor, ambos con la versión nueva):

1. A sin sesión: el botón *Conectar* está deshabilitado y aparece “Iniciar sesión con Dienstmotor”.
2. Iniciar sesión → se abre el navegador → Authentik → la página “Sesión iniciada” → A muestra el
   usuario. Conectar a B: funciona. B no tiene sesión.
3. Con la sesión A→B abierta: *Cerrar sesión* en A, revocar tokens en Authentik
   (*Directory → Tokens*), `docker stop dienstmotor-auth-api`, parar Authentik. La sesión sigue
   (pantalla, teclado, transferencia). Abrir una conexión nueva falla con “servicio no disponible”
   o “inicia sesión”.
4. Con la API de nuevo arriba y A sin sesión, cortar la red de B unos segundos: la reconexión
   automática falla con “inicia sesión”.
5. Desde un RustDesk oficial configurado con `remote.dienstmotor.com` y la clave del servidor:
   conectar a B → “Dienstmotor: sign in to start a connection”. Con IP directa (si B tiene
   *direct IP access* activado) → B responde “this device only accepts connections from
   signed-in Dienstmotor operators”.
6. Esperar a que caduque el access token (10 min) sin cerrar la app y abrir una conexión nueva:
   se renueva sola. Borrar el refresh token en Authentik y repetir: pide iniciar sesión.

## 7. Limitaciones de seguridad conocidas

1. **Ticket sin cifrar hasta hbbs.** hbbs OSS no implementa el intercambio de claves TCP de Pro, así
   que el `PunchHoleRequest` (y el ticket) viajan en claro, como todo el tráfico de rendezvous OSS.
   El cliente no intenta `secure_tcp` con un ticket (`wants_secure_tcp`), porque se quedaría
   esperando hasta el timeout. Mitigación: 60 s de vida, atado a IP de origen y destino en hbbs, uso
   único estricto en el host (la conexión legítima lo consume en milisegundos) y transporte
   extremo a extremo cifrado hacia el host. Quien lo capture necesita además salir por la misma IP
   pública en esos 60 s.
2. **Hosts con RustDesk oficial o versiones anteriores de Dienstmotor Remote** registrados en
   nuestro hbbs solo están protegidos por hbbs. Si tienen *acceso directo por IP* activado o un
   atacante está en su misma LAN, se puede conectar sin pasar por hbbs (con la contraseña del
   host). Solo los hosts con la versión nueva validan el ticket por sí mismos.
3. El registro de replay vive en memoria de un único proceso (`--workers 1`). Un reinicio de la API
   lo vacía; la ventana de reutilización en hbbs queda acotada por la vida del ticket.
4. `TICKET_BIND_SOURCE_IP`: un cliente de doble pila que use IPv4 para el punch e IPv6 para el relay
   sería rechazado. Si ocurre, poner `false`; el host sigue imponiendo uso único.
5. Revocar en Authentik no invalida un ticket ya emitido (≤ 60 s, solo para una conexión nueva).
6. *Cambio de lado* exige que ambos lados tengan sesión. El cliente Web no está soportado.
7. Consultas de presencia (`OnlineRequest`) y el registro de IDs siguen abiertos, como en upstream.
   hbbr sigue siendo un relay sin autenticación propia, igual que antes, aunque no puede llegar a
   un host sin autorización de hbbs.
8. Almacenamiento de tokens: DPAPI del usuario en Windows; en Linux, un archivo `0600` en el
   directorio de configuración (no se usa el llavero del escritorio).
9. Cerrar sesión revoca los tokens, pero no la sesión SSO del navegador en Authentik: el siguiente
   login puede no pedir contraseña.
10. Rotar la clave de tickets requiere publicar primero un cliente con la clave nueva añadida a
    `DM_TICKET_PUBKEYS`. Un host con el reloj desviado más de 5 min rechaza los tickets.
11. Un operador con sesión puede conectarse a cualquier ID (no hay permisos por equipo, por diseño).
12. Preexistente, no relacionado: `services/rustdesk/data/id_ed25519` (clave privada de hbbs) y
    varios `.env` están versionados en `dienstmotor/services`. Conviene mantener ese repositorio
    privado. No se regenera la clave porque rompería los clientes desplegados.

## 8. Rollback

* **Servidor**: `docker compose -f docker-compose.yaml up -d` en `services/rustdesk` vuelve a las
  imágenes upstream con el mismo `./data`. La API puede seguir en marcha.
* **Clientes**: reinstalar la release anterior. Mientras queden hosts con la versión nueva, la API
  debe seguir disponible: esos hosts exigen ticket, aunque hbbs ya no lo haga.
* **Nginx**: quitar el enlace de `sites-enabled/remote-api.dienstmotor.com` y recargar.
* **Código**: los cambios están en commits propios (`git revert`). En el cliente, `branding.rs`
  conserva `RENDEZVOUS_SERVER` y `RS_PUB_KEY`.
