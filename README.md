# oauth2-auth-server

Spring Boot 4 / Java 17 OAuth2 authorization server, built with Maven. A separate
webapp supplies the login UI and calls the JSON authentication API. Users live in
an external JSON file containing bcrypt password hashes.

The server supports Authorization Code with S256 PKCE, signed JWT access tokens,
OAuth2 metadata, JWKS, introspection, and revocation. See the
[design document](DESIGNS/oauth2-auth-server.md) for the architecture and sequence.

## Build and test

Install JDK 17+ and Maven, then run:

```shell
mvn clean verify
```

Tests create temporary user directories and signing keys. No local credentials
or running external services are required.

## Configure users

Copy `config/users.example.json` to `config/users.json`. Generate a password hash
offline from an interactive terminal after building:

```shell
java -Dloader.main=io.ytong.authserver.tools.PasswordHash -cp target/oauth2-auth-server-0.0.1-SNAPSHOT.jar org.springframework.boot.loader.launch.PropertiesLauncher
```

The utility prompts twice without echoing the password. Replace the example
`passwordHash` with the complete printed `{bcrypt}...` value. Passwords must fit
within bcrypt's 72-byte UTF-8 limit. Hashes with cost 10–16 are accepted; the
utility generates cost 12. Never commit actual user files or signing keys.

Users require a unique immutable `id`, unique case-sensitive `username`, an
`enabled` boolean, and a `roles` array. The default role is `USER`, which permits
`demo.read`. The file is validated and loaded once at startup; replacing it
requires a restart. Invalid or missing user files prevent startup.

## Run locally

```shell
mvn spring-boot:run -Dspring-boot.run.profiles=dev
```

The server listens at `http://localhost:9000`. The explicit `dev` profile enables
an ephemeral signing key and non-Secure cookies for local HTTP. The default
registered public client is `webapp`, with the exact redirect URI
`http://localhost:9000/app/callback` and scope `demo.read`.

Serve your webapp's `/app/**` routes through a reverse proxy on the same public
origin. Route `/api/auth/**`, `/oauth2/**`, and `/.well-known/**` to this server.
The configured login route is `/app/login`; this repository supplies the server
APIs and does not serve that page.

## Webapp integration

1. Generate a random OAuth2 `state`, a PKCE verifier, and its base64url SHA-256
   challenge. Keep `state` and the verifier across browser navigation.
2. Navigate to `/oauth2/authorize` with `response_type=code`, `client_id=webapp`,
   the registered `redirect_uri`, `scope=demo.read`, `state`, `code_challenge`,
   and `code_challenge_method=S256`.
3. An unauthenticated browser is redirected to `/app/login`. Fetch
   `GET /api/auth/csrf` with cookies included; the response contains `token` and
   `headerName`.
4. Submit credentials with cookies and that CSRF header:

   ```javascript
   const csrf = await fetch('/api/auth/csrf', { credentials: 'same-origin' })
     .then(response => response.json());
   const response = await fetch('/api/auth/login', {
     method: 'POST',
     credentials: 'same-origin',
     headers: { 'Content-Type': 'application/json', [csrf.headerName]: csrf.token },
     body: JSON.stringify({ username, password })
   });
   const result = await response.json();
   if (!response.ok) throw new Error(result.error);
   if (result.continueUrl) window.location.assign(result.continueUrl);
   ```

5. The server resumes authorization and redirects to the registered callback
   with `code` and `state`. Verify `state`, then POST a form-encoded request to
   `/oauth2/token` containing `grant_type=authorization_code`, `client_id`,
   `redirect_uri`, `code`, and `code_verifier`. Public clients have no secret.
6. Use the returned access token as an API bearer token. The resource server must
   validate signature, issuer, audience `demo-api`, expiry, and scope `demo.read`.

A successful login response is:

```json
{
  "user": { "id": "user-001", "username": "alice" },
  "continueUrl": "/api/auth/continue?id=<server-generated-id>"
}
```

Login without a pending authorization request returns `continueUrl: null`.
Continuations expire after five minutes and can be consumed once. A new pending
request replaces the previous one in the same browser session.

`GET /api/auth/session` returns the authenticated user's ID and username, or
401. For logout, obtain a fresh CSRF token after login and call
`POST /api/auth/logout` with that header and cookies; success returns 204.

Login errors use JSON `{ "error": "...", "message": "..." }`: 400 for malformed
input, 401 for invalid credentials (including disabled/unknown users), 403 for
invalid CSRF, 415 for a non-JSON content type, and 429 for rate limiting.
Login requests are limited to 4 KiB. Rate limits are 10 attempts per username and
60 per source address per minute, held in bounded process memory.

## Deployment configuration

Without `dev`, a PKCS12 keystore and password are required, and session cookies
are Secure. Configure these environment variables:

| Variable | Purpose |
| --- | --- |
| `AUTH_USERS_PATH` | External user file; default `./config/users.json` |
| `AUTH_ISSUER` | Canonical public HTTPS issuer |
| `AUTH_LOGIN_URL` | Webapp login path under `/app/`; default `/app/login` |
| `AUTH_KEYSTORE_PATH` | PKCS12 signing keystore; default `./config/keys/signing.p12` |
| `AUTH_KEYSTORE_PASSWORD` | Keystore/private-key password |
| `AUTH_KEY_ALIAS` | Active RSA key alias; default `signing` |
| `AUTH_COOKIE_SECURE` | Defaults to true outside the local dev profile |

For example, create a signing key after setting `AUTH_KEYSTORE_PASSWORD` securely
in the environment and creating the `config/keys` directory:

```shell
keytool -genkeypair -alias signing -keyalg RSA -keysize 3072 -storetype PKCS12 -keystore config/keys/signing.p12 -storepass:env AUTH_KEYSTORE_PASSWORD -dname "CN=OAuth2 Auth Server" -validity 365
```

Start the packaged server with `java -jar target/oauth2-auth-server-0.0.1-SNAPSHOT.jar`.
Restrict access to the keystore and user file to the service account and operators.

Override `auth.clients` and `auth.role-scopes` in an external Spring configuration
file. Each client specifies `id`, exact `redirect-uris`, and `scopes`. A client
with a `secret-hash` uses `client_secret_basic`; omitting it creates a public
client. Confidential client secrets must also use bcrypt hashes and PKCE. Keep
the entire client list in the external file because Spring replaces lists rather
than merging entries. Never embed a confidential client secret in browser code.

HTTPS is required for non-loopback issuer and redirect URLs. Forwarded headers
are ignored by default. With the shared-origin proxy, preserve paths and route
the webapp separately. Rate limiting uses the direct peer address, so an upstream
proxy should enforce source-address limits before forwarding requests.

For signing-key rotation, use a new unique alias, change `AUTH_KEY_ALIAS`, and
retain retired keys as certificate-only keystore entries. Their public keys stay
in JWKS without being selected for signing. Restart after a keystore change and
retain retired certificates until their access tokens expire, plus clock skew.

## Operational limits

This is a single-instance implementation with in-memory sessions and OAuth2
state. Restarting drops sessions, pending requests, and grants. Access tokens
expire after five minutes; authorization codes after 60 seconds. Logout, user
disablement, and revocation do not immediately invalidate JWTs at APIs using local
signature validation. Authenticated introspection reflects live server state;
durable shared state is needed for persistence across restarts or multiple instances.

Only trusted first-party clients are registered. Refresh tokens, OIDC, interactive
consent, user-management APIs, and password/implicit grants are outside this version.
