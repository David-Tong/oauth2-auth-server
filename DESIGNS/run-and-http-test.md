# Run locally and test over HTTP

Run commands from the repository root. This walkthrough uses PowerShell and
Java 17+ with Maven on `PATH`. It exercises the real server without needing the
separate login webapp. HTTP redirects are inspected rather than followed into
the unimplemented `/app/login` and `/app/callback` pages.

## 1. Build and prepare a local user

```powershell
java -version
mvn -version
mvn clean verify
```

Generate a bcrypt hash in an interactive terminal (the utility needs a console):

```powershell
java '-Dloader.main=io.ytong.authserver.tools.PasswordHash' -cp target/oauth2-auth-server-0.0.1-SNAPSHOT.jar org.springframework.boot.loader.launch.PropertiesLauncher
```

Enter the same local test password twice. Copy the full printed `{bcrypt}...`
value. Passwords must contain 1–72 UTF-8 bytes and no NUL character.

Create the local directory file only if it does not already exist:

```powershell
if (-not (Test-Path -LiteralPath config/users.json)) {
    Copy-Item config/users.example.json config/users.json
}
```

Edit `config/users.json`, replacing the placeholder `passwordHash` with the
generated value. Keep the example username `alice`, ID `user-001`,
`enabled: true`, and role `USER` for the expected responses below. Do not commit
this local credential file. Existing users need not be replaced; adjust the
username and expected identity below if using another account.

## 2. Start the server

In terminal A:

```powershell
java -jar target/oauth2-auth-server-0.0.1-SNAPSHOT.jar --spring.profiles.active=dev
```

Alternatively, use `mvn spring-boot:run '-Dspring-boot.run.profiles=dev'`.
Wait for the application-started message. The server uses
`http://localhost:9000`; dev enables an ephemeral RSA key and cookies suitable
for local HTTP. User data is still required. Keep terminal A running.

Restart after changing the user file. Restart clears sessions and grants; dev
also replaces the signing key. Use the README's production keystore instructions
for deployments outside local development.

## 3. Set up an HTTP client

Run the remaining blocks in order in terminal B, using the same PowerShell
session. This helper preserves cookies, returns HTTP error responses for
inspection, and disables automatic redirects. It works with Windows PowerShell
5.1 and PowerShell 7.

```powershell
Add-Type -AssemblyName System.Net.Http
$base = 'http://localhost:9000'
$handler = [System.Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $false
$handler.CookieContainer = [System.Net.CookieContainer]::new()
$client = [System.Net.Http.HttpClient]::new($handler)

function Send-Http {
    param(
        [string]$Method,
        [string]$Path,
        [string]$Body,
        [string]$ContentType = 'application/json',
        [hashtable]$Headers = @{}
    )
    $request = [System.Net.Http.HttpRequestMessage]::new(
        [System.Net.Http.HttpMethod]::new($Method), "$base$Path")
    foreach ($name in $Headers.Keys) {
        $null = $request.Headers.TryAddWithoutValidation($name, [string]$Headers[$name])
    }
    if ($PSBoundParameters.ContainsKey('Body')) {
        $request.Content = [System.Net.Http.StringContent]::new(
            $Body, [System.Text.Encoding]::UTF8, $ContentType)
    }
    $response = $client.SendAsync($request).GetAwaiter().GetResult()
    try {
        [pscustomobject]@{
            Status = [int]$response.StatusCode
            Location = [string]$response.Headers.Location
            Body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        }
    } finally {
        $response.Dispose()
        $request.Dispose()
    }
}

function Encode([string]$Value) { [uri]::EscapeDataString($Value) }
```

## 4. Check public endpoints and an anonymous session

```powershell
Send-Http GET '/.well-known/oauth-authorization-server'
Send-Http GET '/oauth2/jwks'
Send-Http GET '/api/auth/session'
```

Expect 200 metadata with issuer `http://localhost:9000`, 200 public RSA JWKS,
and 401 `unauthorized` for the anonymous session. JWKS must not expose private
RSA parameters. Discovery is OAuth2 metadata; OIDC is not enabled.

## 5. Start authorization before login

Generate a fresh PKCE verifier, S256 challenge, and state:

```powershell
$random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object byte[] 32
$random.GetBytes($bytes)
$random.Dispose()
$verifier = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
$sha = [System.Security.Cryptography.SHA256]::Create()
$challenge = [Convert]::ToBase64String(
    $sha.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($verifier))
).TrimEnd('=').Replace('+', '-').Replace('/', '_')
$sha.Dispose()
$state = [guid]::NewGuid().ToString('N')
$redirectUri = "$base/app/callback"
$authorizePath = '/oauth2/authorize?response_type=code&client_id=webapp' +
    '&redirect_uri=' + (Encode $redirectUri) + '&scope=demo.read' +
    '&state=' + $state + '&code_challenge=' + $challenge +
    '&code_challenge_method=S256'

$authorization = Send-Http GET $authorizePath
$authorization
```

Expect 302 with `Location: /app/login`. The cookie container now holds the
session containing the pending request. Do not follow that location: this
repository does not serve a login page. The continuation expires in five minutes;
a newer authorization request in this session replaces it.

## 6. Fetch CSRF and log in

```powershell
$csrf = (Send-Http GET '/api/auth/csrf').Body | ConvertFrom-Json
$csrfHeaders = @{}
$csrfHeaders[$csrf.headerName] = $csrf.token
$credential = Get-Credential -UserName alice -Message 'Enter the local test password'
$loginBody = @{
    username = $credential.UserName
    password = $credential.GetNetworkCredential().Password
} | ConvertTo-Json -Compress
$loginResult = Send-Http POST '/api/auth/login' -Body $loginBody -Headers $csrfHeaders
$loginBody = $null
$credential = $null
$loginResult
$login = $loginResult.Body | ConvertFrom-Json
Send-Http GET '/api/auth/session'
```

Expect login 200 with `user.id: user-001`, `user.username: alice`, and a
`continueUrl` beginning `/api/auth/continue?id=`. Session inspection returns
200 with that identity. The server rotates the session ID; the cookie container
keeps the updated cookie. Login without step 5 instead returns
`continueUrl: null`. Login does not issue an access token.

## 7. Resume authorization and capture the code

```powershell
$continuation = Send-Http GET $login.continueUrl
$continuation
$callback = Send-Http GET $continuation.Location
$callback

# Parse the callback Location without requesting the webapp page.
$callbackUri = [uri]$callback.Location
if ($callbackUri.GetLeftPart([System.UriPartial]::Path) -ne $redirectUri) {
    throw 'Unexpected callback URI'
}
$parameters = @{}
foreach ($pair in $callbackUri.Query.TrimStart('?').Split('&')) {
    $parts = $pair.Split('=', 2)
    $parameters[[uri]::UnescapeDataString($parts[0])] =
        [uri]::UnescapeDataString($parts[1].Replace('+', ' '))
}
if ($parameters['state'] -ne $state) { throw 'OAuth state mismatch' }
$code = $parameters['code']
if (-not $code) { throw 'No authorization code returned' }
```

Expect two 302 responses: first to the saved `/oauth2/authorize?...` URL, then
to the exact registered callback with `code` and the original `state`.
The continuation is single-use. The authorization code expires in 60 seconds;
perform the next step promptly.

## 8. Exchange the code for a token

```powershell
$tokenBody = 'grant_type=authorization_code&client_id=webapp' +
    '&redirect_uri=' + (Encode $redirectUri) + '&code=' + (Encode $code) +
    '&code_verifier=' + (Encode $verifier)
$tokenResult = Send-Http POST '/oauth2/token' -Body $tokenBody `
    -ContentType 'application/x-www-form-urlencoded'
$tokenResult
$tokens = $tokenResult.Body | ConvertFrom-Json
```

Expect 200 with `access_token`, `token_type: Bearer`, scope `demo.read`, and
approximately 300 seconds of validity. No refresh token is issued. `webapp` is a
public client; do not send a client secret or user password to this endpoint.

To inspect the JWT payload locally:

```powershell
$payload = $tokens.access_token.Split('.')[1].Replace('-', '+').Replace('_', '/')
$payload = $payload.PadRight($payload.Length + ((4 - $payload.Length % 4) % 4), '=')
[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) |
    ConvertFrom-Json
```

Expect `sub: user-001`, issuer `http://localhost:9000`, audience `demo-api`,
`client_id: webapp`, granted scope, and time claims. Decoding is inspection only;
it does not verify the signature. A separate resource server must validate the
signature against JWKS, issuer, audience, expiry, and required scope. This app
does not expose a demo bearer-protected business API. Automated integration tests
also verify the JWT signature using its published public key.

## 9. Log out with a fresh CSRF token

```powershell
$csrf = (Send-Http GET '/api/auth/csrf').Body | ConvertFrom-Json
$csrfHeaders = @{}
$csrfHeaders[$csrf.headerName] = $csrf.token
Send-Http POST '/api/auth/logout' -Headers $csrfHeaders
Send-Http GET '/api/auth/session'
```

Expect 204, then 401. The CSRF token from before login is no longer valid.
Logout ends the browser session; an issued JWT can remain valid at a resource
server until its expiry.

## 10. Negative HTTP checks

Run these after the successful flow. For code replay, run the check only when
the earlier code has already been successfully exchanged; replay handling may
invalidate the server-side authorization associated with that code.

```powershell
# Reuse an already consumed continuation: authenticated session required.
# Run before logout if testing this case: expect 400 authorization_expired.
# Send-Http GET $login.continueUrl

# Code replay: expect 400 OAuth error.
Send-Http POST '/oauth2/token' -Body $tokenBody `
    -ContentType 'application/x-www-form-urlencoded'

# Missing CSRF: expect 403 forbidden, before credential validation.
Send-Http POST '/api/auth/login' -Body '{"username":"alice","password":"wrong"}'

# Valid CSRF plus bad credentials: expect 401 invalid_credentials.
$csrf = (Send-Http GET '/api/auth/csrf').Body | ConvertFrom-Json
$csrfHeaders = @{}
$csrfHeaders[$csrf.headerName] = $csrf.token
Send-Http POST '/api/auth/login' -Headers $csrfHeaders `
    -Body '{"username":"alice","password":"wrong"}'

# Malformed login schema: expect 400 invalid_request.
Send-Http POST '/api/auth/login' -Headers $csrfHeaders -Body '{}'

# Unregistered redirect: expect 400 with no Location header.
Send-Http GET ($authorizePath.Replace((Encode $redirectUri), (Encode 'https://attacker.example/callback')))

# Plain PKCE: expect 400.
Send-Http GET ($authorizePath.Replace('code_challenge_method=S256', 'code_challenge_method=plain'))

# Introspection without confidential-client authentication: expect 401.
Send-Http POST '/oauth2/introspect' -ContentType 'application/x-www-form-urlencoded' -Body 'token=fake'
```

The default public client cannot authenticate to introspection/revocation.
For successful calls, configure a confidential client with a bcrypt secret hash
and obtain its token using that client's own code flow. The existing
`AuthServerIntegrationTests.confidentialClientAuthenticatesAndCanIntrospectAndRevoke`
test covers that scenario with test-only client configuration.

## Troubleshooting and cleanup

| Symptom | Check |
| --- | --- |
| Startup reports invalid user directory | File exists, placeholder hash replaced, strict schema valid, roles match configured policy |
| Startup requires keystore/password | Activate `dev` for this local walkthrough |
| Cannot connect | Server started, port 9000 free, terminal A still running |
| Login 403 | Fetch CSRF with this same client/cookie container and send its named header |
| Login 401 | Username/password correct, user enabled, server restarted after user-file changes |
| Login 429 | Account limit is 10 attempts/minute; source limit is 60/minute, including successful attempts; wait at least 60 seconds |
| Continuation 400 | Flow expired, replaced, consumed, or belongs to another session; start again at step 5 |
| Token exchange 400 | Code expired/used, verifier differs, or redirect/client does not match; obtain a fresh code |
| `/app/login` or `/app/callback` fails | Those routes belong to the separate webapp; inspect redirects without following them |

Dispose the HTTP client after finishing:

```powershell
$client.Dispose()
$tokens = $null
$tokenBody = $null
$verifier = $null
```

Stop the server with Ctrl+C in terminal A. Clearing variables is cleanup, not a
guarantee of memory erasure. Keep token responses and local credentials out of
shared terminal transcripts.
