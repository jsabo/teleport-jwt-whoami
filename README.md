# jwt-whoami

A small Flask app that shows what Teleport hands an application on every request:
the `Teleport-Jwt-Assertion` header, a signed JSON Web Token (JWT) that names the
person who cleared Teleport, their roles and their traits. The app verifies that
token against the cluster's published signing keys and renders every claim, every
check it ran, and every other header the request arrived with. A request that did
not come through Teleport gets the same page with status 401 and an explanation.

Verified against Teleport 18.11.3 (Cloud).

## What it shows

```
VERIFIED        pc3ai.teleport.sh signed this token for alice and it is valid right now.

WHO I AM        alice                      roles  access  editor  developer-environment-access
                trait logins   alice, ubuntu
                trait groups   engineering

THE HEADER,     header present   ok   Teleport-Jwt-Assertion, 812 characters
VERIFIED        signature        ok   RS256 with key id 8f2d… from https://pc3ai.teleport.sh/.well-known/jwks.json
                issuer           ok   iss = 'pc3ai.teleport.sh', expected 'pc3ai.teleport.sh'
                audience         ok   aud = ['http://jwt-whoami:8080'], expected to contain 'http://jwt-whoami:8080'
                not expired      ok   exp = 2026-10-11 23:14:02Z, 3587 s left
                not before       ok   nbf = 2026-10-11 22:14:02Z

THE TOKEN       {"alg": "RS256", "kid": "8f2d…", "typ": "JWT"}
                {"aud": [...], "exp": ..., "iss": "pc3ai.teleport.sh", "nbf": ..., "sub": "alice",
                 "username": "alice", "roles": [...], "traits": {...}}

EVERYTHING      Host, X-Forwarded-For, X-Forwarded-Host, X-Forwarded-Proto, User-Agent, ...
ELSE SENT
```

The same page reached by `curl` straight at the container, with no Teleport in the
path, reads `REFUSED: no token` and returns 401.

Terms, defined once. A **JWT** (JSON Web Token) is a signed, base64-encoded JSON
document; the fields inside it are **claims**. The **issuer** (`iss`) is who signed
it, here the Teleport cluster name. The **audience** (`aud`) is who it was signed
for, here the application's URI as registered in Teleport. A **JWKS** (JSON Web Key
Set) is the issuer's list of public keys, published at a URL so anyone can verify
its signatures without sharing a secret. The **Teleport application service** is
the agent that proxies requests to the application and adds the header.

## How a request flows

```
 browser / tsh ──► Teleport proxy ──► application service ──► this app
                   authenticates      mints a JWT for this        verifies the JWT against
                   the user, checks   request, signed by the      https://<cluster>/.well-known/jwks.json
                   role access        cluster's JWT signer CA,    and renders the page
                                      adds Teleport-Jwt-Assertion
```

1. The user opens the application through Teleport (the Web UI tile, or
   `tsh app login`). Teleport authenticates them and checks that a role allows the
   application.
2. When an app session first reaches the application service, it asks the Auth
   Service for a JWT: `sub` and `username` are the Teleport username, `roles` and
   `traits` are the user's, `iss` is the cluster name, `aud` is the application's
   `uri`, and `exp` is the session's expiry. The Auth Service signs it with the
   cluster's JWT signer certificate authority. The service keeps the token with
   the session and puts it in the `Teleport-Jwt-Assertion` header of every
   request it forwards for that session, so the `jti` stays the same across
   requests until the session ends.
3. This app fetches the cluster's JWKS once (cached, refreshed when it sees an
   unknown key id), verifies the signature, then checks issuer, audience, expiry
   and not-before. Only then does it show the identity as trusted.

The token is also what Teleport's `{{internal.jwt}}` template variable expands to
in a header rewrite rule, so the app accepts `Authorization: Bearer <token>` as well.

## Run it

Locally, pointed at your cluster:

```bash
docker run --rm -p 8080:8080 -e TELEPORT_PROXY=example.teleport.sh ghcr.io/jsabo/teleport-jwt-whoami:main
curl -i http://localhost:8080/            # 401, "no token": nothing came through Teleport
curl -s http://localhost:8080/healthz     # ok
```

Or from source:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
TELEPORT_PROXY=example.teleport.sh .venv/bin/python app.py
```

### Register it as a Teleport application

Run the container somewhere a Teleport application service can reach it, then
register the application. The `uri` is what the service connects to and what ends
up in the token's `aud` claim, so set `EXPECTED_AUDIENCE` on the container to the
same value.

```yaml
kind: app
version: v3
metadata:
  name: jwt-whoami
  description: Shows and verifies the JWT Teleport adds to every forwarded request
  labels:
    env: demo
spec:
  uri: http://jwt-whoami:8080
  # Optional. roles-and-traits is the default; roles, traits or none trim the token.
  rewrite:
    jwt_claims: roles-and-traits
```

```bash
tctl create jwt-whoami.yaml
```

The application service needs an `app_service` selector that matches the label, or
a static `apps:` entry with the same `uri`. No header rewrite is required: the
`Teleport-Jwt-Assertion` header is added to every HTTP application.

### Verify from the command line

```bash
tsh app login jwt-whoami
eval "$(tsh app config --format=curl jwt-whoami)"/whoami.json
```

The JSON has `"verified": true`, the `identity` block, and one entry per check.
Change `jwt_claims` to `none` on the application resource, then start a new app
session (`tsh app logout jwt-whoami && tsh app login jwt-whoami`, or sign out of
the tile and open it again): the identity block loses its roles and traits with no
change to the app, because the token itself changed. An existing session keeps its
token until it ends.

## What the app refuses, and why

| Check | Fails when | What it means |
|---|---|---|
| header present | the request did not pass through a Teleport application service | nothing to verify; the page explains that instead of guessing |
| signature | the token was signed by a key not in the JWKS, or was altered | a different cluster, a forged token, or a stale key cache (refreshed automatically on an unknown key id) |
| issuer | `iss` is not `EXPECTED_ISSUER` | the token is from another cluster, or the proxy address you configured is not the cluster name |
| audience | `aud` does not contain `EXPECTED_AUDIENCE` | the token was minted for a different application `uri` |
| not expired | `exp` is in the past, beyond 30 s of leeway | the Teleport session ended; the user has to log in again |
| not before | `nbf` is in the future, beyond 30 s of leeway | clock skew between the cluster and this host |

A refused request still shows the token's claims, marked unverified, so the reason
is visible rather than hidden behind a bare error.

## Configuration

| Variable | Meaning | Default |
|---|---|---|
| `TELEPORT_PROXY` | the cluster's proxy address, for example `example.teleport.sh` | required |
| `JWKS_URL` | where to fetch the signing keys | `https://<TELEPORT_PROXY>/.well-known/jwks.json` |
| `EXPECTED_ISSUER` | the value `iss` must equal | `TELEPORT_PROXY` without a port |
| `EXPECTED_AUDIENCE` | the value `aud` must contain, the application's registered `uri` | unset: shown but not checked |
| `PORT` | listen port | `8080` |

Endpoints: `/` (the page), `/whoami.json` (the same data, without the raw token),
`/healthz` (always 200, no token check).

## Troubleshooting

- **issuer refused, and the cluster name is not the proxy address.** `iss` is the
  cluster name, which can differ from the address you reach the proxy on. Set
  `EXPECTED_ISSUER` to the cluster name shown by `tsh status`.
- **audience refused.** `aud` is exactly the `uri` in the application resource,
  scheme and port included. Set `EXPECTED_AUDIENCE` to that string, or leave it unset
  to display without checking.
- **signature refused on a cluster that just rotated its CA.** The JWKS cache lives
  five minutes; an unknown key id triggers a refresh. Rotation of the JWT signer CA
  changes the key id, so the next request after rotation refreshes the keys.
- **not before refused.** The host running this app is behind the cluster's clock
  by more than 30 s. Fix the host's time sync.

## Files

| File | What it is |
|---|---|
| `app.py` | The whole app: token lookup, JWKS verification, the checks, three routes |
| `templates/index.html` | The page, styled with the Teleport Web UI's colour tokens |
| `Dockerfile` | `python:3.12-slim`, non-root, gunicorn on port 8080 |
| `.github/workflows/image.yml` | Builds and pushes `ghcr.io/jsabo/teleport-jwt-whoami` for amd64 and arm64 |

## License

Apache-2.0.
