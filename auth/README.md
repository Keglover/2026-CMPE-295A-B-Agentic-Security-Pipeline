# Authentication gateway and local identity provider

This folder contains only the server-side authentication needed by Promptrail.
The gateway exposes four endpoints: public `GET /health`, `GET /auth/config`,
`GET /auth/registration`, and protected `GET /auth/whoami`. There are no policy,
evaluation, approval, agent-token or execution routes.

## Files

| File | Responsibility |
| --- | --- |
| `__init__.py` | Server package boundary used by `auth.gateway:app` |
| `gateway.py` | Authentication-only HTTP API; basic access enforcement |
| `oidc.py` | Pinned OIDC discovery, bounded JWKS cache and RS256 verification |
| `setup.py` | Private config generation and opt-in local signup configuration |
| `compose.yml` | Local Keycloak service and persistent named data volume |
| `keycloak-realm.json` | Public client, gateway audience and one basic-access role |
| `env.example` | Local gateway/admin configuration template |
| `requirements.txt` | Authentication server dependencies, separate from the CLI |
| `tests/` | JWT, access enforcement, realm and private setup tests |

## Run locally

Follow the [root quickstart](../CLI_README.md). `setup.py` creates `auth/.env` with
mode 0600 and a generated bootstrap administrator password; existing values are
preserved. The Keycloak administrator is `promptrail-admin`. Use the private
file locally if administrator console access is needed; do not commit or share it.
No fixed user credentials are created. Users register their own accounts after
an administrator opts in:

```bash
.venv/bin/python auth/setup.py --enable-signup
# Restart the gateway process to reload auth/.env.
```

This enables browser registration, grants only `promptrail:access` through the
realm default role and updates the gateway advertisement flag. The script refuses
unexpected default-role grants. It never adds execution/reviewer privileges.
Disable signup without deleting accounts or changing their roles:

```bash
.venv/bin/python auth/setup.py --disable-signup
# Restart the gateway process to reload auth/.env.
```

Keycloak listens on loopback port 8080. Run the gateway separately on loopback
port 8003:

```bash
.venv/bin/python -m uvicorn auth.gateway:app --host 127.0.0.1 --port 8003 --env-file auth/.env
```
Gateway settings are `PROMPTRAIL_AUTH_MODE=required`, `PROMPTRAIL_OIDC_PROVIDER`,
`PROMPTRAIL_OIDC_ISSUER`, `PROMPTRAIL_OIDC_CLIENT_ID`, `PROMPTRAIL_OIDC_AUDIENCE`
and `PROMPTRAIL_SELF_REGISTRATION_ENABLED`. Disabled authentication is rejected.

Access tokens last five minutes; device codes last ten. Assigned provider roles
and requested scopes must both include `promptrail:access`. The gateway checks
signature, issuer, audience, client and expiry before returning identity. Invalid
credentials get a safe reason code; upstream bodies, passwords and tokens are not
echoed. `auth status` performs server verification rather than trusting decoded
JWT text in the CLI. No gateway signing key or model API key is required.

## Existing development installations

The new realm/client/audience are `promptrail`, `promptrail-cli`, and
`promptrail-gateway`. Earlier `jev` realm users are not migrated automatically.
Previous containers/volumes are preserved local historical state. Unused private
credentials and runtime files were moved to the private pre-cleanup recovery
copy outside this project; they are not part of the new implementation. Stop conflicting old services before
starting this Compose project. Do not use `down --volumes` if accounts must survive.
Existing accounts/passwords in a preserved realm survive ordinary restarts.

Keycloak startup import skips an existing realm; changing the JSON file does not
migrate an already imported realm. See [Keycloak realm import](https://www.keycloak.org/server/importExport).
The setup script intentionally updates only enrollment and the safe default role.
A browser can reuse its old SSO identity: use a fresh private context when testing
signup. If a device code expires, rerun the CLI and use its new code. For a VM,
forward both ports and keep the issuer hostname consistent.

## Shared deployment and verification

The loopback `start-dev` configuration is for development. A shared deployment
needs reachable HTTPS URLs, managed identity storage, SMTP/email verification,
enrollment policy and operational ownership. The current gateway supports
Keycloak only. Auth0 server configuration, permissions verification and tenant
setup are deferred to the gateway plan; no Auth0 implementation is kept here.

```bash
.venv/bin/python -m pytest auth/tests -q
```

Tests use real RSA signatures with fake provider metadata and need no live
provider. Browser signup/signin and OS-keyring availability are separate acceptance
checks. Models, sandboxing, structured audit storage and agent sessions are future
work in the maintainer-local `PROMPTRAIL_GATEWAY_PLAN.md` (excluded from this release).

## Function reference

### HTTP API — `gateway.py`

| Function | Called by | Responsibility and result |
| --- | --- | --- |
| `lifespan(app)` | ASGI startup | Validate server configuration before accepting requests; unsupported/disabled auth prevents startup |
| `response_privacy(request, call_next)` | Every HTTP request | Add `Cache-Control: no-store` and `X-Content-Type-Options: nosniff` to responses |
| `health()` | `GET /health` | Report process availability and `authentication` capability; does not check Keycloak availability or authorize execution |
| `configuration()` | `GET /auth/config` | Return public issuer/client/audience/scopes; never the bootstrap password |
| `registration()` | `GET /auth/registration` | Advertise the operator's signup setting; does not enable enrollment in Keycloak |
| `whoami(request)` | `GET /auth/whoami` | Verify a bearer token and require `promptrail:access`; return subject, issuer, audience, provider, permissions and expiry |

`whoami()` runs the blocking verifier in a worker thread so metadata requests
and RSA verification do not block the asynchronous request loop. A missing or
invalid token returns HTTP 401; a verified identity without basic access returns
403; unavailable identity metadata or invalid server configuration returns 503.
Only a safe `reason_code` is returned on these failures. Other paths return 404.

### Token verification — `oidc.py`

| Class/function | Purpose |
| --- | --- |
| `AuthenticationError(code, status=401)` | Carry a safe public code and HTTP status; no raw upstream body |
| `validated_url(value)` | Reject embedded credentials, query/fragment, malformed ports and non-loopback plaintext HTTP |
| `origin(value)` | Normalize scheme/hostname/effective port for origin comparisons |
| `OIDCSettings` / `__post_init__()` | Immutable verification authority; require `required` mode and `keycloak` provider and validate configured identifiers |
| `load_settings()` | Read `PROMPTRAIL_*` server environment settings and local defaults |
| `Identity` | Verified claims and the effective permission set; contains no bearer token |
| `TokenVerifier.__init__(settings, transport, clock)` | Initialize the empty signing-key cache, lock and injectable test dependencies |
| `TokenVerifier._json(url)` | Fetch only the configured issuer origin, with redirects/proxy inheritance disabled, a five-second HTTP timeout and a 1 MiB response limit |
| `TokenVerifier._refresh()` | Check discovery issuer and JWKS URL, accept up to 100 supported public-key entries, reject ambiguous/private signing-key material, then replace the cache |
| `TokenVerifier.verify(token)` | Enforce bounded token/header shape, obtain the trusted key, verify RS256 claims, validate client/subject/timestamps and derive permissions |
| `get_verifier(settings)` | Reuse up to eight verifier instances by immutable settings so requests share key caches |

Verification order is important:

1. An unverified header supplies only the key identifier (`kid`). It does not
   choose the trusted issuer, audience or algorithm.
2. Discovery must match the configured issuer exactly. Its signing-key URL must
   have the same origin. Only supported RSA signing keys are accepted.
3. The verifier checks the signature with RS256 and requires `exp`, `iat`, `iss`,
   `aud` and `sub`. It also checks `azp` against the public CLI client and validates
   subject/timestamp types and ordering.
4. Effective permissions are the intersection of requested token scopes and
   signed `realm_access.roles`. The HTTP handler separately requires basic access.

The cache uses monotonic time, expires after 300 seconds and limits refresh
attempts to one per ten seconds. A lock coordinates concurrent refreshes.
An expired cache cannot bypass a failed refresh. JWT expiry uses wall-clock time
through the JWT library, rather than the cache's monotonic clock.

This is signature-based access-token verification, not a live session/user
lookup. Role changes or browser logout do not make an otherwise valid signed
JWT immediately invalid here; it remains subject to its expiry and these checks.

### Local configuration and enrollment — `setup.py`

| Function | Inputs and effect |
| --- | --- |
| `read_private(path)` | Read an owner-owned regular file with no group/other permissions; refuse symlinks on supported POSIX systems, cap input at 64 KiB and parse without interpolation; return parsed values plus original text |
| `initialize(path=ENV_PATH)` | Preserve existing valid private configuration, or generate a bootstrap password and create `auth/.env` exclusively with mode 0600 |
| `configure(client, headers, enabled=...)` | Contact the fixed local realm admin URL; before enabling signup, verify safe default-role membership and add only `promptrail:access` if absent; preserve other realm settings |
| `configure.call(method, path, ...)` | Internal admin-request helper; accept only expected successful status codes and otherwise stop the setup operation |
| `set_registration(enabled, path=ENV_PATH)` | Read private admin credentials, obtain an in-memory admin token, update the realm, then update the local advertisement flag |
| `main()` | Parse `--enable-signup` / `--disable-signup`, run setup and return 0 or a safe failure exit 2 |

The admin token never goes into the CLI keyring or configuration file. The
script updates the local signup advertisement only after the realm operation
succeeds. Keycloak changes and the file update are separate operations, not a
transaction; on setup failure inspect both settings before retrying. Restart the
gateway after changing its `.env` so it reloads the advertisement value.

## Configuration backbone

| File/field | Why it matters |
| --- | --- |
| `__init__.py` | Defines the server package used by `auth.gateway:app`; never shipped inside the CLI wheel |
| `compose.yml`: loopback port mapping | Makes the development issuer reachable at the exact hostname advertised in tokens/discovery |
| `compose.yml`: `keycloak_data` | Persists realm accounts and passwords across ordinary restarts |
| `compose.yml`: realm bind mount | Imports the public realm template on first creation; does not overwrite an existing realm |
| `keycloak-realm.json`: `promptrail-cli` | Public device-flow client; no client secret and no direct password grant |
| Realm subject/audience/role mappers | Include `sub`, gateway `aud`, and assigned realm roles in access tokens for verification |
| Realm default client scope | Requests `promptrail:access`; actual role assignment is still required |
| Realm token/device lifetimes | Five-minute JWTs and ten-minute device challenges; neither is an agent session |
| `env.example` | Public variable names/defaults used by setup; the generated `auth/.env` is private |
| `requirements.txt` | Server dependencies only; the terminal wheel does not depend on FastAPI, Uvicorn or PyJWT |

The focused test files are `tests/test_gateway.py` (real RSA signatures, cache,
claim/permission failures, HTTP boundaries and missing execution routes) and
`tests/test_setup.py` (private config, stable initialization, safe enrollment and
realm configuration). Test functions are not runtime API entry points.
