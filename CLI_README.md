# Promptrail gateway — CLI and authentication

This `gateway` branch currently provides an independently installable `promptrail`
terminal client and a small authentication gateway. Users can sign up in a browser,
sign in, check verified identity/permissions, and sign out of local credential storage.
The CLI contains no Jev backend and installs only the `promptrail` executable.


For a step-by-step terminal guide, signup/signin explanations and current/future
connection diagrams, see [how_to_run.md](how_to_run.md).

The previous gateway backend has been restored from `a4de267` under `src/mvp/`.
It is retained alongside this standalone CLI/auth implementation. The CLI still
exposes authentication only; it does not yet call the legacy pipeline. See
[src/mvp/README.md](src/mvp/README.md) for that backend.

## Current architecture

```mermaid
sequenceDiagram
    participant U as User browser
    participant C as Promptrail CLI
    participant G as Authentication gateway
    participant I as Keycloak
    C->>G: Get public login configuration
    C->>I: Request device code (public client)
    C-->>U: Display URL and user code; wait
    U->>I: Register or sign in and authorize
    I-->>C: Short-lived access token
    C->>G: Verify token with /auth/whoami
    G->>I: Load pinned discovery and public signing keys
    G-->>C: Verified identity and basic access
    C->>C: Save in OS keyring, or discard with --no-store
```

The gateway verifies RS256 signatures, issuer, audience, authorized client, expiry
and assigned access. Asking for an OAuth scope does not grant a permission.
`promptrail:access` is basic gateway access; it grants no execution capability.
The authentication gateway supports Keycloak only. A CLI Auth0 device-request
adapter remains as a future scaffold; Auth0 server support belongs to the plan.

## Local setup

Use Python 3.11+ and Docker Compose v2 on a maintained Linux development host.
From the project root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e './cli[test]' -r auth/requirements.txt
.venv/bin/python auth/setup.py

docker compose --env-file auth/.env -f auth/compose.yml up -d
# Wait until Keycloak is ready on http://127.0.0.1:8080, then opt in to signup:
.venv/bin/python auth/setup.py --enable-signup

.venv/bin/python -m uvicorn auth.gateway:app --host 127.0.0.1 --port 8003 --env-file auth/.env
```

Keep the gateway terminal running. In another terminal:

```bash
source .venv/bin/activate
export PROMPTRAIL_GATEWAY_URL=http://127.0.0.1:8003
promptrail --version
promptrail doctor
promptrail auth signup --no-store
promptrail auth signin --no-store
```

Open each freshly displayed device URL, choose **Register** for a new account,
and finish browser authorization. Passwords are entered only in Keycloak.
The local realm is `promptrail`; there are no predefined test users/passwords.
Signup is disabled until the administrator explicitly enables it.

For persistent login on a machine with a supported secure OS keyring:

```bash
promptrail auth signin
promptrail auth status
promptrail auth signout
promptrail auth status  # expected: NO_CREDENTIAL, exit 1
```

With `--no-store`, verification still runs against the gateway, but later commands
have no saved login. The local access-token lifetime is five minutes. Sign in
again after expiry; refresh tokens are not stored. Signout clears local storage;
it does not revoke existing JWTs or end browser SSO. Remove any
`PROMPTRAIL_AUTH_TOKEN` environment override separately.

## Install the terminal package

The current local test release is **0.1.0rc3**. If upgrading rc2, first run
`pipx uninstall promptrail-cli` to remove its old command links. Build from this checkout:

```bash
.venv/bin/python -m pip wheel --no-deps --wheel-dir dist ./cli
pipx install ./dist/promptrail_cli-0.1.0rc3-py3-none-any.whl
promptrail --help
```

Old `jev-security-cli` installations must first be removed with
`pipx uninstall jev-security-cli`. Installing the CLI starts no services. Teammates
using a shared deployment need its reachable HTTPS gateway and identity-provider
URLs. Set `PROMPTRAIL_GATEWAY_URL` to the supplied gateway address. Remote HTTP
URLs are rejected. The local Compose service is development-only.

## Test and contribute

```bash
.venv/bin/python -m pytest cli/tests auth/tests -q
.venv/bin/python -m pip check
```

The retained tests cover device flow, signup/signin, cancellation/expiry,
credential storage, bounded HTTP requests, real RSA/JWT verification, permissions,
public configuration and the absence of execution routes. They require no model
API key or running identity provider. Live browser registration/signin is a
separate acceptance step. Persistent OS-keyring behavior needs a supported desktop
keyring; headless testing uses `--no-store`.

[cli/README.md](cli/README.md) explains the package and tests.
[auth/README.md](auth/README.md) explains local services and authentication setup.
The active root documents are this overview, [how_to_run.md](how_to_run.md),
and the maintainer-local gateway plan (excluded from this release). `history/`,
`Meeting_Notes/`, `Research/`, and historical root artifacts are retained project
material, not instructions for this release. The restored `src/mvp` backend has its own historical setup and API commands;
these are separate from the current authentication-only Promptrail commands. No remote push or production deployment is implied by
this cleanup.
