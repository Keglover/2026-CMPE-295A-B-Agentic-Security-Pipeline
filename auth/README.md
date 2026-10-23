# Gateway identity setup for Promptrail testing

Promptrail is installed separately from the gateway. This directory supplies a
local Keycloak realm and an authenticated MOCK gateway for integration testing.
It is not required on teammate computers using an existing shared gateway.

The larger gateway/database plan is on hold. This round covers standalone CLI
packaging, signup, signin, verified user access and team feedback. Existing agent
and review mechanisms are carried forward without new session features.

## Start a private local environment

From the repository root, with Python 3.11+ and Docker Compose v2:

```bash
python3 -m venv src/mvp/.venv
src/mvp/.venv/bin/python -m pip install -r src/mvp/requirements.txt
src/mvp/.venv/bin/python -m pip install -e './cli[test]'
src/mvp/.venv/bin/python auth/setup-dev.py
src/mvp/.venv/bin/python auth/setup-signing.py
docker compose --env-file auth/.env.keycloak -f auth/docker-compose.keycloak.yml up -d
docker compose -f auth/docker-compose.gateway-dev.yml up -d --build
```

Keycloak is available on `http://127.0.0.1:8080`; the authenticated gateway binds
`http://127.0.0.1:8003`. Wait for services to become healthy before login. The
existing stack on port 8000 is separate. The development API forces MOCK tools
and disables the optional LLM judge. It uses persistent protected identity and
review metadata under `auth/.runtime` and never stores bearer tokens there.

`auth/setup-dev.py` creates owner-only, ignored `auth/.env.keycloak` and
`auth/README.local.md`. It preserves existing generated passwords. The latter
lists local development accounts; never commit or share it as a package asset.
Normal restart preserves Keycloak passwords through its named data volume.
The realm template maps subject, API audience and assigned realm roles into
access tokens. Existing realms may need `auth/sync-client-mappers.py` and
`auth/sync-dev-users.py` after a template upgrade; neither resets passwords.

## Opt in to browser signup

Registration is disabled by default. An administrator can enable it in this
local development realm and grant newly registered users evaluation access:

```bash
src/mvp/.venv/bin/python auth/configure-registration.py --enable
JEV_SELF_REGISTRATION_ENABLED=true \
  docker compose -f auth/docker-compose.gateway-dev.yml up -d --no-build
```

The script refuses unexpected default-role grants rather than silently exposing
execution/reviewer access. It authenticates only to the fixed local Keycloak
admin endpoint using the private bootstrap file; no administrator key goes into
Promptrail. The gateway registration flag advertises this operator choice on
`/auth/registration`. `/auth/config` stays backward compatible. Both the realm
and gateway must be configured; a flag alone cannot enable provider signup.

```bash
export PROMPTRAIL_GATEWAY_URL=http://127.0.0.1:8003
promptrail auth signup
```

Use a fresh private browser context, open the displayed device URL, choose
**Register**, create the account, and complete the device authorization. The CLI
never collects a password. The gateway verifies the resulting JWT and permissions
before the CLI stores it. On a headless machine add `--no-store --verify-evaluation`.

Disable enrollment later with:

```bash
src/mvp/.venv/bin/python auth/configure-registration.py --disable
JEV_SELF_REGISTRATION_ENABLED=false \
  docker compose -f auth/docker-compose.gateway-dev.yml up -d --no-build
```

Disabling signup does not delete existing accounts or change their roles.
For a shared service, administrators must additionally configure HTTPS, email
verification/SMTP and enrollment rules. Do not expose this `start-dev` realm as
production identity hosting. Auth0 is a tested wire adapter scaffold, not a
provisioned signup tenant.

## User access and session lifetime

```bash
promptrail auth signin
promptrail auth status
promptrail auth status --json
promptrail eval 'Check a public sample.' --json
promptrail auth signout
```

The gateway trusts issuer, signature, audience, authorized client, expiry and
assigned permissions, not caller-provided role fields. Requested scopes are
intersected with assigned roles; requesting a role does not grant it. New signup
accounts receive `jev:evaluate` only. An administrator must explicitly assign
additional roles and configure corresponding scopes before any extra access.

The local realm issues five-minute access tokens and ten-minute device codes.
Promptrail stores a verified access token in the system keyring, scoped to gateway
URL. It does not store refresh tokens; sign in again after expiry. `--no-store`
verifies login for the current process only. `signout` clears local credentials,
not browser SSO or every issued JWT. See [CLI user sessions](../cli/README.md#how-user-sessions-work).

If browser login reports a missing restart cookie, request a fresh device code
and open its entry URL in a single normal/private browser context. Login may
automatically reuse an existing browser account; check the intended identity.
A VM browser may need SSH port forwarding for both 8080 and 8003; use a consistent
issuer hostname. Shared deployments need reachable HTTPS gateway/issuer URLs.

## Verification and feedback

CLI-only tests require no backend. For backend integration, from the repo root:

```bash
PYTHONPATH=src/mvp JEV_AUTH_MODE=disabled REAL_TOOLS=false LLM_JUDGE_ENABLED=false \
  src/mvp/.venv/bin/python -m pytest cli/tests -q

cd src/mvp
JEV_AUTH_MODE=disabled REAL_TOOLS=false LLM_JUDGE_ENABLED=false \
  AUDIT_LOG_PATH=/tmp/promptrail-auth-tests.ndjson \
  .venv/bin/python -m pytest tests/test_authentication.py tests/test_keycloak_configuration.py tests/test_registration.py -q
```

Team feedback should include package/commit version, platform, operation and safe
reason code. Exclude credentials and raw private content. Anonymous/invalid-token
requests must fail, self-signup must not grant tools/review, and an expired token
must require fresh signin. Browser login is a separate human acceptance step.
