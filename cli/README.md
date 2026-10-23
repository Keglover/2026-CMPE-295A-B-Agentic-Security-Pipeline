# Promptrail CLI

Promptrail is a standalone terminal client for a compatible authenticated security
gateway. Install it without the Jev backend, database, Docker or scoring engine.
The Python package and distribution are `promptrail` and `promptrail-cli`.
Jev is the integration-test gateway in this repository; it is not bundled in the
CLI. A compatible gateway is still required to assess requests and execute tools.

This test release focuses on independent packaging and **Authentication and Access**.
The larger gateway/database plan is on hold. Existing agent commands are retained;
this release does not add agent-session management or production sandbox features.

## Download from the gateway branch

Requirements: Python 3.11+, Git and pipx. Linux, macOS and WSL2 are the supported
test targets. Native Windows agent checkpoint locking is not supported.

If you installed the previous `jev-security-cli` distribution, remove that pipx
installation first so its `promptrail` executable does not conflict:

```bash
pipx uninstall jev-security-cli
```

Install the branch under test:

```bash
pipx install 'git+https://github.com/Keglover/2026-CMPE-295A-B-Agentic-Security-Pipeline.git@gateway#subdirectory=cli'
promptrail --version
promptrail --help
```

For reproducible team testing, replace `gateway` with the commit SHA being tested.
Later updates can be installed with `pipx reinstall promptrail-cli`. The legacy
`jev` command remains an alias; new integrations should use `promptrail`.
No PyPI publication is implied by this Git installation command.

## Choose a gateway

All commands default to `http://127.0.0.1:8003`, the authenticated development
gateway. For a shared deployment, each teammate sets the HTTPS address supplied
by the administrator:

```bash
export PROMPTRAIL_GATEWAY_URL=https://gateway.example.edu
promptrail doctor
```

Replace the illustrative hostname with a real reachable gateway. Installing the
CLI does not start the gateway or Keycloak. A teammate's localhost is their own
computer, so a shared gateway must advertise an identity-provider URL reachable
from that computer too. Remote gateway and identity URLs require HTTPS.

`PROMPTRAIL_AUDIT_PATH` selects private local activity history.
`PROMPTRAIL_AUTH_TOKEN` is an optional explicit environment credential, never
printed or persisted by evaluation. Legacy `JEV_GATEWAY_URL`, `JEV_AUDIT_PATH`
and `JEV_AUTH_TOKEN` remain fallback aliases. Promptrail names take precedence;
explicit command flags take precedence over environment settings.

## Sign up and sign in

```bash
promptrail auth signup
promptrail auth signin
promptrail auth status
promptrail auth status --json
promptrail auth signout
```

`signup` checks that the administrator has enabled registration, starts a device
login and prints a browser URL/code. In a fresh browser context choose **Register**
and create your account with the identity provider. The CLI never accepts or
stores your password. Complete the device authorization in that browser context.
It verifies the resulting access token with the gateway before saving it.
Registration can be disabled; in that case request an administrator-created
account/invitation instead. Signup may also sign into an existing browser account;
use a fresh private context when testing a new account.

New local signup accounts have evaluation access only. Tool execution, reviewer
and audit privileges require explicit administrator assignment. Requested OAuth
scopes cannot create permissions. Email verification/SMTP, enrollment controls
and HTTPS must be configured for a shared deployment; local Docker setup is a
development environment, not production identity hosting.

`signin` uses the same browser/device login for an existing account. `login` and
`logout` remain aliases for `signin` and `signout`. See the [local identity
setup](../auth/README.md) if you need your own gateway for testing.

## How user sessions work

- The identity provider issues a short-lived bearer access token (JWT with the
  supplied Keycloak gateway). The gateway verifies its signature, issuer,
  audience, client, expiry and permissions. The CLI does not trust locally
  decoded JWT fields as proof of login.
- Promptrail stores a verified token in the OS keyring, scoped to the normalized
  gateway URL under the `promptrail-cli` service. It does not silently import old
  `jev-security-cli` keyring entries; sign in again after upgrading.
- Subsequent commands retrieve the token and send it only to the selected
  gateway. `auth status` checks the gateway again and displays verified expiry
  and permissions. A saved token is not proof that it is still valid.
- This release does not save refresh tokens or implement silent refresh. After
  expiry, sign in again. The local development token lifetime is five minutes.
- `signout` removes both current and legacy keyring entries for that gateway.
  It does not revoke already issued JWTs or sign out the browser's SSO session.
  Environment-token overrides must also be unset. Provider/admin session
  revocation is separate from deleting a local credential.
- A checkpoint or request ID contains context and grants no access. User login
  persistence is separate from agent tool grants; agent-session changes are
  outside this release.

If your machine has no secure keyring, use verification-only mode:

```bash
promptrail auth signin --no-store --verify-evaluation
# Or test browser registration without storing a token:
promptrail auth signup --no-store --verify-evaluation
```

These commands check authenticated evaluation in the same process. The login
does not persist for a later standalone `eval`. Enable a supported OS keyring
for persistent login. Access tokens are never written to `.env`, audit logs or
checkpoints. Model API keys, when needed later, belong in a separate private
model `.env` file; they are not gateway login credentials.

## Teammate acceptance checklist

Run these after configuring your gateway and identity account:

```bash
promptrail doctor
promptrail auth signup          # fresh browser context; registration must be enabled
promptrail auth status
promptrail eval 'Summarize a public sample.' --json
promptrail audit
promptrail auth signout
promptrail auth status          # should report no credential if no env override is set
promptrail auth signin
```

Also check disabled signup, cancelled/expired device login, an expired access
token, unreachable gateway and permissions denied for an ordinary account.
Report your CLI version, OS/Python, gateway profile, safe reason code and
expected/actual behavior. Never include passwords, keys, tokens, `.env` contents
or raw private prompts in feedback. Authenticated requests must fail closed
when verification is unavailable.

An evaluation result always has `execution_authorized: false`; `eval` cannot
run a program, queue an execution review or consume approval. Existing `test`,
`agent` and `approvals` commands remain available, but they are not required
for this authentication acceptance round. `doctor` reports configuration and
MOCK/SANDBOX mode; it is not proof of a successful real sandbox run.

## Development and verification

From the repository root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e './cli[test]'
.venv/bin/python -m pytest cli/tests -q
```

CLI protocol tests run against independent fake HTTP services and need no Jev
server, database, model API key or browser account. The optional gateway
integration tests skip when backend imports are unavailable; the optional
existing-agent adapter test skips when the repository backend is unavailable.
Backend contract tests can additionally run with `PYTHONPATH=src/mvp`.
The CLI implements wire enums/contracts, not scoring rules or policy thresholds.

Build and install a local wheel:

```bash
python -m pip wheel --no-build-isolation --no-deps --wheel-dir dist ./cli
pipx install ./dist/promptrail_cli-0.1.0rc2-py3-none-any.whl
```

The wheel includes `promptrail` plus a `jev` compatibility import namespace.
It excludes backend code, tests, credentials and runtime/checkpoint files.
