# CLI package

This folder builds `promptrail-cli` 0.1.0rc3. The sole executable is `promptrail`;
`python -m promptrail` uses the same entry point. It needs Python 3.11+ and a
compatible authentication gateway, but no backend, Docker or database installation.

## Commands

| Command | Behavior |
| --- | --- |
| `promptrail` / `--help` | Display available commands |
| `promptrail --version` | Show installed package version |
| `promptrail doctor [--json]` | Read public health/auth configuration without credentials |
| `promptrail auth signup [--no-store]` | Register in the provider's browser flow and verify the token |
| `promptrail auth signin [--no-store]` | Browser/device login, then gateway verification |
| `promptrail auth status [--json]` | Verify a saved credential with the gateway |
| `promptrail auth signout` | Remove the selected gateway's keyring credential |

`login`/`logout` remain aliases for `signin`/`signout`. Gateway-taking commands
accept `--gateway-url`. The default is `http://127.0.0.1:8003`; remote endpoints
require HTTPS. `PROMPTRAIL_GATEWAY_URL` overrides the default and explicit flags
come first. `PROMPTRAIL_AUTH_TOKEN` optionally overrides keyring lookup; its value
is never printed. Legacy `JEV_*` variables and the `jev` executable are removed.

No `eval`, `run`, `test`, `agent`, `approvals` or `audit` commands are present.
The old `--verify-evaluation` flag is removed; authentication always verifies
`/auth/whoami`, without sending a prompt or invoking a tool.

## User sessions

The CLI never accepts a password. It requests a bounded device challenge, prints
its URL/user code and polls until authorization, denial, cancellation or expiry.
It accepts identity endpoints only on the configured issuer's origin. After the
gateway verifies the token and required permissions, the CLI saves it in the OS
keyring under `promptrail-cli`, scoped to the gateway URL.

Use `--no-store` if a secure keyring is unavailable. This verifies login for that
process only; a later `auth status` returns `NO_CREDENTIAL`. No plaintext token
fallback is used. JWT expiry requires fresh signin; refresh tokens are not stored.
Signout removes local credentials, not issued tokens or browser SSO sessions.

Exit codes: `0` successful operation; `1` no valid saved login for status;
`2` configuration, service or login failure; `130` interrupted login.

## Implementation and testing

- `promptrail/main.py`: terminal entry point and readiness command.
- `promptrail/config.py`: validated gateway settings and keyring access.
- `promptrail/readiness.py`: bounded, read-only authentication gateway probe.
- `promptrail/auth/`: device protocol, provider adapter and auth commands.
- `tests/`: authentication/configuration/HTTP/CLI tests only.

From the project root, use the [current setup](../CLI_README.md), then run:

```bash
.venv/bin/python -m pytest cli/tests -q
.venv/bin/python -m pip wheel --no-deps --wheel-dir dist ./cli
```

The wheel includes only `promptrail` and package metadata. Authentication service
code, tests, configuration secrets and historical material are excluded. The
Auth0 adapter is tested with fake responses; no tenant has been provisioned.
Future execution/session work belongs to the maintainer-local gateway plan (`PROMPTRAIL_GATEWAY_PLAN.md`, excluded from this release).

## File reference

| File | Responsibility |
| --- | --- |
| `pyproject.toml` | Package metadata, runtime/test dependencies, included packages and sole `promptrail` console entry point |
| `promptrail/__init__.py` | Identifies the standalone client package; imports no server implementation |
| `promptrail/__main__.py` | Calls the same Typer application for `python -m promptrail` |
| `promptrail/main.py` | Root command group, version callback and `doctor` |
| `promptrail/config.py` | Gateway URL/timeout validation, environment precedence and keyring access |
| `promptrail/readiness.py` | Public health/auth-contract checks without a credential |
| `promptrail/auth/__init__.py` | Authentication subpackage |
| `promptrail/auth/commands.py` | Terminal signup/signin/status/signout and safe error presentation |
| `promptrail/auth/device.py` | Device challenge validation, bounded polling and gateway identity verification |
| `promptrail/auth/providers.py` | Public login-profile validation and device-request parameter adapters |

## Function reference

### Entry point and settings

| Function/class | Behavior |
| --- | --- |
| `main.main(show_version)` | Handle `--version` from installed package metadata before subcommand dispatch |
| `main.doctor(gateway_url, json_output)` | Load settings, call the readiness probe and print a human or JSON report; never start login |
| `config.Settings` / `validate_url(value)` | Validate URL and request timeout; allow HTTP only on loopback; normalize the URL used for requests and keyring lookup |
| `config.load_settings(gateway_url, timeout)` | Select explicit gateway argument, then `PROMPTRAIL_GATEWAY_URL`, then the local default |
| `config.get_token(gateway_url)` | Read `PROMPTRAIL_AUTH_TOKEN` first or the matching keyring entry; reject malformed credentials before header use |
| `config.set_token(gateway_url, token)` | Store a validated token under keyring service `promptrail-cli` and account equal to the selected gateway URL |
| `readiness.ReadinessError` | Safe public readiness failure reason |
| `readiness.inspect_gateway(settings, transport)` | Read `/health` and `/auth/config`, validate service/profile compatibility and reject HTTPS-to-HTTP identity downgrade |
| `readiness.inspect_gateway.read(client, url)` | Internal GET helper; require HTTP 200 and a JSON object within 64 KiB |

An invalid environment credential is an error, not a signal to try a different
stored account. Keyring lookup failure produces no credential; there is no
plaintext fallback. `doctor` does not call `get_token()` and does not establish
that a user is signed in or that the identity provider is currently available.

### Terminal authentication commands — `auth/commands.py`

| Function | Behavior |
| --- | --- |
| `login(gateway_url, no_store)` | Implement both `signin` and `login`; delegate to the shared authentication flow |
| `signup(gateway_url, no_store)` | Start the shared flow with registration opt-in checks and browser Register instructions |
| `_authenticate(gateway_url, no_store, signup=...)` | Check secure-storage availability when persistence is requested, begin/poll login, verify identity, then optionally store the token |
| `status(gateway_url, json_output)` | Read the selected credential and reverify it against current gateway configuration before reporting identity/expiry |
| `status.report(value)` | Render safe human/JSON output; never include a bearer token |
| `logout(gateway_url)` | Implement both `signout` and `logout`; remove only the selected gateway keyring entry and warn if an environment override remains |

The order `begin → poll → verify → optional storage` is the login backbone.
Browser authorization alone is not a successful CLI login: the selected gateway
must verify the resulting credential, and its response must match the login
profile. With `--no-store`, all verification still runs but the token is not
saved for another command. CLI signout neither calls provider revocation nor
clears browser cookies, and cannot unset a parent shell's environment variable.

### Device protocol — `auth/device.py`

| Class/method | Behavior |
| --- | --- |
| `LoginError(code)` | Hold a safe login reason for terminal error handling |
| `DeviceChallenge` / `bounded_code(value)` | Bound provider challenge fields; mask the private device secret with `SecretStr` while keeping the user code displayable |
| `VerifiedIdentity` | Require the expected gateway identity fields and reject extra fields |
| `DeviceLogin.__init__(settings, transport, clock, sleep)` | Create one bounded HTTP client; injectable transport/clock/sleep make failure and timing tests deterministic |
| `__enter__()` / `__exit__()` | Own and close the HTTP client for the flow, including error/interrupt paths |
| `_request(method, url, ...)` | Read a JSON object up to 1 MiB; map network, timeout and parsing failures to safe codes |
| `_issuer_url(url)` | Validate endpoint URLs and require the advertised issuer origin |
| `_verification_url(url)` | Validate the browser URL, allowing its user-code query but rejecting credentials, whitespace and fragments |
| `begin(scopes=None, signup=False)` | Read/validate gateway profile, check signup advertisement if requested, fetch issuer discovery, validate endpoints and request a challenge |
| `poll(challenge)` | Poll the provider token endpoint until authorization, denial or expiry; return a masked bearer token |
| `verify(token)` | Send the token to the selected gateway's `/auth/whoami`, then verify response issuer/audience/provider/expiry and required permissions |
| `inspect_identity(token)` | Refresh the gateway profile first, then run `verify()` for a saved session |

The discovery issuer must exactly match the configured profile. Provider URLs
must stay on that issuer origin. Redirects and environment proxy inheritance
are disabled. HTTPS gateways cannot advertise plaintext HTTP issuers.
The CLI trusts its selected gateway to verify JWT signatures; it does not infer
identity by decoding unverified JWT text locally.

Polling uses monotonic time and the provider's challenge deadline. It waits on
`authorization_pending`, adds five seconds for `slow_down`, and doubles the
interval after network timeouts. Each poll's HTTP timeout is capped by remaining
device lifetime. Denial, unsupported errors or expiry stop the flow. No automatic
refresh token is used or persisted. Error presentation forwards only recognized
public reason codes, not arbitrary provider error descriptions.

### Provider contract — `auth/providers.py`

| Function/class | Behavior |
| --- | --- |
| `LoginProfile` | Strict gateway-provided mode/provider/issuer/client/audience/scopes model |
| `valid_issuer(value)` | Reuse validated client URL rules for the issuer |
| `required_auth(value)` | Refuse a profile whose authentication mode is not `required` |
| `supported_provider(value)` | Accept Keycloak and optional compatible OIDC/Auth0 client profiles |
| `allowed_scopes(values)` | Require 1–32 distinct bounded OAuth scope tokens without whitespace, quotes or backslashes |
| `origin(url)` | Normalize scheme, hostname and effective port |
| `KeycloakProvider.device_parameters(profile)` | Send public `client_id` and joined scopes; no client secret |
| `Auth0Provider.device_parameters(profile)` | Optional client scaffold that additionally sends API audience |
| `provider_for(profile)` | Select Auth0 parameters or the standard device-request adapter |

The local gateway currently accepts Keycloak only. Retaining a client adapter
is not a claim that an Auth0 tenant or server verifier has been provisioned.

## Test file reference

| File | Focus |
| --- | --- |
| `tests/test_auth_commands.py` | Verify-before-storage ordering, no-store mode, keyring failure, cancellation, signup, expiry/status and secret-free output |
| `tests/test_auth_http.py` | Installed executable against independent loopback HTTP gateway/provider fixtures, including signup/signin/expiry and generic permissions |
| `tests/test_cli.py` | Public entry point, version, removed-command rejection and bounded credential-free readiness |
| `tests/test_config.py` | URL security, gateway precedence and correctly scoped keyring/environment credentials |
| `tests/test_device_login.py` | Challenge validation, endpoints/origin checks, polling/backoff/deadlines, safe errors and identity consistency |

Keep tests focused on these authentication contracts. New policy, model, agent
or execution features remain deferred to the plan and require their own approved
interfaces and tests when implemented.
