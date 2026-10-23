"""Generate local development credentials once, without displaying secrets."""

import os
import secrets
from pathlib import Path

root = Path(__file__).resolve().parent
path = root / ".env.keycloak"
if path.exists():
    print("Existing auth/.env.keycloak preserved.")
else:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write("JEV_KEYCLOAK_ADMIN_PASSWORD=" + secrets.token_urlsafe(32) + "\n")
        stream.write("JEV_DEV_USER_PASSWORD=" + secrets.token_urlsafe(24) + "\n")
    print("Created owner-only auth/.env.keycloak. Passwords were not printed.")
(root / ".runtime").mkdir(mode=0o700, exist_ok=True)

# Keep the actual development password in a local README, outside Git.
values = dict(line.split("=", 1) for line in path.read_text().splitlines() if "=" in line)
for variable in ("JEV_AGENT_USER_PASSWORD", "JEV_REVIEWER_USER_PASSWORD"):
    if variable not in values:
        values[variable] = secrets.token_urlsafe(24)
        descriptor = os.open(path, os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "a") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(variable + "=" + values[variable] + "\n")
readme = root / "README.local.md"
content = f"""# Local Keycloak login

These credentials belong to this workspace's local development realm.

| Field | Value |
| --- | --- |
| Account page | http://127.0.0.1:8080/realms/jev/account/ |
| Realm | `jev` |
| Username | `jev-dev` |
| Password | `{values['JEV_DEV_USER_PASSWORD']}` |
| Permission | `jev:evaluate` |

## Agent caller and reviewer

| Username | Password | Assigned permissions |
| --- | --- | --- |
| `jev-agent-dev` | `{values['JEV_AGENT_USER_PASSWORD']}` | `jev:evaluate`, `jev:tools:call` |
| `jev-reviewer-dev` | `{values['JEV_REVIEWER_USER_PASSWORD']}` | `jev:evaluate`, `jev:approvals:write` |

Use the agent caller for `jev agent start --login`. Switch accounts in the
browser (sign out from the account page) before authorizing the reviewer.
The caller cannot approve actions, and the reviewer cannot execute tools.

The username is fixed by `auth/keycloak/jev-realm.json`. The password remains
the same across container restarts and normal `docker compose down`/`up`
while the Keycloak data volume is preserved and nobody changes the password
in Keycloak. Running `auth/setup-dev.py` again preserves `.env.keycloak`.

Deleting `.env.keycloak` generates new bootstrap values on the next setup run,
but an existing Keycloak realm keeps its database password. Recreating the
realm/data volume imports the current bootstrap value. After changing the
password through Keycloak, update this local reference separately.

This file is ignored by Git and contains no administrator password. For VM
port forwarding and CLI device login, see `auth/README.md`.
"""
descriptor = os.open(readme, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
with os.fdopen(descriptor, "w") as stream:
    os.fchmod(stream.fileno(), 0o600)
    stream.write(content)
print("Updated ignored, owner-only auth/README.local.md with the development login details.")
