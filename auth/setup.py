"""Generate private local configuration and optionally enable/disable enrollment."""
import argparse
import io
import os
from pathlib import Path
import secrets
import stat

import httpx
from dotenv import dotenv_values

ENV_PATH = Path(__file__).parent / ".env"


def read_private(path):
    """Read at most 64 KiB of an owner-only regular dotenv file without interpolation."""
    # Inspect the opened descriptor, not just a pathname that could resolve to a different file.
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                or info.st_uid != os.getuid()):
            raise ValueError("PRIVATE_CONFIGURATION_REQUIRED")
        data = stream.read(65537)
    if len(data) > 65536:
        raise ValueError("PRIVATE_CONFIGURATION_REQUIRED")
    # Configuration is data: do not expand embedded environment-variable references.
    return dotenv_values(stream=io.StringIO(data.decode()), interpolate=False), data.decode()


def initialize(path=ENV_PATH):
    """Create private bootstrap configuration once, preserving existing credentials."""
    if path.exists() or path.is_symlink():
        values, _ = read_private(path)
        if not values.get("PROMPTRAIL_KEYCLOAK_ADMIN_PASSWORD"):
            raise ValueError("ADMIN_PASSWORD_REQUIRED")
        return
    template = Path(__file__).with_name("env.example").read_text()
    content = template.replace("PROMPTRAIL_KEYCLOAK_ADMIN_PASSWORD=\n",
                               "PROMPTRAIL_KEYCLOAK_ADMIN_PASSWORD=" + secrets.token_urlsafe(32) + "\n")
    # Exclusive creation preserves an existing password; mode 0600 protects the new bootstrap secret.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(content)


def configure(client, headers, *, enabled):
    """Update local realm enrollment, allowing only safe default roles before enabling it."""
    endpoint = "http://127.0.0.1:8080/admin/realms/promptrail"

    def call(method, path, **kwargs):
        """Call the fixed realm admin API and reject unsuccessful responses."""
        response = client.request(method, endpoint + path, headers=headers, **kwargs)
        if response.status_code not in {200, 201, 204}:
            raise ValueError("REGISTRATION_CONFIGURATION_FAILED")
        return response.json() if response.content else None

    realm = call("GET", "")
    if enabled:
        default_role = realm.get("defaultRole", {}).get("name")
        if not default_role or default_role != "default-roles-promptrail":
            raise ValueError("DEFAULT_ROLE_REQUIRES_ADMIN_REVIEW")
        roles = call("GET", "/roles/" + default_role + "/composites/realm")
        # Enabling signup must not silently enroll every new user into a privileged custom role.
        safe_defaults = {"offline_access", "uma_authorization", "promptrail:access"}
        if any(role.get("name") not in safe_defaults for role in roles):
            raise ValueError("DEFAULT_ROLE_REQUIRES_ADMIN_REVIEW")
        if "promptrail:access" not in {role["name"] for role in roles}:
            role = call("GET", "/roles/promptrail:access")
            call("POST", "/roles/" + default_role + "/composites", json=[role])
    if realm.get("registrationAllowed") is not enabled:
        call("PUT", "", json=realm | {"registrationAllowed": enabled})



def set_registration(enabled, path=ENV_PATH):
    """Configure Keycloak with a transient admin token, then save the gateway signup flag."""
    values, text = read_private(path)
    with httpx.Client(timeout=10, trust_env=False, follow_redirects=False) as client:
        response = client.post("http://127.0.0.1:8080/realms/master/protocol/openid-connect/token", data={
            "grant_type": "password", "client_id": "admin-cli", "username": "promptrail-admin",
            "password": values.get("PROMPTRAIL_KEYCLOAK_ADMIN_PASSWORD", "")})
        if response.status_code != 200:
            raise ValueError("LOCAL_ADMIN_LOGIN_FAILED")
        token = response.json().get("access_token")
        if not isinstance(token, str) or not token:
            raise ValueError("LOCAL_ADMIN_LOGIN_FAILED")
        # The administrator token stays in this process; it is never saved in the CLI keyring or .env.
        configure(client, {"Authorization": "Bearer " + token}, enabled=enabled)
    # Advertise the change only after the realm update succeeds; the gateway must reload its environment.
    key = "PROMPTRAIL_SELF_REGISTRATION_ENABLED"
    lines = [line for line in text.splitlines() if not line.startswith(key + "=")]
    lines.append(key + ("=true" if enabled else "=false"))
    descriptor = os.open(path, os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "w") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write("\n".join(lines) + "\n")


def main():
    """Run local config generation or the explicitly selected enrollment change."""
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--enable-signup", action="store_true")
    group.add_argument("--disable-signup", action="store_true")
    args = parser.parse_args()
    try:
        initialize()
        if args.enable_signup or args.disable_signup:
            set_registration(args.enable_signup)
            print("Registration updated. Restart the gateway to load auth/.env.")
        else:
            print("Private auth/.env ready. Existing credentials preserved; no passwords displayed.")
    except (OSError, ValueError, httpx.HTTPError):
        print("Setup failed. Check private configuration, local Keycloak availability and administrator access.")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
