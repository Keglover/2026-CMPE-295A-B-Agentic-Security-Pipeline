"""Opt in to local development signup; never grant tool/reviewer roles by default."""
import argparse
import io
import os
import stat
from pathlib import Path

import httpx


def configure(client, headers, *, enabled):
    endpoint = "http://127.0.0.1:8080/admin/realms/jev"

    def call(method, path, **kwargs):
        response = client.request(method, endpoint + path, headers=headers, **kwargs)
        if response.status_code not in {200, 201, 204}:
            raise ValueError("REGISTRATION_CONFIGURATION_FAILED")
        return response.json() if response.content else None

    realm = call("GET", "")
    if enabled:
        default_role = realm.get("defaultRole", {}).get("name")
        if not default_role or default_role != "default-roles-jev":
            raise ValueError("DEFAULT_ROLE_REQUIRES_ADMIN_REVIEW")
        roles = call("GET", "/roles/" + default_role + "/composites/realm")
        safe_defaults = {"offline_access", "uma_authorization", "jev:evaluate"}
        if any(role.get("name") not in safe_defaults for role in roles):
            raise ValueError("DEFAULT_ROLE_REQUIRES_ADMIN_REVIEW")
        if "jev:evaluate" not in {role["name"] for role in roles}:
            role = call("GET", "/roles/jev:evaluate")
            call("POST", "/roles/" + default_role + "/composites", json=[role])
    if realm.get("registrationAllowed") is not enabled:
        call("PUT", "", json=realm | {"registrationAllowed": enabled})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--enable", action="store_true")
    choice.add_argument("--disable", action="store_true")
    args = parser.parse_args()
    try:
        from dotenv import dotenv_values
        descriptor = os.open(Path(__file__).parent / ".env.keycloak", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise ValueError("LOCAL_ADMIN_CONFIGURATION_REQUIRED")
            data = stream.read(65537)
        if len(data) > 65536:
            raise ValueError("LOCAL_ADMIN_CONFIGURATION_REQUIRED")
        values = dotenv_values(stream=io.StringIO(data.decode()), interpolate=False)
        password = values.get("JEV_KEYCLOAK_ADMIN_PASSWORD")
        if not password:
            raise ValueError("LOCAL_ADMIN_CONFIGURATION_REQUIRED")
        with httpx.Client(timeout=10, trust_env=False, follow_redirects=False) as client:
            response = client.post("http://127.0.0.1:8080/realms/master/protocol/openid-connect/token", data={
                "grant_type": "password", "client_id": "admin-cli", "username": "jev-admin", "password": password})
            if response.status_code != 200:
                raise ValueError("LOCAL_ADMIN_AUTHENTICATION_FAILED")
            token = response.json()["access_token"]
            configure(client, {"Authorization": "Bearer " + token}, enabled=args.enable)
        print("Local self-registration enabled with evaluation-only defaults." if args.enable
              else "Local self-registration disabled.")
        print("Also set JEV_SELF_REGISTRATION_ENABLED=" + ("true" if args.enable else "false")
              + " when recreating the development gateway.")
    except (httpx.HTTPError, ValueError, KeyError, TypeError, OSError):
        raise SystemExit("Registration setup stopped. Check local administrator access and default roles; no secrets were printed.") from None


if __name__ == "__main__":
    main()
