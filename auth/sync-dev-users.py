"""Add isolated development caller/reviewer accounts without resetting passwords."""
import json
from pathlib import Path

import httpx

root = Path(__file__).resolve().parent
values = dict(line.split("=", 1) for line in (root / ".env.keycloak").read_text().splitlines() if "=" in line)
users = json.loads((root / "keycloak" / "jev-realm.json").read_text())["users"]
base = "http://127.0.0.1:8080"
with httpx.Client(timeout=10, trust_env=False, follow_redirects=False) as client:
    response = client.post(base + "/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": "admin-cli", "username": "jev-admin",
        "password": values["JEV_KEYCLOAK_ADMIN_PASSWORD"]})
    if response.status_code != 200:
        raise SystemExit("Local administrator authentication failed; accounts were not changed.")
    headers = {"Authorization": "Bearer " + response.json()["access_token"]}
    endpoint = base + "/admin/realms/jev/users"
    for template in users:
        if template["username"] == "jev-dev":
            continue
        response = client.get(endpoint, headers=headers, params={"username": template["username"], "exact": "true"})
        response.raise_for_status()
        existing = response.json()
        if not existing:
            user = json.loads(json.dumps(template))
            variable = user["credentials"][0]["value"][2:-1]
            user["credentials"][0]["value"] = values[variable]
            response = client.post(endpoint, headers=headers, json=user)
            response.raise_for_status()
            response = client.get(endpoint, headers=headers, params={"username": user["username"], "exact": "true"})
            response.raise_for_status()
            existing = response.json()
        if len(existing) != 1:
            raise SystemExit("Development account lookup was ambiguous; synchronization stopped.")
        user_id = existing[0]["id"]
        role_endpoint = endpoint + "/" + user_id + "/role-mappings/realm"
        response = client.get(role_endpoint, headers=headers)
        response.raise_for_status()
        current = {role["name"] for role in response.json()}
        missing = []
        for role in template["realmRoles"]:
            if role not in current:
                response = client.get(base + "/admin/realms/jev/roles/" + role, headers=headers)
                response.raise_for_status()
                missing.append(response.json())
        if missing:
            response = client.post(role_endpoint, headers=headers, json=missing)
            response.raise_for_status()
        print("Development account ready:", template["username"])
print("Caller/reviewer roles synchronized; existing passwords preserved.")
