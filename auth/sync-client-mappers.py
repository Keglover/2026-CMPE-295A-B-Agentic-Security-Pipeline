"""Apply client mapper fixes without resetting the existing realm or its users."""

import json
from pathlib import Path

import httpx

root = Path(__file__).resolve().parent
values = dict(line.split("=", 1) for line in (root / ".env.keycloak").read_text().splitlines() if "=" in line)
realm = json.loads((root / "keycloak" / "jev-realm.json").read_text())
desired = next(app for app in realm["clients"] if app["clientId"] == "jev-cli")["protocolMappers"]
base = "http://127.0.0.1:8080"
with httpx.Client(timeout=10, trust_env=False, follow_redirects=False) as client:
    response = client.post(base + "/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": "admin-cli", "username": "jev-admin",
        "password": values["JEV_KEYCLOAK_ADMIN_PASSWORD"]})
    if response.status_code != 200:
        raise SystemExit("Local administrator authentication failed; no configuration was changed.")
    headers = {"Authorization": "Bearer " + response.json()["access_token"]}
    response = client.get(base + "/admin/realms/jev/clients", params={"clientId": "jev-cli"}, headers=headers)
    response.raise_for_status()
    apps = response.json()
    if len(apps) != 1:
        raise SystemExit("Expected one jev-cli client; no configuration was changed.")
    app = apps[0]
    endpoint = base + "/admin/realms/jev/clients/" + app["id"] + "/protocol-mappers/models"
    current = {mapper["name"]: mapper for mapper in app.get("protocolMappers", [])}
    for mapper in desired:
        if mapper["name"] in current:
            existing = current[mapper["name"]]
            if all(
                all(existing.get("config", {}).get(field) == setting for field, setting in value.items())
                if key == "config" else existing.get(key) == value
                for key, value in mapper.items()
            ):
                continue
            merged = existing | mapper | {"config": existing.get("config", {}) | mapper.get("config", {})}
            response = client.put(endpoint + "/" + existing["id"], headers=headers,
                                  json=merged)
        else:
            response = client.post(endpoint, headers=headers, json=mapper)
        response.raise_for_status()
        print("Synchronized mapper:", mapper["name"])
print("Client mappers synchronized; existing users and passwords preserved.")
