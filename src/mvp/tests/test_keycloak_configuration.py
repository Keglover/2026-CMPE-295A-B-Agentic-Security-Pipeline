"""Deployment contracts required for real tokens to satisfy gateway identity checks."""

import json
from pathlib import Path


def test_cli_realm_maps_subject_audience_and_assigned_permissions():
    root = Path(__file__).resolve().parents[3]
    realm = json.loads((root / "auth/keycloak/jev-realm.json").read_text())
    app = next(app for app in realm["clients"] if app["clientId"] == "jev-cli")
    mappers = {mapper["protocolMapper"]: mapper for mapper in app["protocolMappers"]}
    assert mappers["oidc-sub-mapper"]["config"]["access.token.claim"] == "true"
    assert mappers["oidc-audience-mapper"]["config"]["included.client.audience"] == "jev-gateway"
    assert mappers["oidc-usermodel-realm-role-mapper"]["config"]["claim.name"] == "realm_access.roles"
    assert app["publicClient"] is True
    assert app["directAccessGrantsEnabled"] is False
    user = next(user for user in realm["users"] if user["username"] == "jev-dev")
    assert user["realmRoles"] == ["jev:evaluate"]
    assert user["credentials"][0]["value"] == "${JEV_DEV_USER_PASSWORD}"


def test_execution_and_review_accounts_have_separate_roles():
    root = Path(__file__).resolve().parents[3]
    users = {user["username"]: user for user in json.loads((root / "auth/keycloak/jev-realm.json").read_text())["users"]}
    assert users["jev-agent-dev"]["realmRoles"] == ["jev:evaluate", "jev:tools:call"]
    assert users["jev-reviewer-dev"]["realmRoles"] == ["jev:evaluate", "jev:approvals:write"]
    assert users["jev-agent-dev"]["credentials"][0]["value"] == "${JEV_AGENT_USER_PASSWORD}"
    assert users["jev-reviewer-dev"]["credentials"][0]["value"] == "${JEV_REVIEWER_USER_PASSWORD}"
