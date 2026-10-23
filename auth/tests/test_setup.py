import json
import os

import httpx
import pytest

from auth import setup


def test_enable_adds_only_basic_access_default_and_preserves_realm():
    changes=[]
    def handle(request):
        if request.method=="GET" and request.url.path.endswith("/composites/realm"):
            return httpx.Response(200,json=[{"name":"offline_access"}])
        if request.method=="GET" and request.url.path.endswith("/roles/promptrail:access"):
            return httpx.Response(200,json={"name":"promptrail:access","id":"evaluate"})
        if request.method=="GET":
            return httpx.Response(200,json={"defaultRole":{"name":"default-roles-promptrail"},"registrationAllowed":False,"verifyEmail":True})
        import json
        changes.append((request.method,json.loads(request.content)))
        return httpx.Response(204)
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        setup.configure(client,{},enabled=True)
    assert changes==[("POST",[{"name":"promptrail:access","id":"evaluate"}]),
                     ("PUT",{"defaultRole":{"name":"default-roles-promptrail"},"registrationAllowed":True,"verifyEmail":True})]


def test_unexpected_default_grants_stop_before_enabling_signup():
    mutations=[]
    def handle(request):
        if request.method!="GET":mutations.append(request.method)
        return httpx.Response(200,json=([{"name":"promptrail:review"}] if request.url.path.endswith("/composites/realm") else
                             {"defaultRole":{"name":"default-roles-promptrail"},"registrationAllowed":False}))
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(ValueError,match="DEFAULT_ROLE_REQUIRES_ADMIN_REVIEW"):
            setup.configure(client,{},enabled=True)
    assert not mutations

def test_configuration_generation_is_private_and_restart_safe(tmp_path):
    path = tmp_path / '.env'
    setup.initialize(path)
    first = path.read_bytes()
    assert path.stat().st_mode & 0o777 == 0o600
    values, _ = setup.read_private(path)
    assert len(values['PROMPTRAIL_KEYCLOAK_ADMIN_PASSWORD']) >= 32
    setup.initialize(path)
    assert path.read_bytes() == first


def test_configuration_cannot_read_symlink_or_public_file(tmp_path):
    target = tmp_path / 'target'
    target.write_text('PROMPTRAIL_KEYCLOAK_ADMIN_PASSWORD=private\n')
    target.chmod(0o644)
    with pytest.raises(ValueError):
        setup.read_private(target)
    link = tmp_path / '.env'
    link.symlink_to(target)
    with pytest.raises(OSError):
        setup.initialize(link)


def test_realm_contains_no_execution_roles_or_passwords():
    from pathlib import Path
    realm = json.loads(Path('auth/keycloak-realm.json').read_text())
    assert realm['realm'] == 'promptrail' and realm['registrationAllowed'] is False
    assert [role['name'] for role in realm['roles']['realm']] == ['promptrail:access']
    assert 'users' not in realm
    cli = next(client for client in realm['clients'] if client['clientId'] == 'promptrail-cli')
    assert cli['publicClient'] and cli['attributes']['oauth2.device.authorization.grant.enabled'] == 'true'
    assert not cli['directAccessGrantsEnabled'] and not cli['standardFlowEnabled']
