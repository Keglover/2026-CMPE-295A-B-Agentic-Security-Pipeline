"""Local enrollment is opt-in and cannot add execution/reviewer defaults."""
import importlib.util
from pathlib import Path

import httpx
import pytest

from app.auth.routes import registration_config


@pytest.mark.parametrize("enabled", [False, True])
def test_registration_advertisement_is_explicit_and_requires_auth(monkeypatch, enabled):
    monkeypatch.setenv("JEV_AUTH_MODE", "required")
    monkeypatch.setenv("JEV_OIDC_PROVIDER", "keycloak")
    monkeypatch.setenv("JEV_SELF_REGISTRATION_ENABLED", "true" if enabled else "false")
    assert registration_config()=={"signup_enabled":enabled}
    monkeypatch.setenv("JEV_AUTH_MODE", "disabled")
    assert registration_config()=={"signup_enabled":False}


@pytest.fixture
def registration_module():
    path=Path(__file__).resolve().parents[3]/"auth/configure-registration.py"
    spec=importlib.util.spec_from_file_location("registration_configurator",path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def test_enable_adds_only_evaluation_default_and_preserves_realm(registration_module):
    changes=[]
    def handle(request):
        if request.method=="GET" and request.url.path.endswith("/composites/realm"):
            return httpx.Response(200,json=[{"name":"offline_access"}])
        if request.method=="GET" and request.url.path.endswith("/roles/jev:evaluate"):
            return httpx.Response(200,json={"name":"jev:evaluate","id":"evaluate"})
        if request.method=="GET":
            return httpx.Response(200,json={"defaultRole":{"name":"default-roles-jev"},"registrationAllowed":False,"verifyEmail":True})
        import json
        changes.append((request.method,json.loads(request.content)))
        return httpx.Response(204)
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        registration_module.configure(client,{},enabled=True)
    assert changes==[("POST",[{"name":"jev:evaluate","id":"evaluate"}]),
                     ("PUT",{"defaultRole":{"name":"default-roles-jev"},"registrationAllowed":True,"verifyEmail":True})]


def test_unexpected_default_grants_stop_before_enabling_signup(registration_module):
    mutations=[]
    def handle(request):
        if request.method!="GET":mutations.append(request.method)
        return httpx.Response(200,json=([{"name":"jev:approvals:write"}] if request.url.path.endswith("/composites/realm") else
                             {"defaultRole":{"name":"default-roles-jev"},"registrationAllowed":False}))
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(ValueError,match="DEFAULT_ROLE_REQUIRES_ADMIN_REVIEW"):
            registration_module.configure(client,{},enabled=True)
    assert not mutations
