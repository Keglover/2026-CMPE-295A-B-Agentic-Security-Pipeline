"""Installed standalone CLI against an independent OIDC/gateway HTTP fixture."""
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from promptrail.client import unavailable
from promptrail.models import EvaluationRequest, PolicyAction, ExecutionRequirement


def test_standalone_signup_signin_expiry_and_generic_permissions(tmp_path):
    state = {"registration": True, "expired": False, "posts": []}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def reply(self, status, data):
            body = json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def do_GET(self):
            issuer = f"http://127.0.0.1:{self.server.server_port}/identity"
            if self.path == "/auth/config":
                self.reply(200, {"mode":"required", "provider":"oidc", "issuer":issuer,
                    "client_id":"standalone-cli", "audience":"example-gateway", "scopes":["openid","example:inspect"]})
            elif self.path == "/auth/registration":
                self.reply(200, {"signup_enabled":state["registration"]})
            elif self.path.endswith("/.well-known/openid-configuration"):
                self.reply(200, {"issuer":issuer, "device_authorization_endpoint":issuer+"/device", "token_endpoint":issuer+"/token"})
            elif self.path == "/auth/whoami":
                assert self.headers["Authorization"] == "Bearer private-user-token"
                if state["expired"]:
                    self.reply(401, {"reason_code":"TOKEN_EXPIRED"})
                else:
                    self.reply(200, {"subject":"team-member", "issuer":issuer, "audience":"example-gateway",
                        "provider":"oidc", "permissions":["example:inspect"], "expires_at":int(time.time())+300})
            else:
                self.reply(404, {})
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            state["posts"].append(self.path)
            issuer = f"http://127.0.0.1:{self.server.server_port}/identity"
            if self.path == "/identity/device":
                assert b"example%3Ainspect" in body
                self.reply(200, {"device_code":"private-device-code", "user_code":"ABCD-EFGH",
                    "verification_uri":issuer+"/verify", "expires_in":30, "interval":1})
            elif self.path == "/identity/token":
                self.reply(200, {"access_token":"private-user-token", "token_type":"Bearer", "refresh_token":"never-save-this"})
            elif self.path == "/evaluate":
                request = EvaluationRequest.model_validate_json(body)
                result = unavailable(request, "PUBLIC_SAMPLE").model_copy(update={"status":"evaluated", "risk_score":0,
                    "policy_action":PolicyAction.ALLOW, "execution_requirement":ExecutionRequirement.NONE})
                self.reply(200, result.model_dump(mode="json"))
            else:
                self.reply(404, {})
    server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        executable=os.getenv("PROMPTRAIL_TEST_EXECUTABLE", str(Path(sys.executable).parent/"promptrail"))
        env=os.environ | {"PROMPTRAIL_GATEWAY_URL":f"http://127.0.0.1:{server.server_port}",
                          "PROMPTRAIL_AUTH_TOKEN":"private-user-token"}
        env.pop("PYTHONPATH",None)
        def run(*args):
            result=subprocess.run([executable,*args],env=env,cwd=tmp_path,capture_output=True,text=True,timeout=15)
            assert all(value not in result.stdout+result.stderr for value in ["private-user-token","private-device-code","never-save-this"])
            return result
        for operation in ["signup","signin"]:
            result=run("auth",operation,"--no-store","--verify-evaluation")
            assert result.returncode==0,result.stdout+result.stderr
            assert "Credential was not stored" in result.stdout and "Authenticated evaluation succeeded" in result.stdout
        result=run("auth","status","--json")
        assert result.returncode==0 and json.loads(result.stdout)["permissions"]==["example:inspect"]
        state["expired"]=True
        result=run("auth","status","--json")
        assert result.returncode==1 and json.loads(result.stdout)["reason_code"]=="TOKEN_EXPIRED"
        state["registration"]=False
        count=len(state["posts"])
        result=run("auth","signup","--no-store")
        assert result.returncode==2 and "SIGNUP_UNAVAILABLE" in result.stdout+result.stderr
        assert len(state["posts"])==count
    finally:
        server.shutdown();server.server_close();thread.join(timeout=5)
