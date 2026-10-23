"""Launch a separate authenticated host API; leave the existing stack alone."""

import os
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
runtime = root / "auth" / ".runtime"
runtime.mkdir(mode=0o700, exist_ok=True)
env = os.environ | {"JEV_AUTH_MODE": "required", "JEV_OIDC_PROVIDER": "keycloak",
    "JEV_OIDC_ISSUER": "http://127.0.0.1:8080/realms/jev", "JEV_OIDC_CLIENT_ID": "jev-cli",
    "JEV_OIDC_AUDIENCE": "jev-gateway", "REAL_TOOLS": "false", "LLM_JUDGE_ENABLED": "false",
    "AUDIT_LOG_PATH": str(runtime / "pipeline.ndjson"),
    "JEV_GATEWAY_SIGNING_KEY": str(runtime / "gateway-signing.pem"),
    "JEV_GATEWAY_VERIFY_KEY": str(runtime / "gateway-verify.pem"),
    "JEV_GATEWAY_STATE_DB": str(runtime / "gateway-state.sqlite3"),
    "JEV_APPROVAL_PENDING_TTL": "604800", "JEV_APPROVAL_GRANT_TTL": "300",
    "EXECUTION_AUDIT_LOG_PATH": str(runtime / "execution.ndjson"),
    "EVALUATION_AUDIT_LOG_PATH": str(runtime / "evaluation.ndjson")}
os.chdir(root / "src" / "mvp")
os.execve(sys.executable, [sys.executable, "-m", "uvicorn", "app.main:app",
                          "--host", "127.0.0.1", "--port", "8003"], env)
