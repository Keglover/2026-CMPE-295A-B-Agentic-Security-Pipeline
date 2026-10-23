"""Gateway-only RSA signing and runner-only verification of one dispatch."""

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.auth.oidc import AuthenticationError

ISSUER = "jev-gateway"
RUNNER_AUDIENCE = "jev-tool-runner"
AGENT_AUDIENCE = "jev-agent"


def args_hash(args):
    return hashlib.sha256(json.dumps(args, sort_keys=True, allow_nan=False).encode()).hexdigest()


def _key(variable, private=False):
    path = os.getenv(variable)
    if not path:
        raise AuthenticationError("SIGNING_CONFIGURATION_UNAVAILABLE", 503)
    try:
        data = Path(path).read_bytes()
        key = (serialization.load_pem_private_key(data, password=None) if private
               else serialization.load_pem_public_key(data))
        expected = rsa.RSAPrivateKey if private else rsa.RSAPublicKey
        if not isinstance(key, expected) or key.key_size < 2048:
            raise ValueError("Unsupported key")
        return key
    except Exception:
        raise AuthenticationError("SIGNING_CONFIGURATION_UNAVAILABLE", 503) from None


def sign(audience, subject, lifetime, **claims):
    now = int(time.time())
    if not 1 <= lifetime <= 300:
        raise ValueError("Invalid token lifetime")
    return jwt.encode(claims | {"iss": ISSUER, "aud": audience, "sub": subject,
                      "iat": now, "exp": now + lifetime, "jti": str(uuid4())},
                      _key("JEV_GATEWAY_SIGNING_KEY", private=True), algorithm="RS256")


def verify(token, audience, *, public_variable="JEV_GATEWAY_VERIFY_KEY", lifetime=300):
    if not isinstance(token, str) or not token or len(token) > 16384 or any(c.isspace() for c in token):
        raise AuthenticationError("CAPABILITY_INVALID")
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256" or header.get("crit"):
            raise ValueError("Invalid algorithm")
        claims = jwt.decode(token, _key(public_variable), algorithms=["RS256"],
                            issuer=ISSUER, audience=audience,
                            options={"require": ["iss", "aud", "sub", "iat", "exp", "jti"]})
        if (type(claims["iat"]) is not int or type(claims["exp"]) is not int
                or not 0 < claims["exp"] - claims["iat"] <= lifetime
                or not isinstance(claims["sub"], str) or not 0 < len(claims["sub"]) <= 256
                or not isinstance(claims["jti"], str) or not 0 < len(claims["jti"]) <= 128):
            raise ValueError("Invalid claims")
        return claims
    except AuthenticationError:
        raise
    except Exception:
        raise AuthenticationError("CAPABILITY_INVALID") from None


def issue_runner(request, policy, trace_id):
    from app.gateway.gateway import REGISTRY_VERSION, action_fingerprint
    from app.policy.engine import POLICY_VERSION
    return sign(RUNNER_AUDIENCE, request.agent_id or "anonymous", 60,
                request_id=request.request_id, trace_id=trace_id, tool=request.proposed_tool,
                args_hash=args_hash(request.tool_args or {}), action_hash=action_fingerprint(request, policy),
                policy_version=POLICY_VERSION, registry_version=REGISTRY_VERSION)


def authorize_runner(token, tool, args):
    """Check the payload, then atomically burn the nonce before any job is created."""
    from app.gateway.validation import validate_tool_args
    from app.gateway.domain_validation import validate_tool_urls
    from app.policy.config_loader import load_tool_registry, load_policy_config
    claims = verify(token, RUNNER_AUDIENCE, public_variable="JEV_RUNNER_VERIFY_KEY", lifetime=60)
    registry = load_tool_registry()
    for field in ("request_id", "trace_id", "action_hash", "args_hash", "policy_version", "registry_version"):
        if not isinstance(claims.get(field), str) or not 0 < len(claims[field]) <= 128:
            raise AuthenticationError("CAPABILITY_INVALID")
    if (claims.get("tool") != tool or claims["args_hash"] != args_hash(args)
            or claims["registry_version"] != str(registry.get("version"))
            or claims["policy_version"] != str(load_policy_config().get("version"))):
        raise AuthenticationError("CAPABILITY_ACTION_MISMATCH", 403)
    try:
        validate_tool_args(tool, args, registry)
        if any(not item.is_approved for item in validate_tool_urls(args)):
            raise ValueError("Invalid domains")
    except Exception:
        raise AuthenticationError("CAPABILITY_ACTION_MISMATCH", 403) from None
    database = os.getenv("JEV_RUNNER_NONCE_DB")
    if not database:
        raise AuthenticationError("NONCE_STORE_UNAVAILABLE", 503)
    try:
        path = Path(database)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.fchmod(fd, 0o600)
            if os.geteuid() == 0:
                # Docker's named volume inherits the image directory's application owner.
                owner = path.parent.stat()
                os.fchown(fd, owner.st_uid, owner.st_gid)
        finally:
            os.close(fd)
        with sqlite3.connect(path, timeout=5) as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS consumed (nonce TEXT PRIMARY KEY, expires INTEGER NOT NULL)")
            connection.execute("DELETE FROM consumed WHERE expires < ?", (int(time.time()),))
            connection.execute("INSERT INTO consumed VALUES (?, ?)", (claims["jti"], claims["exp"]))
    except sqlite3.IntegrityError:
        raise AuthenticationError("CAPABILITY_REPLAY", 403) from None
    except Exception:
        raise AuthenticationError("NONCE_STORE_UNAVAILABLE", 503) from None
    return claims
