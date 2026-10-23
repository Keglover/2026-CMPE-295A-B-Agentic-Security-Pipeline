"""Pinned OIDC issuer, RS256 verification, bounded JWKS cache, and permissions."""

import os
import threading
import time
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urlsplit

import httpx
import jwt


class AuthenticationError(Exception):
    """Carry a public reason code and HTTP status without upstream response text."""
    def __init__(self, code: str, status: int = 401):
        """Store the safe error code and response status."""
        self.code, self.status = code, status
        super().__init__(code)


def validated_url(value: str) -> str:
    """Accept credential-free identity URLs, requiring HTTPS outside loopback."""
    parsed = urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or any(char.isspace() for char in value)):
        raise ValueError("Invalid identity URL")
    parsed.port
    if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Identity provider requires HTTPS outside loopback")
    return value


def origin(value: str):
    """Return scheme, hostname and effective port for same-origin comparisons."""
    parsed = urlsplit(value)
    return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


@dataclass(frozen=True)
class OIDCSettings:
    """Immutable server configuration used to pin the token verification authority."""
    mode: str
    provider: str
    issuer: str
    client_id: str
    audience: str

    def __post_init__(self):
        """Require Keycloak authentication and validate issuer/client/audience settings."""
        if self.mode != "required" or self.provider != "keycloak":
            raise ValueError("Unsupported authentication configuration")
        validated_url(self.issuer)
        for value in (self.client_id, self.audience):
            if not value or len(value) > 256 or any(char.isspace() for char in value):
                raise ValueError("Invalid identity configuration")


def load_settings() -> OIDCSettings:
    """Read server-only environment settings with local development defaults."""
    return OIDCSettings(mode=os.getenv("PROMPTRAIL_AUTH_MODE", "required"),
        provider=os.getenv("PROMPTRAIL_OIDC_PROVIDER", "keycloak"),
        issuer=os.getenv("PROMPTRAIL_OIDC_ISSUER", "http://127.0.0.1:8080/realms/promptrail"),
        client_id=os.getenv("PROMPTRAIL_OIDC_CLIENT_ID", "promptrail-cli"),
        audience=os.getenv("PROMPTRAIL_OIDC_AUDIENCE", "promptrail-gateway"))


@dataclass(frozen=True)
class Identity:
    """Verified signed claims; permissions are requested scopes intersected with realm roles."""
    subject: str
    issuer: str
    audience: str
    provider: str
    permissions: frozenset[str]
    expires_at: int


class TokenVerifier:
    """Verify RS256 access tokens using a bounded, synchronized cache of issuer public keys."""
    def __init__(self, settings: OIDCSettings, *, transport=None, clock=time.monotonic):
        """Initialize an empty key cache with injectable HTTP transport and cache clock."""
        self.settings, self.transport, self.clock = settings, transport, clock
        self._keys = {}
        self._refreshed = float("-inf")
        self._last_attempt = float("-inf")
        self._lock = threading.Lock()

    def _json(self, url: str) -> dict:
        """Fetch at most 1 MiB of JSON from the configured issuer origin."""
        validated_url(url)
        # Discovery must not send the server to an unrelated signing-key endpoint.
        if origin(url) != origin(self.settings.issuer):
            raise AuthenticationError("IDENTITY_CONFIGURATION_INVALID", 503)
        # Ignore ambient proxy settings and refuse redirects when fetching trusted metadata.
        with httpx.Client(timeout=5, trust_env=False, follow_redirects=False, transport=self.transport) as client:
            with client.stream("GET", url, headers={"Accept": "application/json"}) as response:
                response.raise_for_status()
                data = bytearray()
                for chunk in response.iter_bytes(chunk_size=65536):
                    data.extend(chunk)
                    if len(data) > 1048576:
                        raise ValueError("Identity response too large")
        import json
        result = json.loads(data)
        if not isinstance(result, dict):
            raise ValueError("Invalid identity response")
        return result

    def _refresh(self):
        """Load pinned discovery and supported public keys, replacing the cache on success."""
        self._last_attempt = self.clock()
        try:
            metadata = self._json(self.settings.issuer.rstrip("/") + "/.well-known/openid-configuration")
            if metadata.get("issuer") != self.settings.issuer:
                raise ValueError("Issuer mismatch")
            document = self._json(metadata["jwks_uri"])
            entries = document["keys"]
            if not isinstance(entries, list) or not 1 <= len(entries) <= 100:
                raise ValueError("Invalid signing keys")
            keys = {}
            for entry in entries:
                if (entry.get("kty") != "RSA" or entry.get("use", "sig") != "sig"
                        or entry.get("alg", "RS256") != "RS256"):
                    continue
                if "key_ops" in entry and "verify" not in entry["key_ops"]:
                    continue
                kid = entry["kid"]
                if not isinstance(kid, str) or not kid or len(kid) > 128 or kid in keys:
                    raise ValueError("Invalid signing key identifier")
                if any(field in entry for field in ("d", "p", "q")):
                    raise ValueError("Private signing key in public metadata")
                keys[kid] = jwt.PyJWK.from_dict(entry, algorithm="RS256").key
            if not keys:
                raise ValueError("No supported signing keys")
            # Replace the cache only after the complete new public-key document passes validation.
            self._keys, self._refreshed = keys, self.clock()
        except AuthenticationError:
            raise
        except Exception:
            raise AuthenticationError("IDENTITY_UNAVAILABLE", 503) from None

    def verify(self, token: str) -> Identity:
        """Return verified identity or a safe authentication error; never trust unsigned claims."""
        if not isinstance(token, str) or not token or len(token) > 16384 or any(char.isspace() for char in token):
            raise AuthenticationError("INVALID_TOKEN")
        try:
            # The unverified header selects a cached key only; it never grants authority.
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if (header.get("alg") != "RS256" or not isinstance(kid, str)
                    or not kid or len(kid) > 128 or "crit" in header):
                raise AuthenticationError("INVALID_TOKEN")
            with self._lock:
                now = self.clock()
                # Cache keys for five minutes; throttle unknown-key refreshes to one per ten seconds.
                if now - self._refreshed >= 300 or kid not in self._keys:
                    if now - self._last_attempt < 10:
                        if now - self._refreshed >= 300:
                            raise AuthenticationError("IDENTITY_UNAVAILABLE", 503)
                    else:
                        self._refresh()
                key = self._keys.get(kid)
            if key is None:
                raise AuthenticationError("INVALID_TOKEN")
            # Pin the algorithm and configured authority; never use values from the token as trust settings.
            claims = jwt.decode(token, key, algorithms=["RS256"], audience=self.settings.audience,
                issuer=self.settings.issuer, options={"require": ["exp", "iat", "iss", "aud", "sub"]})
            if (claims.get("azp") != self.settings.client_id or not isinstance(claims["sub"], str)
                    or not claims["sub"] or len(claims["sub"]) > 256
                    or type(claims["exp"]) is not int or type(claims["iat"]) is not int
                    or claims["exp"] <= claims["iat"]):
                raise AuthenticationError("INVALID_TOKEN")
            scope = claims.get("scope", "")
            if not isinstance(scope, str):
                raise AuthenticationError("INVALID_TOKEN")
            grants = claims.get("realm_access", {}).get("roles", [])
            if not isinstance(grants, list) or any(not isinstance(value, str) for value in grants):
                raise AuthenticationError("INVALID_TOKEN")
            # Requesting a scope cannot create a role, and a role outside the requested scope is inactive.
            permissions = frozenset(scope.split()) & frozenset(grants)
            return Identity(claims["sub"], self.settings.issuer, self.settings.audience,
                            self.settings.provider, permissions, claims["exp"])
        except AuthenticationError:
            raise
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("TOKEN_EXPIRED") from None
        except jwt.MissingRequiredClaimError as error:
            raise AuthenticationError("TOKEN_SUBJECT_MISSING" if error.claim == "sub"
                                      else "TOKEN_CLAIM_MISSING") from None
        except Exception:
            raise AuthenticationError("INVALID_TOKEN") from None


@lru_cache(maxsize=8)
def get_verifier(settings: OIDCSettings) -> TokenVerifier:
    """Reuse up to eight verifiers keyed by immutable server configuration."""
    return TokenVerifier(settings)
