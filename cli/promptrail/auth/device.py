"""Bounded RFC 8628 flow and gateway verification before credential storage."""

import json
import time

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from promptrail.auth.providers import LoginProfile, origin, provider_for
from promptrail.config import Settings


class LoginError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class DeviceChallenge(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    device_code: SecretStr
    user_code: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9-]+$")
    verification_uri: str
    verification_uri_complete: str | None = None
    expires_in: int = Field(gt=0, le=900)
    interval: int = Field(default=5, gt=0, le=60)

    @field_validator("device_code")
    @classmethod
    def bounded_code(cls, value):
        if not 1 <= len(value.get_secret_value()) <= 4096:
            raise ValueError("Invalid device code")
        return value


class VerifiedIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    subject: str = Field(min_length=1, max_length=256)
    issuer: str
    audience: str
    provider: str
    permissions: list[str]
    expires_at: int = Field(gt=0)


class DeviceLogin:
    def __init__(self, settings: Settings, *, transport=None, clock=time.monotonic, sleep=time.sleep):
        self.settings, self.clock, self.sleep = settings, clock, sleep
        self.http = httpx.Client(timeout=settings.timeout, trust_env=False,
                                 follow_redirects=False, transport=transport)
        self.profile = None
        self.token_endpoint = None
        self._deadline = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.http.close()

    def _request(self, method: str, url: str, **kwargs):
        try:
            with self.http.stream(method, url, **kwargs) as response:
                data = bytearray()
                for chunk in response.iter_bytes(chunk_size=65536):
                    data.extend(chunk)
                    if len(data) > 1048576:
                        raise LoginError("INVALID_IDENTITY_RESPONSE")
                result = json.loads(data)
                if not isinstance(result, dict):
                    raise LoginError("INVALID_IDENTITY_RESPONSE")
                return response.status_code, result
        except httpx.TimeoutException:
            raise LoginError("IDENTITY_TIMEOUT") from None
        except httpx.HTTPError:
            raise LoginError("IDENTITY_UNAVAILABLE") from None
        except (ValueError, TypeError):
            raise LoginError("INVALID_IDENTITY_RESPONSE") from None

    def _issuer_url(self, url: str):
        parsed = Settings(gateway_url=url)
        if origin(parsed.gateway_url) != origin(self.profile.issuer):
            raise LoginError("IDENTITY_ENDPOINT_MISMATCH")
        return url

    def _verification_url(self, url: str):
        # Device browser URLs may have a user-code query, but no credentials/fragment.
        from urllib.parse import urlsplit, urlunsplit
        parsed = urlsplit(url)
        if parsed.fragment or any(char.isspace() for char in url):
            raise LoginError("INVALID_VERIFICATION_URL")
        self._issuer_url(urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")))
        return url

    def begin(self, scopes: list[str] | None = None, *, signup: bool = False) -> DeviceChallenge:
        try:
            status, profile = self._request("GET", self.settings.gateway_url + "/auth/config")
            if status != 200:
                raise LoginError("GATEWAY_CONFIGURATION_UNAVAILABLE")
            self.profile = LoginProfile.model_validate(profile)
            if signup:
                status, registration = self._request("GET", self.settings.gateway_url + "/auth/registration")
                if status != 200 or registration.get("signup_enabled") is not True:
                    raise LoginError("SIGNUP_UNAVAILABLE")
            if scopes is not None:
                self.profile = LoginProfile.model_validate(self.profile.model_dump() | {"scopes": scopes})
            if origin(self.settings.gateway_url)[0] == "https" and origin(self.profile.issuer)[0] != "https":
                raise LoginError("INSECURE_IDENTITY_PROVIDER")
            status, metadata = self._request("GET", self.profile.issuer.rstrip("/") + "/.well-known/openid-configuration")
            if status != 200 or metadata.get("issuer") != self.profile.issuer:
                raise LoginError("IDENTITY_ISSUER_MISMATCH")
            endpoint = self._issuer_url(metadata["device_authorization_endpoint"])
            self.token_endpoint = self._issuer_url(metadata["token_endpoint"])
            status, payload = self._request("POST", endpoint, data=provider_for(self.profile).device_parameters(self.profile))
            if status != 200:
                raise LoginError("DEVICE_AUTHORIZATION_FAILED")
            challenge = DeviceChallenge.model_validate(payload)
            self._verification_url(challenge.verification_uri)
            if challenge.verification_uri_complete:
                self._verification_url(challenge.verification_uri_complete)
            self._deadline = self.clock() + challenge.expires_in
            return challenge
        except LoginError:
            raise
        except Exception:
            raise LoginError("INVALID_IDENTITY_CONFIGURATION") from None

    def inspect_identity(self, token: SecretStr) -> VerifiedIdentity:
        """Verify an existing user credential against this gateway's current profile."""
        try:
            status, profile = self._request("GET", self.settings.gateway_url + "/auth/config")
            if status != 200:
                raise LoginError("GATEWAY_CONFIGURATION_UNAVAILABLE")
            self.profile = LoginProfile.model_validate(profile)
            if origin(self.settings.gateway_url)[0] == "https" and origin(self.profile.issuer)[0] != "https":
                raise LoginError("INSECURE_IDENTITY_PROVIDER")
            return self.verify(token)
        except LoginError:
            raise
        except Exception:
            raise LoginError("INVALID_IDENTITY_CONFIGURATION") from None

    def poll(self, challenge: DeviceChallenge) -> SecretStr:
        if self._deadline is None or self.token_endpoint is None:
            raise LoginError("LOGIN_NOT_STARTED")
        interval = challenge.interval
        while self.clock() < self._deadline:
            remaining = self._deadline - self.clock()
            if interval >= remaining:
                break
            self.sleep(interval)
            if self.clock() >= self._deadline:
                break
            try:
                status, payload = self._request("POST", self.token_endpoint, data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "client_id": self.profile.client_id,
                    "device_code": challenge.device_code.get_secret_value()},
                    timeout=min(self.settings.timeout, max(0.1, self._deadline - self.clock())))
            except LoginError as error:
                if error.code != "IDENTITY_TIMEOUT":
                    raise
                interval *= 2
                continue
            if status == 200:
                token = payload.get("access_token")
                token_type = payload.get("token_type")
                if (not isinstance(token_type, str) or token_type.lower() != "bearer" or not isinstance(token, str)
                        or not token or len(token) > 16384 or not token.isascii()
                        or any(char.isspace() for char in token)):
                    raise LoginError("INVALID_TOKEN_RESPONSE")
                return SecretStr(token)
            error = payload.get("error")
            if error == "authorization_pending":
                continue
            if error == "slow_down":
                interval += 5
                continue
            if error == "access_denied":
                raise LoginError("LOGIN_DENIED")
            if error == "expired_token":
                raise LoginError("DEVICE_CODE_EXPIRED")
            raise LoginError("TOKEN_REQUEST_FAILED")
        raise LoginError("DEVICE_CODE_EXPIRED")

    def verify(self, token: SecretStr) -> VerifiedIdentity:
        try:
            status, payload = self._request("GET", self.settings.gateway_url + "/auth/whoami",
                headers={"Authorization": "Bearer " + token.get_secret_value()})
            if status != 200:
                safe_codes = {"TOKEN_SUBJECT_MISSING", "TOKEN_CLAIM_MISSING", "TOKEN_EXPIRED",
                              "INSUFFICIENT_PERMISSION", "IDENTITY_UNAVAILABLE", "INVALID_TOKEN"}
                code = payload.get("reason_code")
                raise LoginError(code if code in safe_codes else "GATEWAY_TOKEN_REJECTED")
            identity = VerifiedIdentity.model_validate(payload)
            if (identity.issuer != self.profile.issuer or identity.audience != self.profile.audience
                    or identity.provider != self.profile.provider or identity.expires_at <= time.time()):
                raise LoginError("IDENTITY_MISMATCH")
            required = set(self.profile.scopes) - {"openid"}
            if not required <= set(identity.permissions):
                raise LoginError("INSUFFICIENT_PERMISSION")
            return identity
        except LoginError:
            raise
        except Exception:
            raise LoginError("INVALID_IDENTITY_RESPONSE") from None
