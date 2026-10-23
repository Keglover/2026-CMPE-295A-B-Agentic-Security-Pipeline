"""Read-only readiness checks. A healthy gateway is not execution authority."""
import json

import httpx

from promptrail.auth.providers import LoginProfile, origin


class ReadinessError(Exception):
    pass


def inspect_gateway(settings, *, transport=None):
    def read(client, url):
        with client.stream("GET", url) as response:
            if response.status_code != 200:
                raise ReadinessError("GATEWAY_NOT_READY")
            data = bytearray()
            for chunk in response.iter_bytes(chunk_size=16384):
                data.extend(chunk)
                if len(data) > 65536:
                    raise ReadinessError("INVALID_READINESS_RESPONSE")
            value = json.loads(data)
            if not isinstance(value, dict):
                raise ReadinessError("INVALID_READINESS_RESPONSE")
            return value

    try:
        with httpx.Client(timeout=settings.timeout, trust_env=False, follow_redirects=False,
                          transport=transport) as client:
            health = read(client, settings.gateway_url + "/health")
            if health.get("status") != "ok":
                raise ReadinessError("GATEWAY_NOT_READY")
            profile = LoginProfile.model_validate(read(client, settings.gateway_url + "/auth/config"))
            if origin(settings.gateway_url)[0] == "https" and origin(profile.issuer)[0] != "https":
                raise ReadinessError("INSECURE_IDENTITY_PROVIDER")
            mode = health.get("executor_mode", "UNKNOWN")
            if mode not in {"MOCK", "SANDBOX", "UNKNOWN"}:
                raise ReadinessError("INVALID_READINESS_RESPONSE")
            return {"gateway_url": settings.gateway_url, "gateway_reachable": True,
                    "authentication_required": True, "provider": profile.provider,
                    "executor_mode": mode, "execution_authorized": False}
    except ReadinessError:
        raise
    except (httpx.HTTPError, ValueError, TypeError):
        raise ReadinessError("READINESS_UNAVAILABLE") from None
