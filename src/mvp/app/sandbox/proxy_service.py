"""Internal egress proxy for sandboxed HTTP fetches."""

from __future__ import annotations

import ipaddress
import re
from html import unescape
from html.parser import HTMLParser
from io import StringIO
from typing import Any
from urllib.parse import urlparse
import json

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.policy.config_loader import load_tool_registry


app = FastAPI(title="Sandbox Egress Proxy", version="0.1.0")

import os

# Local Ollama endpoint for models that are pulled locally (e.g. mistral:latest).
_OLLAMA_LOCAL_URL = os.getenv("OLLAMA_LOCAL_URL", "http://ollama:11434")

# Ollama Cloud API endpoint for `:cloud` suffix models (e.g. kimi-k2.5:cloud).
# These models are not pulled locally — inference runs on Ollama's infrastructure.
# Authentication: OLLAMA_API_KEY env var → "Authorization: Bearer <key>" header.
# No API key → request still reaches the cloud (returns 401/403 proving the chain).
_OLLAMA_CLOUD_URL = os.getenv("OLLAMA_CLOUD_URL", "https://api.ollama.com")
_OLLAMA_API_KEY = os.getenv("OLLAMA_API_KEY", "")

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


class _HTMLStripper(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._text = StringIO()
        self._skip = False

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag in ("script", "style", "noscript"):
            self._skip = True

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "noscript"):
            self._skip = False

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self._text.write(data)

    def get_text(self) -> str:
        return self._text.getvalue()


class FetchRequest(BaseModel):
    url: str = Field(..., min_length=1)


def _get_allowlist() -> set[str]:
    registry = load_tool_registry()
    return {domain.lower() for domain in registry.get("domain_allowlist", ["example.com"])}


def _get_max_response_bytes() -> int:
    registry = load_tool_registry()
    proxy_cfg = registry.get("egress_proxy", {})
    return int(proxy_cfg.get("max_response_bytes", 10 * 1024 * 1024))


def _is_private_ip(hostname: str) -> bool:
    try:
        addr = ipaddress.ip_address(hostname)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def _strip_html(html: str) -> str:
    stripper = _HTMLStripper()
    stripper.feed(html)
    return stripper.get_text()


def _normalize_text(text: str) -> str:
    text = unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > 5000:
        text = text[:5000] + "... [truncated]"
    return text


def _fetch_remote_text(url: str) -> str:
    max_bytes = _get_max_response_bytes()
    with httpx.Client(timeout=10.0, follow_redirects=True, max_redirects=3) as client:
        with client.stream("GET", url, headers={"User-Agent": "AgenticSecurityPipeline/0.2"}) as response:
            response.raise_for_status()
            content = bytearray()
            for chunk in response.iter_bytes():
                remaining = max_bytes - len(content)
                if remaining <= 0:
                    break
                content.extend(chunk[:remaining])
                if len(content) >= max_bytes:
                    break

            text = content.decode(response.encoding or "utf-8", errors="ignore")
            return _normalize_text(_strip_html(text))


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "allowlist_size": len(_get_allowlist())}


@app.post("/fetch")
def fetch(request: FetchRequest) -> dict[str, str]:
    url = request.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise HTTPException(status_code=400, detail="Could not parse hostname from URL.")

    if _is_private_ip(hostname):
        raise HTTPException(status_code=400, detail=f"Access to private/internal address '{hostname}' is blocked.")

    allowlist = _get_allowlist()
    if not any(hostname == domain or hostname.endswith("." + domain) for domain in allowlist):
        raise HTTPException(
            status_code=400,
            detail=f"Domain '{hostname}' is not in the allowlist.",
        )

    try:
        content = _fetch_remote_text(url)
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail=f"Request to '{hostname}' timed out.") from exc
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail=f"HTTP {exc.response.status_code} from '{hostname}'.") from exc
    except httpx.ConnectError as exc:
        raise HTTPException(status_code=502, detail=f"Could not connect to '{hostname}'.") from exc

    return {"content": content or "Page fetched but no text content found."}


from fastapi import Request, Response
from fastapi.responses import StreamingResponse


@app.post("/api/generate")
async def proxy_ollama_generate(request: Request):
    """
    Proxy /api/generate, routing based on model suffix:

    - Model ends with ':cloud'  → Ollama Cloud API (https://api.ollama.com)
      Auth: Authorization: Bearer $OLLAMA_API_KEY
      The model is NOT pulled locally — weights stay on Ollama's infrastructure.
      No subscription → 403; no API key → 401. Either proves the chain reaches
      the cloud endpoint successfully.

    - All other models → local Ollama daemon at OLLAMA_LOCAL_URL
      Requires the model to be pulled: docker exec ollama ollama pull <model>
    """
    body_bytes = await request.body()
    max_bytes = _get_max_response_bytes()

    # Determine target from model name in the request body.
    try:
        model = json.loads(body_bytes).get("model", "")
    except (json.JSONDecodeError, AttributeError):
        model = ""

    is_cloud = isinstance(model, str) and model.endswith(":cloud")
    if is_cloud:
        target_url = f"{_OLLAMA_CLOUD_URL}/api/generate"
        headers = {"Content-Type": "application/json"}
        if _OLLAMA_API_KEY:
            headers["Authorization"] = f"Bearer {_OLLAMA_API_KEY}"
    else:
        target_url = f"{_OLLAMA_LOCAL_URL}/api/generate"
        headers = {"Content-Type": "application/json"}

    async def fetch_and_stream():
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    target_url,
                    content=body_bytes,
                    headers=headers,
                )
                response.raise_for_status()
                payload = response.content
                if len(payload) > max_bytes:
                    yield json.dumps({"error": "Response from Ollama exceeded size limit."}).encode()
                    return
                yield payload
        except httpx.TimeoutException:
            yield json.dumps({"error": "Gateway Timeout: Ollama did not respond in time."}).encode()
        except httpx.HTTPStatusError as exc:
            error_body = exc.response.text[:500]
            yield json.dumps({"error": f"Ollama HTTP {exc.response.status_code}: {error_body}"}).encode()
        except httpx.HTTPError as exc:
            yield json.dumps({"error": str(exc)}).encode()

    return StreamingResponse(fetch_and_stream(), media_type="application/json")


@app.get("/api/tags")
async def proxy_ollama_tags():
    """
    Proxy GET /api/tags to local Ollama so ephemeral containers can list
    available models without needing direct access to ollama:11434.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{_OLLAMA_LOCAL_URL}/api/tags")
            response.raise_for_status()
            return response.json()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Could not reach Ollama: {exc}") from exc