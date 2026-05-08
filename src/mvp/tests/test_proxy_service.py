"""Tests for the sandbox egress proxy service."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.sandbox import proxy_service


client = TestClient(proxy_service.app)


def test_proxy_blocks_private_ip() -> None:
    response = client.post("/fetch", json={"url": "http://169.254.169.254/latest/meta-data"})

    assert response.status_code == 400
    assert "private/internal" in response.json()["detail"].lower()


def test_proxy_blocks_non_allowlisted_domain() -> None:
    response = client.post("/fetch", json={"url": "https://evil.com/collect"})

    assert response.status_code == 400
    assert "allowlist" in response.json()["detail"].lower()

def test_api_generate_cloud_includes_authorization_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    class _FakeResponse:
        def __init__(self, content: bytes) -> None:
            self.content = content

        def raise_for_status(self) -> None:
            return None

    class _FakeAsyncClient:
        def __init__(self, timeout: float) -> None:
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url: str, content: bytes, headers: dict[str, str]):
            calls.append({"url": url, "content": content, "headers": dict(headers)})
            return _FakeResponse(b'{"response":"ok"}')

    monkeypatch.setattr(proxy_service, "_OLLAMA_CLOUD_URL", "https://api.ollama.com")
    monkeypatch.setattr(proxy_service, "_OLLAMA_API_KEY", "test-key")
    monkeypatch.setattr(proxy_service.httpx, "AsyncClient", _FakeAsyncClient)

    response = client.post(
        "/api/generate",
        json={"model": "kimi-k2.5:cloud", "prompt": "hello", "stream": False},
    )

    assert response.status_code == 200
    assert calls
    assert calls[0]["url"] == "https://api.ollama.com/api/generate"
    assert calls[0]["headers"]["Authorization"] == "Bearer test-key"


def test_api_generate_cloud_without_key_omits_authorization_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    class _FakeResponse:
        def __init__(self, content: bytes) -> None:
            self.content = content

        def raise_for_status(self) -> None:
            return None

    class _FakeAsyncClient:
        def __init__(self, timeout: float) -> None:
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url: str, content: bytes, headers: dict[str, str]):
            calls.append({"url": url, "content": content, "headers": dict(headers)})
            return _FakeResponse(b'{"response":"ok"}')

    monkeypatch.setattr(proxy_service, "_OLLAMA_CLOUD_URL", "https://api.ollama.com")
    monkeypatch.setattr(proxy_service, "_OLLAMA_API_KEY", "")
    monkeypatch.setattr(proxy_service.httpx, "AsyncClient", _FakeAsyncClient)

    response = client.post(
        "/api/generate",
        json={"model": "kimi-k2.5:cloud", "prompt": "hello", "stream": False},
    )

    assert response.status_code == 200
    assert calls
    assert calls[0]["url"] == "https://api.ollama.com/api/generate"
    assert "Authorization" not in calls[0]["headers"]


def test_api_generate_local_model_uses_local_url_no_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    class _FakeResponse:
        def __init__(self, content: bytes) -> None:
            self.content = content

        def raise_for_status(self) -> None:
            return None

    class _FakeAsyncClient:
        def __init__(self, timeout: float) -> None:
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url: str, content: bytes, headers: dict[str, str]):
            calls.append({"url": url, "content": content, "headers": dict(headers)})
            return _FakeResponse(b'{"response":"ok"}')

    monkeypatch.setattr(proxy_service, "_OLLAMA_LOCAL_URL", "http://ollama:11434")
    monkeypatch.setattr(proxy_service, "_OLLAMA_API_KEY", "test-key")
    monkeypatch.setattr(proxy_service.httpx, "AsyncClient", _FakeAsyncClient)

    response = client.post(
        "/api/generate",
        json={"model": "mistral:latest", "prompt": "hello", "stream": False},
    )

    assert response.status_code == 200
    assert calls
    assert calls[0]["url"] == "http://ollama:11434/api/generate"
    assert "Authorization" not in calls[0]["headers"]


def test_fetch_remote_text_truncates_large_responses(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeResponse:
        encoding = "utf-8"

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def raise_for_status(self) -> None:
            return None

        def iter_bytes(self) -> Iterator[bytes]:
            yield b"A" * 32

    class _FakeClient:
        def __init__(self, timeout: float, follow_redirects: bool, max_redirects: int) -> None:
            self.timeout = timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def stream(self, method: str, url: str, headers: dict[str, str]):
            return _FakeResponse()

    monkeypatch.setattr(proxy_service.httpx, "Client", _FakeClient)
    monkeypatch.setattr(proxy_service, "_get_max_response_bytes", lambda: 10)

    text = proxy_service._fetch_remote_text("https://example.com")

    assert text == "AAAAAAAAAA"