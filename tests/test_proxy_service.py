"""Tests for the sandbox egress proxy service."""

from __future__ import annotations

from collections.abc import Iterator

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