"""Bounded agent transport. Credentials stay inside the session object."""
import json

import httpx

from promptrail.agent.models import AgentCredential, ToolCallResponse, ApprovalState
from promptrail.client import GatewayClient, request_hash


class SecurityException(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class AgentSession:
    def __init__(self, settings, user_token, *, transport=None):
        self.settings, self.user_token, self.transport = settings, user_token, transport
        self.credential = None
        self.http = httpx.Client(timeout=settings.timeout, trust_env=False,
                                 follow_redirects=False, transport=transport)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.http.close()
        self.user_token = None
        self.credential = None

    def _post(self, path, token, payload):
        try:
            with self.http.stream("POST", self.settings.gateway_url + path,
                                  headers={"Authorization": "Bearer " + token}, json=payload) as response:
                if response.status_code != 200:
                    raise SecurityException("GATEWAY_DENIED" if response.status_code in {401, 403} else "GATEWAY_UNAVAILABLE")
                data = bytearray()
                for chunk in response.iter_bytes(chunk_size=65536):
                    data.extend(chunk)
                    if len(data) > 1048576:
                        raise SecurityException("INVALID_GATEWAY_RESPONSE")
                return bytes(data)
        except httpx.HTTPError:
            raise SecurityException("GATEWAY_UNAVAILABLE") from None

    def exchange(self, tools, agent_id=None):
        try:
            credential = AgentCredential.model_validate_json(self._post("/auth/agent-token", self.user_token,
                {"tools": tools, "agent_id": agent_id}))
            if (set(credential.tools) != set(tools)
                    or set(credential.permissions) != {"jev:evaluate", "jev:tools:call"}
                    or (agent_id is not None and credential.agent_id != agent_id)
                    or not 0 < len(credential.access_token.get_secret_value()) <= 16384):
                raise ValueError("Invalid agent grant")
            self.credential = credential
            self.user_token = None
            return credential.agent_id
        except ValueError:
            raise SecurityException("INVALID_AGENT_GRANT") from None

    def call(self, request):
        if self.credential is None or request.proposed_tool not in self.credential.tools:
            raise SecurityException("AGENT_TOOL_DENIED")
        try:
            result = ToolCallResponse.model_validate_json(self._post("/tools/call",
                self.credential.access_token.get_secret_value(), request.model_dump(mode="json")))
            if (result.evaluation.request_id != request.request_id
                    or result.evaluation.content_hash != request_hash(request)
                    or (result.outcome == "EXECUTED" and result.evaluation.status != "evaluated")):
                raise ValueError("Invalid result")
            return result
        except ValueError:
            raise SecurityException("INVALID_GATEWAY_RESPONSE") from None

    def evaluate(self, request):
        with GatewayClient(self.settings, token=self.credential.access_token.get_secret_value(),
                           transport=self.transport) as client:
            return client.evaluate(request)

    def approval_status(self, request_id):
        if self.credential is None:
            raise SecurityException("LOGIN_REQUIRED")
        try:
            import re
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", request_id):
                raise ValueError("Invalid request identifier")
            with self.http.stream("GET", self.settings.gateway_url + "/tools/requests/" + request_id,
                    headers={"Authorization": "Bearer " + self.credential.access_token.get_secret_value()}) as response:
                if response.status_code != 200:
                    raise SecurityException("APPROVAL_STATE_UNAVAILABLE")
                data = bytearray()
                for chunk in response.iter_bytes(chunk_size=4096):
                    data.extend(chunk)
                    if len(data) > 16384:
                        raise ValueError("Oversized status response")
                state = ApprovalState.model_validate_json(data)
                if state.request_id != request_id:
                    raise ValueError("Mismatched status response")
                return state.status
        except httpx.HTTPError:
            raise SecurityException("APPROVAL_STATE_UNAVAILABLE") from None
        except ValueError:
            raise SecurityException("INVALID_APPROVAL_STATE") from None
