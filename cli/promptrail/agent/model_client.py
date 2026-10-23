"""Bounded model generation with explicit, separately credentialed failover."""
import json
import os
from urllib.parse import urlsplit
from uuid import uuid4

import httpx

from promptrail.agent.client import SecurityException
from promptrail.agent.conversation import Message
from promptrail.agent.model_config import model_values


class ModelUnavailable(SecurityException):
    pass


class ModelClient:
    def __init__(self, checkpoint, *, transport=None):
        values = model_values(checkpoint.model_env_file)
        self.endpoints = [(checkpoint.model_url, checkpoint.model_name, checkpoint.model_key_env,
                           checkpoint.token_limit_field, checkpoint.model_protocol)]
        if checkpoint.fallback_url is not None:
            self.endpoints.append((checkpoint.fallback_url, checkpoint.fallback_model or
                                   os.environ.get("JEV_FALLBACK_MODEL_NAME") or values.get("JEV_FALLBACK_MODEL_NAME"),
                                   checkpoint.fallback_key_env, checkpoint.fallback_token_limit_field, checkpoint.fallback_protocol))
        self.keys = {}
        for index, (url, model, env_name, limit_field, protocol) in enumerate(self.endpoints):
            key = os.environ.get(env_name, values.get(env_name)) or None
            if key is not None and (len(key) > 16384 or not key.isascii()
                                    or any(char.isspace() for char in key)):
                raise SecurityException("INVALID_MODEL_CREDENTIAL")
            if index == 0 and key is None and urlsplit(url).hostname not in {"127.0.0.1", "localhost", "::1"}:
                raise SecurityException("MODEL_CREDENTIAL_REQUIRED")
            self.keys[(url, env_name)] = key
        self.http = httpx.Client(timeout=30.0, trust_env=False, follow_redirects=False, transport=transport)
        self.last_endpoint = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.http.close()
        self.keys.clear()

    def _generate(self, endpoint, messages, tools):
        url, model, env_name, limit_field, protocol = endpoint
        headers = {"Accept": "application/json"}
        key = self.keys[(url, env_name)]
        if not model or (key is None and urlsplit(url).hostname not in {"127.0.0.1", "localhost", "::1"}):
            raise SecurityException("FALLBACK_CONFIGURATION_REQUIRED")
        if key is not None:
            headers["Authorization"] = "Bearer " + key
        payload = {"model": model, "messages": messages, "tools": tools,
                   "stream": False, limit_field: 2048}
        path = "/chat/completions"
        if protocol == "ollama":
            payload = {"model": model, "messages": _ollama_messages(messages), "tools": tools,
                       "stream": False, "options": {"num_predict": 2048}}
            path = "/api/chat"
        try:
            with self.http.stream("POST", url + path, headers=headers, json=payload) as response:
                if response.status_code >= 500:
                    raise ModelUnavailable("MODEL_UNAVAILABLE")
                if response.status_code != 200:
                    raise SecurityException("MODEL_REQUEST_REJECTED")
                data = bytearray()
                for chunk in response.iter_bytes(chunk_size=65536):
                    data.extend(chunk)
                    if len(data) > 1048576:
                        raise SecurityException("INVALID_MODEL_RESPONSE")
                result = json.loads(data)
                if protocol == "ollama":
                    return _ollama_reply(result)
                choices = result["choices"]
                if not isinstance(choices, list) or len(choices) != 1:
                    raise ValueError("One completion required")
                raw = choices[0]["message"]
                if raw.get("refusal"):
                    raise SecurityException("MODEL_REFUSED")
                message = Message.model_validate({name: raw[name] for name in ("role", "content", "tool_calls")
                                                  if name in raw and not (name == "tool_calls" and raw[name] is None)})
                if (message.role != "assistant" or choices[0].get("finish_reason") !=
                        ("tool_calls" if message.tool_calls else "stop")):
                    raise ValueError("Incomplete or invalid completion")
                return message
        except (httpx.NetworkError, httpx.TimeoutException):
            raise ModelUnavailable("MODEL_UNAVAILABLE") from None
        except httpx.HTTPError:
            raise SecurityException("MODEL_TRANSPORT_FAILED") from None
        except (ValueError, TypeError, KeyError, IndexError):
            raise SecurityException("INVALID_MODEL_RESPONSE") from None

    def complete(self, messages, tools):
        for index, endpoint in enumerate(self.endpoints):
            try:
                message = self._generate(endpoint, messages, tools)
                self.last_endpoint = "primary" if index == 0 else "fallback"
                return message
            except ModelUnavailable:
                if index + 1 == len(self.endpoints):
                    raise SecurityException("ALL_MODELS_UNAVAILABLE") from None


def _ollama_messages(messages):
    """Translate saved call IDs into Ollama's name/argument tool protocol."""
    from promptrail.agent.conversation import arguments
    translated, names = [], {}
    for message in messages:
        item = {name: message[name] for name in ("role", "content") if name in message}
        if message.get("tool_calls"):
            calls = []
            for call in message["tool_calls"]:
                function = call["function"]
                names[call["id"]] = function["name"]
                calls.append({"type": "function", "function": {"name": function["name"], "arguments": arguments(function["arguments"])}})
            item["tool_calls"] = calls
        if message["role"] == "tool":
            item["tool_name"] = names[message["tool_call_id"]]
        translated.append(item)
    return translated


def _ollama_reply(result):
    if result.get("done") is not True or result.get("done_reason") not in {None, "stop"}:
        raise ValueError("Incomplete model response")
    raw = result["message"]
    if raw.get("role") != "assistant":
        raise ValueError("Invalid model role")
    calls = []
    for call in raw.get("tool_calls") or []:
        function = call["function"]
        args = function["arguments"]
        if not isinstance(args, dict):
            raise ValueError("Tool arguments must be an object")
        calls.append({"id": "call_" + uuid4().hex, "type": "function",
                      "function": {"name": function["name"], "arguments": json.dumps(args, allow_nan=False)}})
    return Message.model_validate({"role": "assistant", "content": raw.get("content"), "tool_calls": calls})
