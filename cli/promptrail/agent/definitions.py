"""Model hints only. The gateway independently validates every proposal."""
from copy import deepcopy

from promptrail.agent.client import SecurityException

_FIELDS = {
    "summarize": ({"text": {"type": "string", "maxLength": 50000}}, ["text"]),
    "write_note": ({"title": {"type": "string", "maxLength": 200, "pattern": r"^[a-zA-Z0-9_\-\s]+$"},
                    "body": {"type": "string", "maxLength": 10000}}, ["title", "body"]),
    "search_notes": ({"query": {"type": "string", "maxLength": 500}}, ["query"]),
    "fetch_url": ({"url": {"type": "string", "maxLength": 2048}}, ["url"]),
    "execute_command": ({"command": {"type": "string", "maxLength": 4000},
                         "timeout_sec": {"type": "number", "minimum": 1, "maximum": 60},
                         "working_dir": {"type": "string", "maxLength": 200}}, ["command"]),
    "transcribe_audio": ({"audio_url": {"type": "string", "maxLength": 2048},
                          "language": {"type": "string", "maxLength": 10, "enum": ["en", "es", "fr", "de", "zh", "ja", "auto"]},
                          "response_format": {"type": "string", "maxLength": 20, "enum": ["json", "text", "srt", "verbose_json"]}}, ["audio_url"]),
    "analyze_image": ({"image_url": {"type": "string", "maxLength": 2048},
                       "prompt": {"type": "string", "maxLength": 2000},
                       "detail_level": {"type": "string", "maxLength": 20, "enum": ["low", "high", "auto"]}}, ["image_url", "prompt"]),
    "document_qa": ({"document_url": {"type": "string", "maxLength": 2048},
                     "query": {"type": "string", "maxLength": 2000},
                     "page_hint": {"type": "number", "minimum": 1, "maximum": 999}}, ["document_url", "query"]),
}


def definitions(tools):
    if not tools or len(set(tools)) != len(tools) or any(tool not in _FIELDS for tool in tools):
        raise SecurityException("INVALID_AGENT_TOOLS")
    return [{"type": "function", "function": {"name": tool,
             "description": "Propose " + tool + " through the security gateway; approval may be required.",
             "parameters": {"type": "object", "properties": deepcopy(_FIELDS[tool][0]),
                            "required": list(_FIELDS[tool][1]), "additionalProperties": False}}} for tool in tools]
