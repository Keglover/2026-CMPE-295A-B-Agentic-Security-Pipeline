"""
Tool definitions for the LLM (OpenAI function-calling format).

These MUST match the TOOL_SCHEMAS dict in app/gateway/gateway.py exactly.
If you add a tool to the gateway, add the matching definition here.
"""

from __future__ import annotations

# OpenAI function-calling tool definitions.
# Reference: https://platform.openai.com/docs/guides/function-calling

TOOL_DEFINITIONS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "summarize",
            "description": "Summarize a piece of text into a concise version.",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "The text to summarize.",
                    },
                },
                "required": ["text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_note",
            "description": "Save a note with a title and body.",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Title of the note.",
                    },
                    "body": {
                        "type": "string",
                        "description": "Body content of the note.",
                    },
                },
                "required": ["title", "body"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_notes",
            "description": "Search through saved notes by keyword query.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query string.",
                    },
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_url",
            "description": "Fetch the content of a web page by URL.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL to fetch.",
                    },
                },
                "required": ["url"],
            },
        },
    },
]
