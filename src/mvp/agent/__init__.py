"""
Agent loop module — connects an LLM to the security pipeline.

The LLM proposes tool calls; this module intercepts them and routes
every call through POST /pipeline before execution.
"""
