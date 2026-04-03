"""
Configuration Loader for Policy Engine and Tool Gateway.

Project Plan Ref: Tasks 4.4, 4.5, 3.3 (Phase 2–4)

Loads externalized configuration from YAML files, replacing hardcoded
values in policy/engine.py and gateway/gateway.py.

Supports:
  - Policy threshold configuration (config/policy_thresholds.yaml)
  - Tool registry configuration (config/tool_registry.yaml)
  - Future: hot-reload via file watching

TODO List:
    - [ ] Task 4.4  — Wire policy engine to read thresholds from loaded config
    - [ ] Task 4.5  — Implement file-watch for hot-reload without restart
    - [ ] Task 3.3  — Wire gateway to read tool registry from loaded config
    - [ ] Task 2.11 — Support policy rule DSL or structured YAML format
    - [ ] Task 4.18 — Track policy rule version from config file
    - [ ] Add config validation (Pydantic models for config schema)
    - [ ] Add fallback to hardcoded defaults if config file is missing
    - [ ] Write unit tests in tests/test_config_loader.py
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

_log = logging.getLogger("config_loader")

# ---------------------------------------------------------------------------
# Config directory resolution
# ---------------------------------------------------------------------------
_CONFIG_DIR = Path(os.getenv(
    "CONFIG_DIR",
    str(Path(__file__).resolve().parent.parent.parent / "config"),
))

_POLICY_CONFIG_FILE = "policy_thresholds.yaml"
_TOOL_REGISTRY_FILE = "tool_registry.yaml"


def _load_yaml(filepath: Path) -> dict[str, Any]:
    """
    Load and parse a YAML file.

    Args:
        filepath: Path to the YAML file.

    Returns:
        dict: Parsed YAML content.

    Raises:
        FileNotFoundError: If the config file does not exist.
        ImportError: If PyYAML is not installed.
    """
    try:
        import yaml
    except ImportError:
        _log.warning(
            "PyYAML not installed — config loading unavailable. "
            "Install with: pip install pyyaml"
        )
        raise ImportError(
            "PyYAML is required for config loading. Add 'pyyaml' to requirements.txt."
        )

    if not filepath.exists():
        raise FileNotFoundError(f"Config file not found: {filepath}")

    with filepath.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    _log.info("Loaded config from %s", filepath)
    return data or {}


def load_policy_config() -> dict[str, Any]:
    """
    Load policy threshold configuration.

    Returns:
        dict: Policy configuration with keys: thresholds, high_attention_categories,
              fail_closed, etc.

    Falls back to hardcoded defaults if the config file is missing.

    TODO: [ ] Validate loaded config against a Pydantic schema
    """
    filepath = _CONFIG_DIR / _POLICY_CONFIG_FILE
    try:
        return _load_yaml(filepath)
    except (FileNotFoundError, ImportError) as e:
        _log.warning("Using hardcoded policy defaults: %s", e)
        return {
            "version": "1.0-fallback",
            "thresholds": {
                "block": 80,
                "quarantine": 60,
                "require_approval": 35,
                "sanitize": 15,
            },
            "high_attention_categories": [
                "TOOL_COERCION",
                "DATA_EXFILTRATION",
            ],
            "high_attention_min_score": 15,
            "fail_closed": {
                "default_action": "BLOCK",
                "default_reason": "Risk Engine unreachable — fail-closed to BLOCK",
                "log_as_error": True,
            },
        }


def load_tool_registry() -> dict[str, Any]:
    """
    Load tool registry configuration.

    Returns:
        dict: Tool registry with keys: tools, domain_allowlist, rate_limits.

    Falls back to hardcoded defaults if the config file is missing.

    TODO: [ ] Validate loaded config against a Pydantic schema
    """
    filepath = _CONFIG_DIR / _TOOL_REGISTRY_FILE
    try:
        return _load_yaml(filepath)
    except (FileNotFoundError, ImportError) as e:
        _log.warning("Using hardcoded tool registry defaults: %s", e)
        return {
            "version": "1.0-fallback",
            "tools": {
                "summarize": {"required_args": ["text"], "risk_tier": "low", "enabled": True},
                "write_note": {"required_args": ["title", "body"], "risk_tier": "medium", "enabled": True},
                "search_notes": {"required_args": ["query"], "risk_tier": "low", "enabled": True},
                "fetch_url": {"required_args": ["url"], "risk_tier": "high", "enabled": True},
            },
            "domain_allowlist": ["example.com"],
        }
