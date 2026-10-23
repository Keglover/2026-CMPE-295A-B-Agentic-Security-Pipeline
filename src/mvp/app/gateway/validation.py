"""Registry validation reusable by inspection and future execution hardening."""

import math
import re
from urllib.parse import urlsplit


class ArgumentValidationError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def validate_tool_args(tool_name: str, arguments: dict, registry: dict) -> None:
    tools = registry["tools"]
    if tool_name not in tools or not tools[tool_name].get("enabled", True):
        raise ArgumentValidationError("UNKNOWN_TOOL")
    spec = tools[tool_name]
    required = spec["required_args"]
    allowed = set(required) | set(spec.get("optional_args", []))
    if set(required) - arguments.keys():
        raise ArgumentValidationError("MISSING_ARGUMENT")
    if arguments.keys() - allowed:
        raise ArgumentValidationError("UNKNOWN_ARGUMENT")
    types = spec["arg_types"]
    constraints = spec.get("arg_constraints", {})
    for name, value in arguments.items():
        kind = types[name]
        if kind in {"string", "url"}:
            valid = isinstance(value, str)
        elif kind == "number":
            valid = type(value) in {int, float} and math.isfinite(value)
        else:
            raise ValueError("Unsupported registry type")
        if not valid:
            raise ArgumentValidationError("INVALID_ARGUMENT_TYPE")
        if kind == "url":
            parsed = urlsplit(value)
            if (parsed.scheme not in {"https", "http"} or not parsed.hostname
                    or parsed.username is not None or parsed.password is not None
                    or any(char.isspace() for char in value)):
                raise ArgumentValidationError("INVALID_URL")
            try:
                parsed.port
            except ValueError:
                raise ArgumentValidationError("INVALID_URL") from None
        for rule, bound in constraints.get(name, {}).items():
            if rule == "max_length":
                valid = len(value) <= bound
            elif rule == "min_length":
                valid = len(value) >= bound
            elif rule == "min":
                valid = value >= bound
            elif rule == "max":
                valid = value <= bound
            elif rule == "pattern":
                valid = re.fullmatch(bound, value) is not None
            elif rule == "enum":
                valid = value in bound
            else:
                raise ValueError("Unsupported registry constraint")
            if not valid:
                raise ArgumentValidationError("ARGUMENT_CONSTRAINT")
