"""
Tool Runner Service — Phase 3 Tool Proxy.

This service receives jobs from the gateway via HTTP POST to /execute/{tool_name}.
Instead of running them in-memory, it uses the Docker SDK to spawn an ephemeral
gVisor container constrained to the exact permissions needed for that tool,
captures stdout, and returns the result.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
import uuid
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

import docker
from docker.errors import ContainerError, APIError

from app.policy.config_loader import load_tool_registry

# ---------------------------------------------------------------------------
# Setup & Config
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO)
_log = logging.getLogger("sandbox-service")

app = FastAPI(title="Tool Runner Service")

# Feature Flags for Container Spawning
USE_GVISOR = os.getenv("USE_GVISOR", "false").lower() == "true"
TOOL_IMAGE_NAME = os.getenv("TOOL_IMAGE_NAME", "agentic-security-tool-image")
EGRESS_NET_NAME = os.getenv(
    "EGRESS_NET_NAME",
    "2026-cmpe-295a-b-agentic-security-pipeline_egress-net",
)
CONTROL_NET_NAME = os.getenv(
    "CONTROL_NET_NAME",
    "2026-cmpe-295a-b-agentic-security-pipeline_control-net",
)
EGRESS_PROXY_CONTAINER = os.getenv("EGRESS_PROXY_CONTAINER", "agentic-security-egress-proxy")
OLLAMA_CONTAINER = os.getenv("OLLAMA_CONTAINER", "ollama")
JOB_SCRATCH_ROOT = os.getenv("JOB_SCRATCH_ROOT", "").strip() or None


def _safe_env_int(name: str, default: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        return int(raw)
    except (TypeError, ValueError):
        _log.warning("Invalid %s value %r; using default=%d", name, raw, default)
        return default


SUMMARIZE_LOCAL_MAX_CHARS = _safe_env_int("SUMMARIZE_LOCAL_MAX_CHARS", 8000)

try:
    _docker_client = docker.from_env()
except Exception as exc:
    _log.warning(f"Failed to initialize Docker SDK client (mocking for tests): {exc}")
    _docker_client = None


def _resolve_container_ip(container_name: str, network_name: str) -> str | None:
    """
    Resolve a container's IP address on a specific Docker network.

    gVisor (runsc) containers cannot use Docker's embedded DNS resolver
    (127.0.0.11), so hostname-based service discovery fails inside sandboxed
    containers.  This helper looks up the actual IP at job-spawn time and
    lets the caller inject it via --add-host / extra_hosts, restoring name
    resolution without relying on the broken DNS path.
    """
    if _docker_client is None:
        _log.warning("_resolve_container_ip: Docker client is None — skipping lookup")
        return None
    try:
        container = _docker_client.containers.get(container_name)
        networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
        # Always log what networks the container is on so failures are diagnosable.
        _log.info(
            f"_resolve_container_ip: container={container_name!r} "
            f"networks={list(networks.keys())} "
            f"want={network_name!r}"
        )

        # 1. Exact match on the full network name (e.g. projectname_egress-net)
        net_info = networks.get(network_name)
        if net_info:
            ip = net_info.get("IPAddress")
            if ip:
                _log.info(f"_resolve_container_ip: exact match → {ip}")
                return ip

        # 2. Partial / suffix match — handles project-name prefix differences.
        #    e.g. want "2026-cmpe-..._egress-net" but key is "egress-net" or vice-versa.
        for net_key, net_val in networks.items():
            if network_name in net_key or net_key in network_name:
                ip = net_val.get("IPAddress")
                if ip:
                    _log.info(f"_resolve_container_ip: partial match on {net_key!r} → {ip}")
                    return ip

        # 3. Last resort: return any non-empty IP. The caller already adds the IP
        #    to extra_hosts under the container hostname, so any routable IP works
        #    as long as the network topology allows it.
        for net_key, net_val in networks.items():
            ip = net_val.get("IPAddress")
            if ip:
                _log.warning(
                    f"_resolve_container_ip: no network match; "
                    f"using {ip} from {net_key!r} as best-effort fallback"
                )
                return ip

        _log.error(
            f"_resolve_container_ip: {container_name!r} has no routable IPs "
            f"(networks={list(networks.keys())})"
        )
    except Exception as exc:
        _log.error(f"_resolve_container_ip: lookup failed for {container_name!r}: {exc}")
    return None


# Cached egress-proxy IP resolved at startup.
# Used as a guaranteed fallback when the per-request Docker SDK lookup fails
# (e.g. transient socket errors). Populated by _probe_egress_proxy().
_egress_proxy_ip_cache: str | None = None


def _probe_egress_proxy() -> None:
    """Resolve and cache the egress-proxy IP at startup for early diagnostics."""
    global _egress_proxy_ip_cache
    ip = _resolve_container_ip(EGRESS_PROXY_CONTAINER, EGRESS_NET_NAME)
    if ip:
        _egress_proxy_ip_cache = ip
        _log.info(f"Startup probe: {EGRESS_PROXY_CONTAINER} → {ip} (cached for per-request use)")
    else:
        _log.warning(
            f"Startup probe: could not resolve {EGRESS_PROXY_CONTAINER!r} on "
            f"{EGRESS_NET_NAME!r}. "
            f"Summarize/fetch_url containers will use hostname fallback "
            f"which may fail under gVisor. "
            f"Check that EGRESS_PROXY_CONTAINER and EGRESS_NET_NAME match your compose setup."
        )


# Run the probe after the client is initialised (best-effort; never blocks startup).
try:
    _probe_egress_proxy()
except Exception:
    pass


def _tool_timeout(tool_name: str, fallback: float) -> float:
    """Resolve timeout from executor policy for the current tool."""
    try:
        from app.gateway.executor_policy import _load_policy
        return max(1.0, float(_load_policy(tool_name).timeout_sec))
    except Exception:
        return fallback


def _create_job_scratch_dir(job_id: str) -> Path:
    """Create a host scratch directory for a single job."""
    path = Path(tempfile.mkdtemp(prefix=f"job_{job_id}_", dir=JOB_SCRATCH_ROOT))
    # Bind-mounted job scratch must be writable by the container user.
    try:
        os.chmod(path, 0o777)
    except OSError as exc:
        _log.warning("Could not chmod scratch dir %s: %s", path, exc)
    return path


def _parse_gateway_real_output(stdout_text: str, stderr_text: str) -> dict | None:
    """
    Parse structured output emitted by gateway_real CLI.

    Preferred format uses prefixed JSON lines:
      - GATEWAY_REAL_RESULT={...}
      - GATEWAY_REAL_ERROR={...}
    Falls back to legacy plain JSON line parsing for compatibility.
    """

    def _parse_prefixed(text: str, prefix: str) -> dict | None:
        for line in reversed(text.splitlines()):
            line = line.strip()
            if not line.startswith(prefix):
                continue
            payload = line[len(prefix):].strip()
            try:
                parsed = json.loads(payload)
            except json.JSONDecodeError:
                return None
            if isinstance(parsed, dict):
                return parsed
        return None

    parsed = _parse_prefixed(stdout_text, "GATEWAY_REAL_RESULT=")
    if parsed is not None:
        return parsed

    parsed = _parse_prefixed(stderr_text, "GATEWAY_REAL_ERROR=")
    if parsed is not None:
        return parsed

    # Backward-compatible parsing for historical output format.
    for text in (stdout_text, stderr_text):
        stripped_lines = [line.strip() for line in text.splitlines() if line.strip()]
        for line in reversed(stripped_lines):
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict) and parsed.get("status") in {"success", "error"}:
                return parsed
        try:
            parsed = json.loads(text.strip())
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and parsed.get("status") in {"success", "error"}:
            return parsed
    return None


def _is_summarize_local(text: str) -> bool:
    """Decide summarize route based on configured text-length threshold."""
    threshold, _, _ = _get_summarize_policy()
    return len(text) <= threshold


def _network_for_route(route_name: str, fallback: str) -> str:
    route = route_name.strip().lower()
    if route == "control-net":
        return CONTROL_NET_NAME
    if route == "egress-net":
        return EGRESS_NET_NAME
    if route:
        return route_name
    return fallback


def _get_summarize_policy() -> tuple[int, str, str]:
    """Read summarize policy from registry with environment fallbacks."""
    threshold = SUMMARIZE_LOCAL_MAX_CHARS
    local_route = "control-net"
    cloud_route = "egress-net"

    try:
        sandbox_cfg = load_tool_registry().get("sandbox", {})
        summarize_cfg = sandbox_cfg.get("summarize", {})
        threshold = int(summarize_cfg.get("local_max_chars", threshold))
        local_route = str(summarize_cfg.get("local_route", local_route)).strip() or local_route
        cloud_route = str(summarize_cfg.get("cloud_route", cloud_route)).strip() or cloud_route
    except Exception as exc:
        _log.warning("Failed to load summarize policy from registry: %s", exc)

    return threshold, local_route, cloud_route


def _runtime_probe() -> dict:
    """Best-effort runtime checks for health visibility."""
    if _docker_client is None:
        return {
            "docker_available": False,
            "runsc_registered": False,
            "runtime_ready": False,
        }

    try:
        info = _docker_client.info()
        runtimes = info.get("Runtimes", {})
        runsc_registered = "runsc" in runtimes
    except Exception as exc:
        _log.warning("Runtime probe failed: %s", exc)
        return {
            "docker_available": True,
            "runsc_registered": False,
            "runtime_ready": not USE_GVISOR,
        }

    return {
        "docker_available": True,
        "runsc_registered": runsc_registered,
        "runtime_ready": (runsc_registered if USE_GVISOR else True),
    }

# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class ExecuteRequest(BaseModel):
    tool_args: dict


# ---------------------------------------------------------------------------
# Ephemeral Execution Engine
# ---------------------------------------------------------------------------

@app.post("/execute/{tool_name}")
def execute_tool(tool_name: str, payload: ExecuteRequest) -> dict:
    """
    Spawn an ephemeral job container via the Docker SDK.
    Wait for execution, parse stdout JSON, and destroy the container.
    """
    if _docker_client is None:
        raise HTTPException(
            status_code=500,
            detail="Docker client is not available in the Tool Runner."
        )

    job_id = str(uuid.uuid4())
    runtime = "runsc" if USE_GVISOR else None
    timeout_sec = _tool_timeout(tool_name, fallback=10.0)
    scratch_dir: Path | None = None
    tool_args = dict(payload.tool_args or {})

    # Base container isolation constraints
    container_opts = {
        "image": TOOL_IMAGE_NAME,
        "detach": True,
        "runtime": runtime,
        "network_mode": "none",
        "mem_limit": "256m",
        "cpu_quota": 50000,  # 0.5 CPU
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
    }

    # Tool-specific profile overrides
    if tool_name == "write_note":
        scratch_dir = _create_job_scratch_dir(job_id)
        # Windows bind mounts can deny writes for non-root container users.
        container_opts["user"] = "0:0"
        container_opts["network_mode"] = "none"
        container_opts["volumes"] = {
            str(scratch_dir): {
                "bind": "/app/sandbox/notes",
                "mode": "rw",
            }
        }
    elif tool_name == "fetch_url":
        container_opts["network"] = EGRESS_NET_NAME
        container_opts.pop("network_mode", None)
        container_opts["mem_limit"] = "128m"
        # gVisor DNS fix: inject egress-proxy IP as /etc/hosts entry so
        # hostname resolution works without Docker's broken-under-runsc DNS.
        proxy_ip = _resolve_container_ip(EGRESS_PROXY_CONTAINER, EGRESS_NET_NAME)
        if proxy_ip:
            container_opts["extra_hosts"] = {EGRESS_PROXY_CONTAINER: proxy_ip}
            _log.info(f"gVisor DNS fix: {EGRESS_PROXY_CONTAINER} → {proxy_ip}")
        else:
            _log.warning(f"Could not resolve IP for {EGRESS_PROXY_CONTAINER}; DNS may fail under runsc")
    elif tool_name == "summarize":
        summarize_threshold, local_route_name, cloud_route_name = _get_summarize_policy()
        summarize_text = str(tool_args.get("text", ""))
        summarize_local = len(summarize_text) <= summarize_threshold
        container_opts.pop("network_mode", None)
        container_opts["mem_limit"] = "512m"
        container_opts["cpu_quota"] = 100000  # 1.0 CPU

        if summarize_local:
            summarize_network = _network_for_route(local_route_name, CONTROL_NET_NAME)
            container_opts["network"] = summarize_network
            local_host = os.getenv("OLLAMA_HOST", "http://ollama:11434")
            container_opts["environment"] = {
                "OLLAMA_HOST": local_host,
                "LLM_MODEL": os.getenv("LLM_MODEL_LOCAL", "qwen2.5:7b"),
            }
            local_host_name = urlparse(local_host).hostname
            ollama_ip = _resolve_container_ip(OLLAMA_CONTAINER, summarize_network)
            if local_host_name and ollama_ip:
                container_opts["extra_hosts"] = {local_host_name: ollama_ip}
                _log.info("gVisor DNS fix: %s → %s", local_host_name, ollama_ip)
            _log.info(
                "Summarize route: local (len=%d <= %d)",
                len(summarize_text),
                summarize_threshold,
            )
        else:
            summarize_network = _network_for_route(cloud_route_name, EGRESS_NET_NAME)
            container_opts["network"] = summarize_network
            # gVisor DNS fix: resolve egress-proxy IP and inject via extra_hosts.
            # Falls back to the startup-probe cached IP if the live lookup fails.
            proxy_ip = (
                _resolve_container_ip(EGRESS_PROXY_CONTAINER, summarize_network)
                or _egress_proxy_ip_cache
            )
            if proxy_ip:
                egress_host = f"http://{proxy_ip}:8002"
                container_opts["extra_hosts"] = {EGRESS_PROXY_CONTAINER: proxy_ip}
                _log.info(f"gVisor DNS fix: {EGRESS_PROXY_CONTAINER} → {proxy_ip}")
            else:
                egress_host = f"http://{EGRESS_PROXY_CONTAINER}:8002"
                _log.warning(
                    f"Could not resolve IP for {EGRESS_PROXY_CONTAINER} (cache miss too); "
                    f"hostname fallback will fail under gVisor"
                )
            container_opts["environment"] = {
                # Route larger requests through egress proxy/cloud model path.
                "OLLAMA_HOST": egress_host,
                "LLM_MODEL": os.getenv("LLM_MODEL_CLOUD", os.getenv("LLM_MODEL", "qwen2.5:7b")),
            }
            _log.info(
                "Summarize route: cloud (len=%d > %d)",
                len(summarize_text),
                summarize_threshold,
            )
    elif tool_name == "search_notes":
        scratch_dir = _create_job_scratch_dir(job_id)
        container_opts["user"] = "0:0"
        container_opts["network_mode"] = "none"
        container_opts["volumes"] = {
            str(scratch_dir): {
                "bind": "/app/sandbox/notes",
                "mode": "rw",
            }
        }
    elif tool_name == "execute_command":
        scratch_dir = _create_job_scratch_dir(job_id)
        container_opts["network_mode"] = "none"
        container_opts["mem_limit"] = "384m"
        container_opts["cpu_quota"] = 75000
        container_opts["volumes"] = {
            str(scratch_dir): {
                "bind": "/tmp/job",
                "mode": "rw",
            }
        }
        tool_args.setdefault("working_dir", "/tmp/job")

    container_opts["command"] = [
        "python",
        "-m",
        "app.gateway.gateway_real",
        tool_name,
        json.dumps(tool_args),
    ]

    # Only pass runtime if it's set 
    # (Docker SDK will fail if we pass None for runtime specifically)
    if not runtime:
        container_opts.pop("runtime")

    _log.info(
        "Spawning container for %s (job_id: %s) with runtime=%s timeout=%.1fs",
        tool_name,
        job_id,
        runtime,
        timeout_sec,
    )

    container = None
    try:
        container = _docker_client.containers.run(**container_opts)

        if isinstance(container, (bytes, bytearray)):
            stdout_text = bytes(container).decode("utf-8", errors="replace").strip()
            stderr_text = ""
        else:
            try:
                container.wait(timeout=timeout_sec)
            except Exception:
                raise HTTPException(
                    status_code=504,
                    detail=f"Execution timed out after {timeout_sec:.0f}s.",
                )

            stdout_raw = container.logs(stdout=True, stderr=False)
            stderr_raw = container.logs(stdout=False, stderr=True)
            stdout_text = (
                stdout_raw.decode("utf-8", errors="replace").strip()
                if isinstance(stdout_raw, (bytes, bytearray))
                else str(stdout_raw).strip()
            )
            stderr_text = (
                stderr_raw.decode("utf-8", errors="replace").strip()
                if isinstance(stderr_raw, (bytes, bytearray))
                else str(stderr_raw).strip()
            )

        _log.info("Container stdout: %s", stdout_text)
        if stderr_text:
            _log.info("Container stderr: %s", stderr_text)

        result = _parse_gateway_real_output(stdout_text, stderr_text)
        if result is None:
            raise HTTPException(
                status_code=500,
                detail=(
                    "Unparsable container output. "
                    f"stdout={stdout_text!r} stderr={stderr_text!r}"
                ),
            )

        status = str(result.get("status", "")).lower()
        if status == "success":
            if scratch_dir and tool_name in {"write_note", "search_notes"}:
                artifacts = [p.name for p in sorted(scratch_dir.glob("*.md")) if p.is_file()]
                _log.info("Job %s artifacts: %s", job_id, artifacts)
            return {"result": result.get("output")}

        if status == "error":
            raise HTTPException(status_code=400, detail=result.get("error", "Unknown tool error"))

        raise HTTPException(status_code=500, detail="Unknown container output format.")

    except ContainerError as e:
        stderr_output = e.stderr.decode("utf-8", errors="replace") if e.stderr else ""
        _log.error(f"Container error during {tool_name}: Exit code: {e.exit_status}. Stderr: {stderr_output}")
        try:
            error_json = _parse_gateway_real_output("", stderr_output)
            if error_json and error_json.get("error"):
                raise HTTPException(status_code=400, detail=error_json.get("error"))
            raise HTTPException(status_code=500, detail=f"Execution failed: {stderr_output}")
        except HTTPException:
            raise
    except APIError as e:
        _log.error(f"Docker API error spawning {tool_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Infrastructure error: {e}")
    finally:
        if container is not None and not isinstance(container, (bytes, bytearray)):
            try:
                container.remove(force=True)
            except Exception as exc:
                _log.warning("Failed to remove container for job %s: %s", job_id, exc)

        if scratch_dir is not None:
            try:
                shutil.rmtree(scratch_dir, ignore_errors=True)
            except Exception as exc:
                _log.warning("Failed to cleanup scratch dir %s: %s", scratch_dir, exc)

# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------

@app.get("/health")
def health_check() -> dict:
    runtime = _runtime_probe()
    summarize_threshold, local_route_name, cloud_route_name = _get_summarize_policy()
    return {
        "status": "ok",
        "service": "tool-runner",
        "docker_available": runtime["docker_available"],
        "runsc_registered": runtime["runsc_registered"],
        "runtime_ready": runtime["runtime_ready"],
        "use_gvisor": USE_GVISOR,
        "tool_image": TOOL_IMAGE_NAME,
        "summarize_local_max_chars": summarize_threshold,
        "summarize_local_route": local_route_name,
        "summarize_cloud_route": cloud_route_name,
    }