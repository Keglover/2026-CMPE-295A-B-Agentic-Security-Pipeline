"""Start/status/stop the isolated host development API with PID ownership checks."""

import argparse
import os
import signal
import socket
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
runtime = root / "auth" / ".runtime"
pid_file = runtime / "api.pid"
parser = argparse.ArgumentParser()
parser.add_argument("action", choices=["start", "status", "stop"])
action = parser.parse_args().action


def docker_profile():
    try:
        result = subprocess.run(["docker", "inspect", "--format",
            '{{index .Config.Labels "com.docker.compose.project"}} {{index .Config.Labels "com.docker.compose.service"}} {{.State.Running}}',
            "jev-gateway-dev-gateway-1"], capture_output=True, text=True, timeout=5)
        value = result.stdout.strip().split()
        if result.returncode == 0 and value[:2] == ["jev-gateway-dev", "gateway"]:
            return value[2] == "true"
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def owned_pid():
    try:
        pid = int(pid_file.read_text())
        if pid <= 1:
            return None
        command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        cwd = Path(f"/proc/{pid}/cwd").resolve()
        if (b"uvicorn" in command and b"app.main:app" in command and b"8003" in command
                and cwd == root / "src" / "mvp"):
            return pid
    except (OSError, ValueError):
        pass
    return None


pid = owned_pid()
container_running = docker_profile()
if container_running is not None:
    if action == "status":
        print("Authenticated development API running in Docker." if container_running
              else "Authenticated development API container stopped.")
        raise SystemExit(0 if container_running else 1)
    command = ["docker", "compose", "-f", str(root / "auth" / "docker-compose.gateway-dev.yml")]
    command += ["up", "-d", "--no-build", "gateway"] if action == "start" else ["stop", "gateway"]
    raise SystemExit(subprocess.run(command).returncode)
if action == "status":
    print("Authenticated development API running." if pid else "Authenticated development API stopped.")
    raise SystemExit(0 if pid else 1)
if action == "stop":
    if pid:
        os.kill(pid, signal.SIGTERM)
    print("Stop requested for the owned development API." if pid else "No owned API process to stop.")
    raise SystemExit(0)
if pid:
    print("Authenticated development API already running at http://127.0.0.1:8003.")
    raise SystemExit(0)
with socket.socket() as probe:
    try:
        probe.bind(("127.0.0.1", 8003))
    except OSError:
        raise SystemExit("Port 8003 is already occupied; no process was changed.")
runtime.mkdir(mode=0o700, exist_ok=True)
with (runtime / "api.log").open("a") as log:
    process = subprocess.Popen([sys.executable, str(root / "auth" / "run-dev-api.py")],
        stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
pid_file.write_text(str(process.pid))
print("Development API started on loopback port 8003; log: auth/.runtime/api.log.")
