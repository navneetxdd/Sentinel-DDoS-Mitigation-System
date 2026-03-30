import os
import signal
import subprocess

def socket_listing() -> str:
    commands = (
        ["ss", "-ltnp"],
        ["netstat", "-tlnp"],
    )
    for command in commands:
        try:
            return subprocess.check_output(command, stderr=subprocess.DEVNULL, text=True)
        except Exception:
            continue
    raise RuntimeError("Unable to inspect listening sockets with ss/netstat.")


def pids_on_port(port: int) -> set[int]:
    matches: set[int] = set()
    for line in socket_listing().splitlines():
        if f":{port}" not in line:
            continue
        for token in line.split():
            if "/" not in token:
                continue
            pid_text = token.split("/", 1)[0]
            if pid_text.isdigit():
                matches.add(int(pid_text))
    return matches


try:
    found = sorted(pids_on_port(8080))
    if not found:
        print("No listener found on port 8080.")
    for pid in found:
        print(f"Sending SIGTERM to PID {pid}")
        os.kill(pid, signal.SIGTERM)
except Exception as e:
    print(e)
