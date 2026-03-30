#!/usr/bin/env python3
"""Loopback SDN REST proxy for a real controller.

This service does not emulate controller behavior. It forwards supported
Sentinel REST calls to an actual Ryu/OS-Ken controller and returns upstream
errors when the controller is unavailable.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.client import HTTPMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


ALLOWED_HEADERS = ("Accept", "Authorization", "Content-Type")


def listen_host() -> str:
    return os.environ.get("SENTINEL_SDN_API_HOST", "127.0.0.1").strip() or "127.0.0.1"


def listen_port() -> int:
    try:
        return int(os.environ.get("SENTINEL_SDN_API_PORT", "8081"))
    except ValueError:
        return 8081


def controller_base_url() -> str:
    return os.environ.get("SENTINEL_SDN_CONTROLLER_URL", "http://127.0.0.1:8080").strip().rstrip("/")


def proxy_target(path: str, query: str = "") -> str:
    target = f"{controller_base_url()}{path}"
    return f"{target}?{query}" if query else target


def filtered_request_headers(headers: HTTPMessage) -> dict[str, str]:
    forwarded: dict[str, str] = {}
    for header_name in ALLOWED_HEADERS:
        value = headers.get(header_name)
        if value:
            forwarded[header_name] = value
    return forwarded


class SDNProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send_json(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _relay(self, path: str) -> None:
        query = urllib.parse.urlsplit(self.path).query
        payload = None
        if self.command in {"POST", "PUT", "PATCH"}:
            length = int(self.headers.get("Content-Length", "0") or "0")
            payload = self.rfile.read(length) if length > 0 else None

        target = proxy_target(path, query)
        request = urllib.request.Request(
            target,
            data=payload,
            headers=filtered_request_headers(self.headers),
            method=self.command,
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as upstream_response:
                body = upstream_response.read()
                self.send_response(upstream_response.status)
                self.send_header("Content-Type", upstream_response.headers.get("Content-Type", "application/json"))
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        except urllib.error.HTTPError as exc:
            body = exc.read()
            self.send_response(exc.code)
            self.send_header("Content-Type", exc.headers.get("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except urllib.error.URLError as exc:
            self._send_json(
                502,
                {
                    "error": "SDN controller unreachable",
                    "upstream": controller_base_url(),
                    "detail": str(exc.reason),
                },
            )

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/health":
            if controller_base_url() in {f"http://{listen_host()}:{listen_port()}", f"https://{listen_host()}:{listen_port()}"}:
                self._send_json(500, {"status": "error", "detail": "Proxy loop: listen address matches upstream controller URL."})
                return
            self._send_json(200, {"status": "ok", "upstream": controller_base_url()})
            return
        if parsed.path == "/stats/switches":
            self._relay("/stats/switches")
            return
        if parsed.path.startswith("/stats/flow/"):
            dpid = parsed.path[len("/stats/flow/") :]
            self._relay(f"/stats/flow/{urllib.parse.quote(dpid, safe='')}")
            return
        self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/stats/flowentry/add":
            self._relay("/stats/flowentry/add")
            return
        self._send_json(404, {"error": "not_found"})

    def log_message(self, format: str, *args: object) -> None:
        sys.stderr.write(f"[sdn_api] {self.address_string()} - {format % args}\n")


def create_server() -> ThreadingHTTPServer:
    host = listen_host()
    port = listen_port()
    upstream = controller_base_url()
    if upstream in {f"http://{host}:{port}", f"https://{host}:{port}"}:
        raise RuntimeError("Refusing to start sdn_api.py: listen address points to itself.")
    return ThreadingHTTPServer((host, port), SDNProxyHandler)


def main() -> int:
    server = create_server()
    print(f"[*] Sentinel SDN proxy listening on http://{listen_host()}:{listen_port()}")
    print(f"[*] Forwarding to controller: {controller_base_url()}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
