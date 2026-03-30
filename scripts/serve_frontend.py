#!/usr/bin/env python3
"""Serve the built frontend bundle with an SPA fallback."""

from __future__ import annotations

import argparse
import os
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


class FrontendHandler(SimpleHTTPRequestHandler):
    extensions_map = SimpleHTTPRequestHandler.extensions_map.copy()
    extensions_map.update({
        '.js': 'application/javascript',
        '.css': 'text/css',
        '.mjs': 'application/javascript',
    })

    def send_head(self):  # type: ignore[override]
        candidate = Path(self.translate_path(self.path))
        request_path = Path(unquote(urlsplit(self.path).path))

        if candidate.exists() or request_path.suffix:
            return super().send_head()

        self.path = "/index.html"
        return super().send_head()


class FrontendServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def server_bind(self):
        # Set SO_REUSEPORT if available to be extra aggressive against TIME_WAIT
        import socket
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        
        host, port = self.server_address
        print(f"[SENTINEL FRONTEND] Binding to {host}:{port}...", file=sys.stderr, flush=True)
        
        try:
            super().server_bind()
        except OSError as exc:
            print(f"[ERROR] Failed to bind to {host}:{port}: {exc}", file=sys.stderr, flush=True)
            raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, help="Directory to serve")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host")
    parser.add_argument("--port", type=int, default=5173, help="Bind port")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()

    if not root.is_dir():
        raise SystemExit(f"Frontend root not found: {root}")

    handler = partial(FrontendHandler, directory=str(root))
    
    # Smart port hunt: try the requested port and then incremental fallbacks
    server = None
    start_port = args.port
    for port in range(start_port, start_port + 20):
        try:
            server = FrontendServer((args.host, port), handler)
            # Signal the actual port to the orchestration script
            state_dir = os.environ.get("SENTINEL_STATE_DIR", ".")
            try:
                with open(os.path.join(state_dir, "frontend_port_actual"), "w") as f:
                    f.write(str(port))
            except Exception as e:
                print(f"[WARN] Failed to write port signal: {e}", file=sys.stderr)
            
            print(f"SENTINEL_FRONTEND_ACTUAL_PORT={port}", flush=True)
            print(f"[SENTINEL FRONTEND] Serving {root} on http://{args.host}:{port}", flush=True)
            break
        except OSError as exc:
            if exc.errno == 98: # EADDRINUSE
                continue
            raise
    
    if not server:
        raise SystemExit(f"Could not find a free port for frontend starting at {start_port}")

    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
