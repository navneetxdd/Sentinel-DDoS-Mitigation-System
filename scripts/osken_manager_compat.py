#!/usr/bin/env python3
"""OS-Ken manager compatibility launcher with WSGI service startup."""

from __future__ import annotations

import logging
import os
import sys
import types
import threading

# Python 3.12/3.13+ compatibility: mock 'imp' and provide 'ssl.wrap_socket'
if "imp" not in sys.modules:
    imp_mock = types.ModuleType("imp")
    imp_mock.new_module = lambda name: types.ModuleType(name)
    imp_mock.acquire_lock = lambda: None
    imp_mock.release_lock = lambda: None
    imp_mock.lock_held = lambda: False
    sys.modules["imp"] = imp_mock

import ssl
if not hasattr(ssl, "wrap_socket"):
    def mock_wrap_socket(sock, *args, **kwargs):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        return ctx.wrap_socket(sock)
    ssl.wrap_socket = mock_wrap_socket

import builtins
if not hasattr(builtins, "TimeoutError"):
    builtins.TimeoutError = type("TimeoutError", (Exception,), {})

import collections
if not hasattr(collections, "MutableMapping"):
    import collections.abc
    for name in ("MutableMapping", "MutableSequence", "MutableSet", "Iterable", "Mapping", "Sequence", "Set"):
        if hasattr(collections.abc, name):
            setattr(collections, name, getattr(collections.abc, name))

try:
    import eventlet.greenthread
    if not hasattr(eventlet.greenthread, "start_joinable_thread"):
        def mock_start_joinable_thread(func, *args, **kwargs):
            t = threading.Thread(target=func, args=args, kwargs=kwargs)
            t.start()
            return t
        eventlet.greenthread.start_joinable_thread = mock_start_joinable_thread
except ImportError:
    pass

from os_ken import __version__ as version
from os_ken import cfg
from os_ken import log
from os_ken.base.app_manager import AppManager
from os_ken.controller import controller
from os_ken.lib import hub
from os_ken.topology import switches

CONF = cfg.CONF

def main(args: list[str] | None = None, prog: str | None = None) -> int:
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)

    hub.patch(thread=False)
    log.early_init_log(logging.DEBUG)

    CONF.register_cli_opts([
        cfg.ListOpt("app-lists", default=[], help="application module name to run"),
        cfg.MultiStrOpt("app", positional=True, default=[], help="application module name to run"),
        cfg.StrOpt("pid-file", default=None, help="pid file name"),
        cfg.BoolOpt("enable-debugger", default=False, help="don't overwrite Python standard threading library"),
    ])

    try:
        CONF(args=args, prog=prog, project="os_ken", version=f"osken-manager {version}", default_config_files=["/usr/local/etc/os_ken/os_ken.conf"])
    except cfg.ConfigFilesNotFoundError:
        CONF(args=args, prog=prog, project="os_ken", version=f"osken-manager {version}")

    log.init_log()
    logger = logging.getLogger(__name__)

    if not CONF.enable_debugger:
        hub.patch(thread=True)

    if CONF.pid_file:
        with open(CONF.pid_file, "w", encoding="utf-8") as pid_file:
            pid_file.write(str(os.getpid()))

    app_lists = CONF.app_lists + CONF.app
    if not app_lists:
        app_lists = ["os_ken.controller.ofp_handler"]

    app_mgr = AppManager.get_instance()
    app_mgr.load_apps(app_lists)
    contexts = app_mgr.create_contexts()
    services = []
    services.extend(app_mgr.instantiate_apps(**contexts))

    # Explicit Fallback WSGI implementation on port 8081 to avoid Vite conflict
    try:
        from wsgiref.simple_server import make_server
        def os_ken_wsgi_app(environ, start_response):
            path = environ.get('PATH_INFO', '')
            if path == '/stats/switches':
                body = b'[]'
                
                # Setup custom CORS headers so React frontend can fetch if needed
                headers = [
                    ('Content-Type', 'application/json'),
                    ('Content-Length', str(len(body))),
                    ('Access-Control-Allow-Origin', '*'),
                    ('Access-Control-Allow-Methods', 'GET, OPTIONS'),
                    ('Access-Control-Allow-Headers', 'Origin, Content-Type, Accept')
                ]
                start_response('200 OK', headers)
                return [body]
            elif environ.get('REQUEST_METHOD') == 'OPTIONS':
                headers = [
                    ('Access-Control-Allow-Origin', '*'),
                    ('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE'),
                    ('Access-Control-Allow-Headers', 'Origin, Content-Type, Accept')
                ]
                start_response('200 OK', headers)
                return [b'']
            else:
                body = b'{"status": "ok", "app": "sentinel-sdn-compat"}'
                headers = [('Content-Type', 'application/json'), ('Content-Length', str(len(body))), ('Access-Control-Allow-Origin', '*')]
                start_response('200 OK', headers)
                return [body]

        def start_wsgi():
            server = make_server('0.0.0.0', 8081, os_ken_wsgi_app)
            server.serve_forever()

        t = threading.Thread(target=start_wsgi, daemon=True)
        t.start()
        services.append(t)
        logger.info("WSGI fallback service started on port 8081")
    except Exception as exc:
        logger.warning("Failed to start WSGI fallback service: %s", exc)

    try:
        hub.joinall(services)
    except KeyboardInterrupt:
        logger.debug("Keyboard Interrupt received. Closing OSKen application manager...")
    finally:
        app_mgr.close()

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
