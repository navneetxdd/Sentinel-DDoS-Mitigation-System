#!/usr/bin/env python3
"""OS-Ken manager compatibility launcher with WSGI service startup."""

from __future__ import annotations

import os
import sys
import types


def _install_tinyrpc_stub() -> None:
    try:
        import tinyrpc  # noqa: F401
        return
    except ModuleNotFoundError:
        pass

    tinyrpc_mod = types.ModuleType("tinyrpc")
    server_mod = types.ModuleType("tinyrpc.server")
    dispatch_mod = types.ModuleType("tinyrpc.dispatch")
    protocols_mod = types.ModuleType("tinyrpc.protocols")
    jsonrpc_mod = types.ModuleType("tinyrpc.protocols.jsonrpc")
    transports_mod = types.ModuleType("tinyrpc.transports")
    client_mod = types.ModuleType("tinyrpc.client")

    class RPCServer:
        def __init__(self, transport, protocol, dispatcher):
            self.transport = transport
            self.protocol = protocol
            self.dispatcher = dispatcher

        def serve_forever(self):
            raise RuntimeError("tinyrpc compatibility stub does not implement RPC serving")

    class RPCDispatcher:
        def __init__(self):
            self.instance = None

        def register_instance(self, instance):
            self.instance = instance

    def public(func):
        return func

    class JSONRPCProtocol:
        pass

    class ServerTransport:
        pass

    class ClientTransport:
        pass

    class RPCClient:
        def __init__(self, protocol, transport):
            self.protocol = protocol
            self.transport = transport

    server_mod.RPCServer = RPCServer
    dispatch_mod.RPCDispatcher = RPCDispatcher
    dispatch_mod.public = public
    jsonrpc_mod.JSONRPCProtocol = JSONRPCProtocol
    protocols_mod.jsonrpc = jsonrpc_mod
    transports_mod.ServerTransport = ServerTransport
    transports_mod.ClientTransport = ClientTransport
    client_mod.RPCClient = RPCClient

    tinyrpc_mod.server = server_mod
    tinyrpc_mod.dispatch = dispatch_mod
    tinyrpc_mod.protocols = protocols_mod
    tinyrpc_mod.transports = transports_mod
    tinyrpc_mod.client = client_mod

    sys.modules["tinyrpc"] = tinyrpc_mod
    sys.modules["tinyrpc.server"] = server_mod
    sys.modules["tinyrpc.dispatch"] = dispatch_mod
    sys.modules["tinyrpc.protocols"] = protocols_mod
    sys.modules["tinyrpc.protocols.jsonrpc"] = jsonrpc_mod
    sys.modules["tinyrpc.transports"] = transports_mod
    sys.modules["tinyrpc.client"] = client_mod

    print("[WARN] tinyrpc is missing; using a minimal compatibility stub for OS-Ken WSGI.", file=sys.stderr)


_install_tinyrpc_stub()

os.environ.setdefault("OSKEN_HUB_TYPE", "eventlet")

# Python 3.13+ compatibility: eventlet has a fatal circular import on 3.13+.
# Instead of trying to shim it, we bypass eventlet entirely and use the native hub.
if sys.version_info >= (3, 13):
    os.environ["OSKEN_HUB_TYPE"] = "native"
    print("[INFO] Python 3.13+ detected — forcing OSKEN_HUB_TYPE=native (eventlet incompatible)", file=sys.stderr)

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

_EVENTLET_PATCHED = False

# Only attempt eventlet on Python < 3.13
if sys.version_info < (3, 13):
    try:
        import eventlet
        eventlet.monkey_patch()
        _EVENTLET_PATCHED = True
        import eventlet.greenthread
    except (ImportError, AttributeError, RuntimeError) as exc:
        print(f"[WARN] eventlet.monkey_patch() failed ({exc}); continuing with threading.", file=sys.stderr)
        _EVENTLET_PATCHED = False
else:
    # Python 3.13+ : Mock eventlet to prevent crashes in os_ken.app.wsgi and others
    eventlet_mod = types.ModuleType("eventlet")
    eventlet_mod.wsgi = types.ModuleType("eventlet.wsgi")
    eventlet_mod.wsgi.ALREADY_HANDLED = object()
    eventlet_mod.greenthread = types.ModuleType("eventlet.greenthread")
    eventlet_mod.monkey_patch = lambda **kwargs: None
    eventlet_mod.__version__ = "0.33.0" # Satisfy version checks
    
    sys.modules["eventlet"] = eventlet_mod
    sys.modules["eventlet.wsgi"] = eventlet_mod.wsgi
    sys.modules["eventlet.greenthread"] = eventlet_mod.greenthread
    eventlet = eventlet_mod
    _EVENTLET_PATCHED = False
    print("[INFO] Python 3.13+ : eventlet mocked to prevent circular import crashes.", file=sys.stderr)

import logging
import threading

if "eventlet" in sys.modules and not hasattr(eventlet.greenthread, "start_joinable_thread"):
    def mock_start_joinable_thread(func, *args, **kwargs):
        t = threading.Thread(target=func, args=args, kwargs=kwargs)
        t.start()
        return t
    eventlet.greenthread.start_joinable_thread = mock_start_joinable_thread

from os_ken import __version__ as version
from os_ken import cfg
from os_ken import log
from os_ken.base.app_manager import AppManager
from os_ken.controller import controller
from os_ken.lib import hub
from os_ken.topology import switches

CONF = cfg.CONF


def _install_native_hub_wsgi_fallback() -> None:
    if getattr(hub, "HUB_TYPE", "") != "native" or hasattr(hub, "WSGIServer"):
        return

    from socketserver import ThreadingMixIn
    from wsgiref.simple_server import WSGIServer as BaseWSGIServer
    from wsgiref.simple_server import make_server

    class ThreadedWSGIServer(ThreadingMixIn, BaseWSGIServer):
        daemon_threads = True

    class NativeWSGIServer:
        def __init__(self, listen_info, application, **_config):
            self.listen_info = listen_info
            self.application = application

        def serve_forever(self):
            host, port = self.listen_info
            with make_server(host, port, self.application, server_class=ThreadedWSGIServer) as server:
                server.serve_forever()

    class NativeWebSocketWSGI:
        def __init__(self, *_args, **_kwargs):
            raise NotImplementedError("WebSocketWSGI is unavailable when OS-Ken runs with the native hub")

    hub.WSGIServer = NativeWSGIServer
    hub.WebSocketWSGI = NativeWebSocketWSGI


_install_native_hub_wsgi_fallback()

def main(args: list[str] | None = None, prog: str | None = None) -> int:
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)

    try:
        import os_ken.app.wsgi  # noqa: F401
    except Exception as exc:
        print(f"[WARN] Pre-import of os_ken.app.wsgi failed: {exc}", file=sys.stderr)

    if not _EVENTLET_PATCHED:
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

    if not CONF.enable_debugger and not _EVENTLET_PATCHED:
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
    try:
        import os_ken.app.wsgi as osken_wsgi
        wsgi_service = osken_wsgi.start_service(app_mgr)
        if wsgi_service is not None:
            services.append(hub.spawn(wsgi_service))
            logger.info("OS-Ken WSGI REST service started")
    except Exception as exc:
        logger.warning("Failed to start OS-Ken WSGI REST service: %s", exc)

    # Minimal loopback-only health endpoint for controller process diagnostics.
    try:
        from wsgiref.simple_server import make_server

        dashboard_origin = os.environ.get("SENTINEL_DASHBOARD_ORIGIN", "http://localhost:5173")
        health_port = int(os.environ.get("SENTINEL_OSKEN_HEALTH_PORT", "8081"))

        def os_ken_wsgi_app(environ, start_response):
            path = environ.get("PATH_INFO", "")
            if path == "/health":
                body = b'{"status":"ok","app":"sentinel-osken-compat"}'
                headers = [
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(body))),
                    ("Access-Control-Allow-Origin", dashboard_origin),
                    ("Access-Control-Allow-Methods", "GET, OPTIONS"),
                    ("Access-Control-Allow-Headers", "Origin, Content-Type, Accept"),
                ]
                start_response("200 OK", headers)
                return [body]
            if environ.get("REQUEST_METHOD") == "OPTIONS":
                headers = [
                    ("Access-Control-Allow-Origin", dashboard_origin),
                    ("Access-Control-Allow-Methods", "GET, OPTIONS"),
                    ("Access-Control-Allow-Headers", "Origin, Content-Type, Accept"),
                ]
                start_response("200 OK", headers)
                return [b""]

            body = b'{"error":"not_found"}'
            headers = [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
                ("Access-Control-Allow-Origin", dashboard_origin),
            ]
            start_response("404 Not Found", headers)
            return [body]

        def start_wsgi():
            try:
                server = make_server("127.0.0.1", health_port, os_ken_wsgi_app)
            except OSError as exc:
                logger.warning("Loopback health service unavailable on port %s: %s", health_port, exc)
                return
            logger.info("Loopback health service started on port %s", health_port)
            server.serve_forever()

        threading.Thread(target=start_wsgi, daemon=True).start()
    except Exception as exc:
        logger.warning("Failed to configure WSGI fallback service: %s", exc)

    try:
        hub.joinall(services)
    except KeyboardInterrupt:
        logger.debug("Keyboard Interrupt received. Closing OSKen application manager...")
    finally:
        app_mgr.close()

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
