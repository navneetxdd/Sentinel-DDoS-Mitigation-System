#!/usr/bin/env python3
"""OS-Ken manager compatibility launcher with WSGI service startup.

Some OS-Ken builds do not start WSGI apps (e.g. ofctl_rest) from the stock
manager entrypoint, which leaves REST port 8080 unavailable. This launcher
mirrors osken-manager startup and explicitly starts WSGI when available.
"""

from __future__ import annotations

import logging
import os
import sys

from os_ken import __version__ as version
from os_ken import cfg
from os_ken import log
from os_ken.base.app_manager import AppManager
from os_ken.controller import controller  # noqa: F401 - registers OFP opts
from os_ken.lib import hub
from os_ken.topology import switches  # noqa: F401 - registers topology opts


CONF = cfg.CONF


def main(args: list[str] | None = None, prog: str | None = None) -> int:
    # Match manager semantics: patch once early, then thread patch after config.
    hub.patch(thread=False)
    log.early_init_log(logging.DEBUG)

    CONF.register_cli_opts(
        [
            cfg.ListOpt("app-lists", default=[], help="application module name to run"),
            cfg.MultiStrOpt("app", positional=True, default=[], help="application module name to run"),
            cfg.StrOpt("pid-file", default=None, help="pid file name"),
            cfg.BoolOpt(
                "enable-debugger",
                default=False,
                help="don't overwrite Python standard threading library (use only for debugging)",
            ),
        ]
    )

    try:
        CONF(
            args=args,
            prog=prog,
            project="os_ken",
            version=f"osken-manager {version}",
            default_config_files=["/usr/local/etc/os_ken/os_ken.conf"],
        )
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

    # Critical compatibility behavior: start WSGI service for ofctl_rest.
    try:
        from os_ken.app import wsgi

        webapp = wsgi.start_service(app_mgr)
        if webapp:
            services.append(hub.spawn(webapp))
            logger.info("WSGI service started")
        else:
            logger.warning("WSGI service did not start (no web app returned)")
    except Exception as exc:  # pragma: no cover - defensive runtime path
        logger.warning("Failed to start WSGI service: %s", exc)

    try:
        hub.joinall(services)
    except KeyboardInterrupt:
        logger.debug("Keyboard Interrupt received. Closing OSKen application manager...")
    finally:
        app_mgr.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
