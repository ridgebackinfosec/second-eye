"""Foreground daemon orchestration and signal handling (SPEC.md §4, §9).

Wires every prior phase together: scope matching, TLS CA/leaf certs,
upstream routing, the CONNECT/plain-HTTP listener, the intercept/plain-HTTP
handlers, capture recording, and the control socket. ``Daemon.run()`` is
what ``secondeye proxy start`` (cli.py, this same phase) blocks on in the
foreground all day, per SPEC.md §1's operator workflow.

All daemon-startup validation (loopback --listen-address, upstream trust flags)
happens as a side effect of constructing the pieces below — ProxyListener
validates loopback in its own __init__ (SPEC.md §4.7) and UpstreamConnector
validates trust config in its own __init__ (SPEC.md §2) — so Daemon.__init__
fails loud before any socket is ever bound, without duplicating those
checks here.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import signal
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from secondeye.exceptions import ConfigError
from secondeye.proxy.intercept import InterceptHandler
from secondeye.proxy.listener import ProxyListener
from secondeye.proxy.plain_http import PlainHttpHandler
from secondeye.proxy.upstream import UpstreamConnector
from secondeye.recording.control import ControlServer, build_capture_handlers
from secondeye.recording.manager import CaptureManager
from secondeye.scope.matcher import ScopeMatcher
from secondeye.tls.ca import default_state_dir, load_or_create_ca
from secondeye.tls.leaf import LeafCertificateStore

__all__ = ["Daemon", "DaemonConfig"]

logger = logging.getLogger(__name__)

_CONTROL_SOCKET_FILENAME = "control.sock"


@dataclass(frozen=True)
class DaemonConfig:
    """Fully-resolved ``secondeye proxy start`` configuration (SPEC.md §2).

    Attributes:
        listen_host: Bind host for the proxy listener; must be loopback.
        listen_port: Bind port for the proxy listener.
        targets: --target values.
        target_regex: --target-regex values.
        upstream_host: Upstream proxy host, unless no_upstream.
        upstream_port: Upstream proxy port, unless no_upstream.
        no_upstream: Whether --no-upstream was set.
        upstream_ca: Path to the upstream's CA cert (PEM), if provided.
        upstream_insecure: Whether --upstream-insecure was set.
        target_all: Whether --target-all was set.
        cluster_window_ms: --cluster-window value.
        max_connections: --max-connections value.
        state_dir: secondeye's state directory.
    """

    listen_host: str = "127.0.0.1"
    listen_port: int = 8079
    targets: list[str] = field(default_factory=list)
    target_regex: list[str] = field(default_factory=list)
    upstream_host: str | None = "127.0.0.1"
    upstream_port: int | None = 8080
    no_upstream: bool = False
    upstream_ca: Path | None = None
    upstream_insecure: bool = False
    target_all: bool = False
    cluster_window_ms: int = 2000
    max_connections: int = 256
    state_dir: Path = field(default_factory=default_state_dir)


class Daemon:
    """Orchestrates one ``secondeye proxy start`` run, start to shutdown."""

    def __init__(self, config: DaemonConfig) -> None:
        """Build every component; fails loud before any socket binds.

        Args:
            config: Fully-resolved daemon configuration.

        Raises:
            ConfigError: If --listen-address isn't loopback, upstream trust
                flags are invalid (SPEC.md §2, raised by the relevant
                component's own __init__, not duplicated here), or no scope
                was configured at all (SPEC.md §2 marks --target "required
                (at least one)"; -tf/--target-file, --target-regex, or
                --target-all alone also satisfy this, since all are
                legitimate alternative scope mechanisms per SPEC.md
                §3.3/§3.4/§3.7).
            ScopeConfigError: If a --target-regex pattern doesn't compile.
        """
        self._config = config
        self._shutdown_event = asyncio.Event()

        if not config.targets and not config.target_regex and not config.target_all:
            raise ConfigError(
                "at least one --target or --target-regex is required "
                "(or pass --target-all to bypass scope matching entirely)"
            )

        if config.upstream_insecure:
            logger.warning(
                "--upstream-insecure set: TLS verification on the upstream leg is disabled"
            )

        self._scope_matcher = ScopeMatcher(
            targets=config.targets, target_regexes=config.target_regex
        )
        self._ca = load_or_create_ca(config.state_dir)
        self._leaf_store = LeafCertificateStore(self._ca)

        self._upstream_connector = UpstreamConnector(
            upstream_host=config.upstream_host,
            upstream_port=config.upstream_port,
            no_upstream=config.no_upstream,
            upstream_ca=config.upstream_ca,
            upstream_insecure=config.upstream_insecure,
        )

        self._capture_manager = CaptureManager(
            state_dir=config.state_dir,
            target_label=_derive_target_label(
                config.targets, config.target_regex, config.target_all
            ),
            targets=config.targets,
            target_regex=config.target_regex or None,
            target_all=config.target_all,
            upstream=_upstream_label(config),
            no_upstream=config.no_upstream,
            cluster_window_ms=config.cluster_window_ms,
        )

        self._intercept_handler = InterceptHandler(
            leaf_store=self._leaf_store,
            upstream_connector=self._upstream_connector,
            on_entry_recorded=self._capture_manager.record_entry,
        )
        self._plain_http_handler = PlainHttpHandler(
            scope_matcher=self._scope_matcher,
            target_all=config.target_all,
            upstream_connector=self._upstream_connector,
            on_entry_recorded=self._capture_manager.record_entry,
        )

        self._listener = ProxyListener(
            listen_host=config.listen_host,
            listen_port=config.listen_port,
            scope_matcher=self._scope_matcher,
            target_all=config.target_all,
            max_connections=config.max_connections,
            connect_remote=self._upstream_connector.connect_raw,
            on_in_scope=self._intercept_handler,
            on_plain_http=self._plain_http_handler,
        )

        handlers = build_capture_handlers(self._capture_manager)
        handlers["proxy.status"] = self._handle_status
        handlers["proxy.stop"] = self._handle_stop
        self._control_server = ControlServer(
            socket_path=config.state_dir / _CONTROL_SOCKET_FILENAME, handlers=handlers
        )

    @property
    def listener_bound_port(self) -> int:
        """The proxy listener's actual bound port (useful with an ephemeral --listen-address)."""
        return self._listener.bound_port

    @property
    def ca_was_created(self) -> bool:
        """Whether this run just generated a brand-new CA (vs. loading an existing one)."""
        return self._ca.created

    async def _handle_status(self, _params: dict[str, object]) -> dict[str, object]:
        active = self._capture_manager.active_capture
        return {
            "ok": True,
            "result": {
                "listen": f"{self._config.listen_host}:{self.listener_bound_port}",
                "scope": self._capture_manager.scope_summary(),
                "active_capture": (
                    {
                        "name": active.name,
                        "started_at": active.started_at.isoformat(),
                        "request_count": self._capture_manager.active_request_count,
                    }
                    if active is not None
                    else None
                ),
            },
        }

    async def _handle_stop(self, _params: dict[str, object]) -> dict[str, object]:
        self.request_shutdown()
        return {"ok": True, "result": {"stopping": True}}

    async def start(self) -> None:
        """Bind the control socket and proxy listener (does not block).

        The control socket is checked/bound first so that a second
        ``proxy start`` against the same state dir gets the specific
        "another secondeye daemon is already running" message instead of a
        generic port-in-use error from the listener (the common case: both
        instances use the same default --listen-address).
        """
        await self._control_server.start()
        await self._listener.start()
        logger.info(
            "secondeye listening on %s:%d", self._config.listen_host, self.listener_bound_port
        )

    async def wait_for_shutdown(self) -> None:
        """Block until a shutdown has been requested (signal or ``proxy stop``)."""
        await self._shutdown_event.wait()

    async def shutdown(self) -> None:
        """Flush an active capture if any, then close the listener and control socket.

        This is the exact same flush logic ``capture stop`` uses (SPEC.md
        §9) — there is no separate "emergency" code path.
        """
        if self._capture_manager.active_capture is not None:
            logger.info("flushing active capture before shutdown")
            await self._capture_manager.stop_capture()
        await self._listener.stop()
        await self._control_server.stop()
        logger.info("secondeye stopped")

    def request_shutdown(self) -> None:
        """Signal wait_for_shutdown() to return."""
        self._shutdown_event.set()

    def install_signal_handlers(self) -> None:
        """Register SIGINT/SIGTERM handlers on the running event loop (SPEC.md §9)."""
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self._handle_signal)

    def _handle_signal(self) -> None:
        if self._shutdown_event.is_set():
            logger.warning("second interrupt received; forcing immediate exit")
            os._exit(1)
        logger.info("shutdown signal received")
        self._shutdown_event.set()

    async def run(self, *, on_started: Callable[[], None] | None = None) -> None:
        """The full foreground lifecycle: bind, install signal handlers, wait, shut down.

        Args:
            on_started: Optional callback invoked once, synchronously, right
                after a successful bind (both the control socket and the
                proxy listener) and before signal handlers are installed.
                Lets a caller (cli.py) print a startup banner without
                daemon.py knowing anything about console presentation.
        """
        await self.start()
        if on_started is not None:
            on_started()
        self.install_signal_handlers()
        try:
            await self.wait_for_shutdown()
        finally:
            await self.shutdown()


def _derive_target_label(targets: list[str], target_regex: list[str], target_all: bool) -> str:
    if targets:
        return re.sub(r"[^a-zA-Z0-9-]", "-", targets[0])
    if target_regex:
        return "target-regex"
    if target_all:
        return "target-all"
    return "scope"


def _upstream_label(config: DaemonConfig) -> str | None:
    if config.no_upstream:
        return None
    return f"{config.upstream_host}:{config.upstream_port}"
