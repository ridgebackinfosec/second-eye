"""Unix domain socket control channel: transport only (SPEC.md §6.4).

Line-delimited JSON request/response over ``~/.local/state/secondeye/control.sock``.
``ControlServer`` itself knows nothing about capture lifecycle or daemon
state — it dispatches by command name to an injected handler mapping, so
the wire protocol can change later without touching business logic
(SPEC.md §13's module boundary rationale). ``build_capture_handlers()``
wires up the SPEC.md §2 ``capture start/stop/list`` commands against a
recording/manager.py CaptureManager; daemon.py (a later phase) supplies
its own handlers for ``proxy status``/``proxy stop`` and merges the two
mappings before constructing the server.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path

from secondeye.exceptions import (
    CaptureAlreadyActiveError,
    CaptureControlError,
    CaptureNameConflictError,
    ConfigError,
    SecondEyeError,
)
from secondeye.recording.manager import ActiveCapture, CaptureManager, CaptureResult

__all__ = [
    "CommandHandler",
    "ControlServer",
    "ControlSocketUnavailableError",
    "build_capture_handlers",
    "send_request",
]

logger = logging.getLogger(__name__)

CommandHandler = Callable[[dict[str, object]], Awaitable[dict[str, object]]]


class ControlSocketUnavailableError(SecondEyeError):
    """Raised by a control-socket client when no daemon is reachable (SPEC.md §2)."""


class ControlServer:
    """Unix domain socket server dispatching control commands by name."""

    def __init__(self, *, socket_path: Path, handlers: dict[str, CommandHandler]) -> None:
        """Prepare the server (not yet listening).

        Args:
            socket_path: Where to bind the control socket.
            handlers: Command name -> async handler, each returning a
                ``{"ok": True, "result": ...}`` response dict. Handlers may
                raise a SecondEyeError subclass instead of returning an
                error dict themselves; CaptureControlError is caught and
                serialized here (see _error_to_dict).
        """
        self._socket_path = socket_path
        self._handlers = handlers
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        """Bind the control socket and begin accepting clients.

        Raises:
            ConfigError: If another daemon is already listening on this
                socket path (see ``_is_socket_live``). A stale socket file
                left behind by an unclean shutdown, with nothing listening
                behind it, is unlinked and reused as before.
        """
        self._socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self._socket_path.exists():
            if await _is_socket_live(self._socket_path):
                raise ConfigError(
                    f"another secondeye daemon is already running "
                    f"(control socket {self._socket_path} is in use). "
                    "Run 'secondeye proxy stop' first."
                )
            self._socket_path.unlink()
        self._server = await asyncio.start_unix_server(
            self._handle_client, path=str(self._socket_path)
        )

    async def stop(self) -> None:
        """Stop accepting clients and remove the socket file."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        if self._socket_path.exists():
            self._socket_path.unlink()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            line = await reader.readline()
            if not line:
                return
            try:
                request = json.loads(line)
            except json.JSONDecodeError:
                response: dict[str, object] = {
                    "ok": False,
                    "error": {"type": "ProtocolError", "message": "invalid JSON request"},
                }
            else:
                response = await self._dispatch(request)
            writer.write(json.dumps(response).encode("utf-8") + b"\n")
            await writer.drain()
        except Exception:
            logger.exception("unhandled exception handling control client")
        finally:
            if not writer.is_closing():
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass

    async def _dispatch(self, request: object) -> dict[str, object]:
        if not isinstance(request, dict):
            return {
                "ok": False,
                "error": {"type": "ProtocolError", "message": "request must be an object"},
            }

        command = request.get("command")
        params = request.get("params") or {}
        if not isinstance(params, dict):
            return {
                "ok": False,
                "error": {"type": "ProtocolError", "message": "params must be an object"},
            }

        handler = self._handlers.get(str(command))
        if handler is None:
            return {
                "ok": False,
                "error": {"type": "UnknownCommand", "message": f"unknown command {command!r}"},
            }

        try:
            return await handler(params)
        except CaptureControlError as exc:
            return {"ok": False, "error": _error_to_dict(exc)}


async def _is_socket_live(socket_path: Path) -> bool:
    """Whether something is actively listening on an existing socket path.

    A stale socket file left behind by an unclean shutdown refuses the
    connection immediately (ECONNREFUSED); a live daemon accepts it.
    """
    try:
        _reader, writer = await asyncio.open_unix_connection(path=str(socket_path))
    except OSError:
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True


async def send_request(
    socket_path: Path, command: str, params: dict[str, object] | None = None
) -> dict[str, object]:
    """Send one control request and return the daemon's response.

    Args:
        socket_path: Path to the running daemon's control socket.
        command: The command name, e.g. "capture.start".
        params: Command parameters, if any.

    Returns:
        The decoded response: ``{"ok": True, "result": ...}`` or
        ``{"ok": False, "error": {"type": ..., "message": ..., ...}}``.

    Raises:
        ControlSocketUnavailableError: If no daemon is reachable at
            socket_path (SPEC.md §2's "no running secondeye daemon found").
    """
    try:
        reader, writer = await asyncio.open_unix_connection(path=str(socket_path))
    except OSError as exc:
        raise ControlSocketUnavailableError(
            f"no running secondeye daemon found (control socket {socket_path} unavailable): {exc}"
        ) from exc

    try:
        request = {"command": command, "params": params or {}}
        writer.write(json.dumps(request).encode("utf-8") + b"\n")
        await writer.drain()
        line = await reader.readline()
        if not line:
            raise ControlSocketUnavailableError(
                f"daemon at {socket_path} closed the connection without responding"
            )
        response: dict[str, object] = json.loads(line)
        return response
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


def build_capture_handlers(manager: CaptureManager) -> dict[str, CommandHandler]:
    """Build the ``capture.start``/``capture.stop``/``capture.list`` handlers
    for a ControlServer, relaying to a CaptureManager (SPEC.md §2).

    Args:
        manager: The capture lifecycle state machine to relay to.

    Returns:
        A handler mapping suitable for merging into ControlServer's
        ``handlers``.
    """

    async def start(params: dict[str, object]) -> dict[str, object]:
        active = manager.start_capture(str(params["name"]))
        return {"ok": True, "result": _active_capture_to_dict(active, manager)}

    async def stop(_params: dict[str, object]) -> dict[str, object]:
        result = await manager.stop_capture()
        return {"ok": True, "result": _capture_result_to_dict(result)}

    async def list_captures(_params: dict[str, object]) -> dict[str, object]:
        results = manager.list_captures()
        return {"ok": True, "result": [_capture_result_to_dict(r) for r in results]}

    return {"capture.start": start, "capture.stop": stop, "capture.list": list_captures}


def _active_capture_to_dict(active: ActiveCapture, manager: CaptureManager) -> dict[str, object]:
    return {
        "name": active.name,
        "started_at": active.started_at.isoformat(),
        "output_dir": str(active.output_dir),
        "scope": manager.scope_summary(),
    }


def _capture_result_to_dict(result: CaptureResult) -> dict[str, object]:
    return {
        "name": result.name,
        "request_count": result.request_count,
        "total_bytes": result.total_bytes,
        "output_dir": str(result.output_dir),
        "raw_har_path": str(result.raw_har_path),
        "manifest_path": str(result.manifest_path),
        "analysis_path": str(result.analysis_path),
    }


def _error_to_dict(exc: CaptureControlError) -> dict[str, object]:
    d: dict[str, object] = {"type": type(exc).__name__, "message": str(exc)}
    if isinstance(exc, CaptureAlreadyActiveError):
        d["name"] = exc.name
        d["started_at"] = exc.started_at.isoformat()
    elif isinstance(exc, CaptureNameConflictError):
        d["name"] = exc.name
        d["output_dir"] = str(exc.output_dir)
    return d
