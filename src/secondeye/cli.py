"""argparse entrypoint, subcommand dispatch (SPEC.md §2).

``secondeye <noun> <verb>``: ``proxy start/stop/status``, ``capture
start/stop/list``, ``ca export/import-upstream``. ``proxy start`` runs the
foreground daemon (daemon.py); every other subcommand is a short-lived
control-socket client (or, for ``ca``, a local filesystem operation —
SPEC.md §1's workflow calls ``ca export`` before ``proxy start`` even
exists, so it can't depend on a running daemon).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

import h11
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from secondeye.daemon import Daemon, DaemonConfig
from secondeye.exceptions import SecondEyeError, UpstreamConnectionError
from secondeye.recording.control import ControlSocketUnavailableError, send_request
from secondeye.tls.ca import default_state_dir, load_or_create_ca

__all__ = ["main"]

_DEFAULT_LISTEN = "127.0.0.1:8079"
_DEFAULT_UPSTREAM = "127.0.0.1:8080"
_DEFAULT_LISTEN_PORT = 8079
_DEFAULT_UPSTREAM_PORT = 8080


def main(argv: list[str] | None = None) -> int:
    """CLI entry point (``secondeye`` console script).

    Args:
        argv: Arguments to parse; defaults to ``sys.argv[1:]``.

    Returns:
        The process exit code.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except SecondEyeError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secondeye")
    nouns = parser.add_subparsers(dest="noun", required=True)

    proxy = nouns.add_parser("proxy")
    proxy_verbs = proxy.add_subparsers(dest="verb", required=True)

    start = proxy_verbs.add_parser("start")
    start.add_argument("--target", action="append", default=[])
    start.add_argument("--target-regex", action="append", default=[])
    start.add_argument("--listen", default=_DEFAULT_LISTEN)
    start.add_argument("--upstream", default=_DEFAULT_UPSTREAM)
    start.add_argument("--no-upstream", action="store_true")
    start.add_argument("--upstream-ca", type=Path, default=None)
    start.add_argument("--upstream-insecure", action="store_true")
    start.add_argument("--capture-all", action="store_true")
    start.add_argument("--cluster-window", type=int, default=2000)
    start.add_argument("--max-connections", type=int, default=256)
    start.add_argument("-v", "--verbose", action="store_true")
    start.add_argument("-q", "--quiet", action="store_true")
    start.set_defaults(handler=_cmd_proxy_start)

    proxy_verbs.add_parser("stop").set_defaults(handler=_cmd_proxy_stop)
    proxy_verbs.add_parser("status").set_defaults(handler=_cmd_proxy_status)

    capture = nouns.add_parser("capture")
    capture_verbs = capture.add_subparsers(dest="verb", required=True)

    cap_start = capture_verbs.add_parser("start")
    cap_start.add_argument("--name", required=True)
    cap_start.set_defaults(handler=_cmd_capture_start)

    capture_verbs.add_parser("stop").set_defaults(handler=_cmd_capture_stop)
    capture_verbs.add_parser("list").set_defaults(handler=_cmd_capture_list)

    ca = nouns.add_parser("ca")
    ca_verbs = ca.add_subparsers(dest="verb", required=True)

    ca_export = ca_verbs.add_parser("export")
    ca_export.add_argument("--format", choices=["der", "pem"], default="pem")
    ca_export.set_defaults(handler=_cmd_ca_export)

    ca_import = ca_verbs.add_parser("import-upstream")
    ca_import.add_argument("--from-burp", action="store_true", required=True)
    ca_import.add_argument("--upstream", default=_DEFAULT_UPSTREAM)
    ca_import.add_argument("--output", type=Path, default=Path("burp-ca.pem"))
    ca_import.set_defaults(handler=_cmd_ca_import_upstream)

    return parser


# --------------------------------------------------------------------------
# proxy start/stop/status
# --------------------------------------------------------------------------


def _cmd_proxy_start(args: argparse.Namespace) -> int:
    _configure_logging(args)
    listen_host, listen_port = _parse_host_port(args.listen, _DEFAULT_LISTEN_PORT)

    if args.no_upstream:
        upstream_host: str | None = None
        upstream_port: int | None = None
    else:
        upstream_host, upstream_port = _parse_host_port(args.upstream, _DEFAULT_UPSTREAM_PORT)

    config = DaemonConfig(
        listen_host=listen_host,
        listen_port=listen_port,
        targets=args.target,
        target_regex=args.target_regex,
        upstream_host=upstream_host,
        upstream_port=upstream_port,
        no_upstream=args.no_upstream,
        upstream_ca=args.upstream_ca,
        upstream_insecure=args.upstream_insecure,
        capture_all=args.capture_all,
        cluster_window_ms=args.cluster_window,
        max_connections=args.max_connections,
        state_dir=default_state_dir(),
    )
    daemon = Daemon(config)
    asyncio.run(daemon.run())
    return 0


def _cmd_proxy_stop(_args: argparse.Namespace) -> int:
    try:
        response = asyncio.run(send_request(_control_socket_path(), "proxy.stop"))
    except ControlSocketUnavailableError:
        print("✗ No running secondeye daemon found.", file=sys.stderr)
        return 1
    if not response.get("ok"):
        print(f"✗ {_error_message(response)}", file=sys.stderr)
        return 1
    print("✓ secondeye daemon stopping.")
    return 0


def _cmd_proxy_status(_args: argparse.Namespace) -> int:
    try:
        response = asyncio.run(send_request(_control_socket_path(), "proxy.status"))
    except ControlSocketUnavailableError:
        print("Daemon running: no")
        return 0
    if not response.get("ok"):
        print(f"✗ {_error_message(response)}", file=sys.stderr)
        return 1

    result = response["result"]
    assert isinstance(result, dict)
    scope = result["scope"]
    assert isinstance(scope, dict)

    print("Daemon running: yes")
    print(f"Listener:       {result['listen']}")
    print(f"Scope:          {_format_scope(scope)}")
    if scope["no_upstream"]:
        print("Upstream:       none (--no-upstream)")
    else:
        print(f"Upstream:       {scope['upstream']}")

    active = result["active_capture"]
    if active is None:
        print("Active capture: none")
    else:
        assert isinstance(active, dict)
        started_at = _format_local_time(str(active["started_at"]))
        print(f"Active capture: {active['name']} (started {started_at})")
    return 0


# --------------------------------------------------------------------------
# capture start/stop/list
# --------------------------------------------------------------------------


def _cmd_capture_start(args: argparse.Namespace) -> int:
    try:
        response = asyncio.run(
            send_request(_control_socket_path(), "capture.start", {"name": args.name})
        )
    except ControlSocketUnavailableError:
        print("✗ Cannot start capture: no running secondeye daemon found.", file=sys.stderr)
        print("  Run 'secondeye proxy start --target <domain>' first.", file=sys.stderr)
        return 1

    if not response.get("ok"):
        error = response["error"]
        assert isinstance(error, dict)
        error_type = error.get("type")
        if error_type == "CaptureAlreadyActiveError":
            started_at = _format_local_time(str(error["started_at"]))
            print(
                f"✗ Cannot start capture: a capture is already active "
                f"({error['name']!r}, started {started_at}).",
                file=sys.stderr,
            )
            print("  Run 'secondeye capture stop' first.", file=sys.stderr)
        elif error_type == "CaptureNameConflictError":
            print(
                f"✗ Cannot start capture: a capture named {error['name']!r} "
                "already exists for today.",
                file=sys.stderr,
            )
            print(f"  Pick a different name or remove {error['output_dir']}.", file=sys.stderr)
        else:
            print(f"✗ Cannot start capture: {error['message']}", file=sys.stderr)
        return 1

    result = response["result"]
    assert isinstance(result, dict)
    scope = result["scope"]
    assert isinstance(scope, dict)

    print(f"✓ Capture started: {result['name']}")
    print(f"  Started at:  {_format_utc_time(str(result['started_at']))}")
    print(f"  Output dir:  {result['output_dir']}/")
    print(f"  Scope:       {_format_scope(scope)}")
    print()
    print("Recording in-scope traffic. Run 'secondeye capture stop' when done.")
    return 0


def _cmd_capture_stop(_args: argparse.Namespace) -> int:
    try:
        response = asyncio.run(send_request(_control_socket_path(), "capture.stop"))
    except ControlSocketUnavailableError:
        print("✗ Cannot stop capture: no running secondeye daemon found.", file=sys.stderr)
        return 1

    if not response.get("ok"):
        print(f"✗ Cannot stop capture: {_error_message(response)}", file=sys.stderr)
        return 1

    result = response["result"]
    assert isinstance(result, dict)
    size_str = _format_bytes(int(result["total_bytes"]))
    print(f"✓ Capture stopped: {result['name']} ({result['request_count']} requests, {size_str})")
    return 0


def _cmd_capture_list(_args: argparse.Namespace) -> int:
    try:
        response = asyncio.run(send_request(_control_socket_path(), "capture.list"))
    except ControlSocketUnavailableError:
        print("✗ No running secondeye daemon found.", file=sys.stderr)
        return 1

    if not response.get("ok"):
        print(f"✗ {_error_message(response)}", file=sys.stderr)
        return 1

    captures = response["result"]
    assert isinstance(captures, list)
    if not captures:
        print("No captures recorded yet this run.")
        return 0

    for capture in captures:
        assert isinstance(capture, dict)
        size_str = _format_bytes(int(capture["total_bytes"]))
        print(
            f"{capture['name']}: {capture['request_count']} requests, "
            f"{size_str} -> {capture['output_dir']}"
        )
    return 0


# --------------------------------------------------------------------------
# ca export/import-upstream
# --------------------------------------------------------------------------


def _cmd_ca_export(args: argparse.Namespace) -> int:
    ca = load_or_create_ca(default_state_dir())
    encoding = serialization.Encoding.DER if args.format == "der" else serialization.Encoding.PEM
    sys.stdout.buffer.write(ca.certificate.public_bytes(encoding))
    return 0


def _cmd_ca_import_upstream(args: argparse.Namespace) -> int:
    host, port = _parse_host_port(args.upstream, _DEFAULT_UPSTREAM_PORT)
    der_bytes = asyncio.run(_fetch_upstream_cert(host, port))
    certificate = x509.load_der_x509_certificate(der_bytes)
    pem_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    args.output.write_bytes(pem_bytes)
    print(f"✓ Saved upstream CA to {args.output}")
    print(f"  Use with: secondeye proxy start --upstream-ca {args.output} ...")
    return 0


async def _fetch_upstream_cert(host: str, port: int) -> bytes:
    """Fetch a proxy's CA cert from its well-known /cert endpoint (SPEC.md §5.5).

    Args:
        host: The upstream proxy's host.
        port: The upstream proxy's port.

    Returns:
        The DER-encoded certificate bytes.

    Raises:
        UpstreamConnectionError: If the fetch fails or doesn't return a
            usable 200 response.
    """
    try:
        reader, writer = await asyncio.open_connection(host, port)
    except OSError as exc:
        raise UpstreamConnectionError(f"failed to connect to {host}:{port}: {exc}") from exc

    try:
        conn = h11.Connection(our_role=h11.CLIENT)
        request = h11.Request(
            method="GET", target="/cert", headers=[("Host", "burp"), ("Connection", "close")]
        )
        data = conn.send(request)
        if data:
            writer.write(data)
        data = conn.send(h11.EndOfMessage())
        if data:
            writer.write(data)
        await writer.drain()

        response_event: h11.Response | h11.InformationalResponse | None = None
        body = b""
        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA:
                chunk = await reader.read(65536)
                conn.receive_data(chunk)
                continue
            if isinstance(event, h11.Response):
                response_event = event
            elif isinstance(event, h11.Data):
                body += bytes(event.data)
            elif isinstance(event, h11.EndOfMessage | h11.ConnectionClosed):
                break
    except OSError as exc:
        raise UpstreamConnectionError(f"failed reading from {host}:{port}: {exc}") from exc
    finally:
        writer.close()

    if response_event is None or response_event.status_code != 200:
        status = response_event.status_code if response_event is not None else "no response"
        raise UpstreamConnectionError(
            f"failed to fetch CA from {host}:{port}/cert (status: {status})"
        )
    return body


# --------------------------------------------------------------------------
# shared helpers
# --------------------------------------------------------------------------


def _control_socket_path() -> Path:
    return default_state_dir() / "control.sock"


def _configure_logging(args: argparse.Namespace) -> None:
    if args.verbose:
        level = logging.DEBUG
    elif args.quiet:
        level = logging.WARNING
    else:
        level = logging.INFO
    logging.basicConfig(
        level=level, stream=sys.stderr, format="%(levelname)s %(name)s: %(message)s"
    )


def _parse_host_port(value: str, default_port: int) -> tuple[str, int]:
    if value.startswith("["):
        host, _, rest = value[1:].partition("]")
        port_str = rest.lstrip(":") or str(default_port)
        return host, int(port_str)
    host, sep, port_str = value.rpartition(":")
    if not sep:
        return value, default_port
    return host, int(port_str)


def _format_bytes(n: int) -> str:
    if n < 1024:
        return f"{n}B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f}KB"
    return f"{n / (1024 * 1024):.1f}MB"


def _format_scope(scope: dict[str, object]) -> str:
    targets = scope.get("targets") or []
    assert isinstance(targets, list)
    target_regex = scope.get("target_regex") or []
    assert isinstance(target_regex, list)
    parts = [str(t) for t in targets] + [str(t) for t in target_regex]
    scope_str = ", ".join(parts) if parts else "(none)"
    if scope.get("capture_all"):
        scope_str += " [--capture-all]"
    return scope_str


def _format_utc_time(iso_value: str) -> str:
    import datetime

    dt = datetime.datetime.fromisoformat(iso_value.replace("Z", "+00:00"))
    return dt.astimezone(datetime.UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _format_local_time(iso_value: str) -> str:
    import datetime

    dt = datetime.datetime.fromisoformat(iso_value.replace("Z", "+00:00"))
    return dt.astimezone(datetime.UTC).strftime("%H:%M:%S")


def _error_message(response: dict[str, object]) -> str:
    error = response.get("error")
    if isinstance(error, dict) and "message" in error:
        return str(error["message"])
    return "unknown error"


if __name__ == "__main__":
    sys.exit(main())
