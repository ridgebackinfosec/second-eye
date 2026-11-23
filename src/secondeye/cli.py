"""argparse entrypoint, subcommand dispatch (SPEC.md §2).

``secondeye <noun> <verb>``: ``proxy start/stop/status``, ``capture
start/stop/list``, ``ca export/import-upstream``. ``proxy start`` runs the
foreground daemon (daemon.py); every other subcommand is a short-lived
control-socket client (or, for ``ca``, a local filesystem operation —
SPEC.md §1's workflow calls ``ca export`` before ``proxy start`` even
exists, so it can't depend on a running daemon).
"""

# PYTHON_ARGCOMPLETE_OK

from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import logging
import shlex
import sys
from dataclasses import replace
from pathlib import Path

import argcomplete
import h11
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

import secondeye
from secondeye.analysis.cluster import DEFAULT_CLUSTER_WINDOW_MS
from secondeye.analysis.pipeline import CaptureMetadata, write_capture_outputs
from secondeye.capture.buffer import read_buffer
from secondeye.capture.store import BUFFER_FILENAME, discover_captures, find_buffer, load_capture
from secondeye.daemon import Daemon, DaemonConfig
from secondeye.doctor import run_checks
from secondeye.exceptions import ConfigError, SecondEyeError, UpstreamConnectionError
from secondeye.recording.control import ControlSocketUnavailableError, send_request
from secondeye.tls.ca import ca_exists, default_state_dir, load_or_create_ca
from secondeye.tls.trust import (
    build_install_command,
    discover_nss_profiles,
    install_into_profile,
    remove_from_profile,
    system_store_instructions,
)
from secondeye.ui import (
    ActiveCaptureView,
    CaptureRow,
    CaptureStartedView,
    CaptureStoppedView,
    CaStatusView,
    HelpEntry,
    HelpSection,
    HelpView,
    ScopeView,
    StartupView,
    StatusView,
    ui,
)

__all__ = ["main"]

_DEFAULT_LISTEN = "127.0.0.1:8079"
_DEFAULT_UPSTREAM = "127.0.0.1:8080"
_DEFAULT_LISTEN_PORT = 8079
_DEFAULT_UPSTREAM_PORT = 8080

_VERSION = secondeye.__version__

# Width handed to argparse when synthesising a usage line we intend to
# wrap ourselves: large enough that argparse never inserts a break.
_UNBOUNDED_WIDTH = 10_000


class SecondEyeParser(argparse.ArgumentParser):
    """An ``ArgumentParser`` whose help renders through ``ui.py``.

    ``--help`` was the one human-facing surface still writing raw
    argparse output while every other surface went through the rich
    presentation layer. Overriding ``format_help`` rather than supplying
    a ``formatter_class`` is deliberate on two counts:

    - argparse computes its help-column width from raw string length, so
      a formatter that injected ANSI escapes would corrupt its own
      alignment. Rendering the whole screen ourselves avoids that
      arithmetic entirely.
    - argparse routes ``-h``, ``print_help()``, ``print_usage()`` and
      the documentation generator's capture through ``format_help``, so
      one override covers every path that can produce a help screen.

    ``add_subparsers`` defaults ``parser_class`` to ``type(self)``, so
    every subparser inherits this behaviour with nothing passed per call.

    Attributes:
        examples: Runnable command lines shown under an "Examples"
            heading. Passed as a keyword to ``add_parser``/``__init__``.
        help_columns: Wrap width override; None means "detect".
    """

    def __init__(self, *args: object, examples: tuple[str, ...] = (), **kwargs: object) -> None:
        self.examples = examples
        self.help_columns: int | None = None
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]

    def format_help(self) -> str:
        """Render this parser's help screen.

        Returns:
            The rendered screen, as argparse's contract requires.
        """
        return ui.help_screen(self._help_view(), width=self.help_columns)

    def _get_formatter(self) -> argparse.HelpFormatter:
        """Build argparse's formatter, honouring ``help_columns``.

        Only the usage line still comes from argparse (via
        ``format_usage``), but argparse sizes it from its own terminal
        detection. Without this the usage line would wrap to the real
        terminal while the rest of the screen wrapped to the requested
        width — visible as an over-long first line.

        Returns:
            A formatter for this parser.
        """
        if self.help_columns is None:
            return super()._get_formatter()
        return argparse.HelpFormatter(prog=self.prog, width=self.help_columns)

    def _help_view(self) -> HelpView:
        """Adapt argparse's own structures into a renderable view.

        Only ``_action_groups``/``_actions`` are read from argparse's
        internals. Both are stable across the Python versions this
        project supports and are what every third-party argparse
        formatter already relies on; the alternative is re-deriving
        argument metadata that argparse has already computed.

        Returns:
            The equivalent HelpView.
        """
        positionals: list[HelpSection] = []
        custom: list[HelpSection] = []
        builtin_options: list[HelpSection] = []
        for group in self._action_groups:
            entries: list[HelpEntry] = []
            holds_subcommands = False
            for action in group._group_actions:
                if action.help is argparse.SUPPRESS:
                    continue
                if isinstance(action, argparse._SubParsersAction):
                    # The action itself is just a metavar; the useful
                    # content is one pseudo-action per choice, carrying
                    # the `help=` each add_parser call supplied.
                    holds_subcommands = True
                    entries.extend(
                        HelpEntry(
                            invocation=_metavar(choice) or choice.dest,
                            help_text=choice.help or "",
                        )
                        for choice in action._get_subactions()
                        if choice.help is not argparse.SUPPRESS
                    )
                    continue
                entries.append(
                    HelpEntry(invocation=_invocation(action), help_text=action.help or "")
                )
            if not entries:
                continue
            section = HelpSection(
                title="Commands" if holds_subcommands else _section_title(group.title),
                description=group.description,
                entries=tuple(entries),
            )
            # argparse yields its two built-in groups first, which would
            # otherwise open every grouped screen with a lone "-h,
            # --help" before anything the reader came for. Positionals
            # stay first (they are the command's subject); the options
            # bucket sinks to the bottom.
            if group is self._positionals:
                positionals.append(section)
            elif group is self._optionals:
                builtin_options.append(section)
            else:
                custom.append(section)
        return HelpView(
            usage=self._unwrapped_usage(),
            prog=self.prog,
            description=self.description,
            sections=tuple(positionals + custom + builtin_options),
            examples=self.examples,
        )

    def _unwrapped_usage(self) -> str:
        """Synthesise the usage text as a single unwrapped line.

        argparse builds the usage string, which is genuinely useful —
        it knows which arguments are optional, which are mutually
        exclusive, and how to notate both. But it also wraps it, and at
        a narrow width its fixed continuation indent overflows. Asking
        for it at an effectively unbounded width yields one long line
        for ``ui.py`` to wrap properly.

        Returns:
            The usage text, without argparse's ``usage: `` prefix.
        """
        formatter = argparse.HelpFormatter(prog=self.prog, width=_UNBOUNDED_WIDTH)
        formatter.add_usage(self.usage, self._actions, self._mutually_exclusive_groups)
        return formatter.format_help().removeprefix("usage: ").strip()


def _section_title(title: str | None) -> str:
    """Capitalise an argparse group title for display.

    argparse names its two built-in groups ``"positional arguments"``
    and ``"options"``; the groups added here are already written as
    headings. Returns a heading either way.

    Args:
        title: The group's title, if it has one.

    Returns:
        A display heading.
    """
    if not title:
        return "Options"
    return title[0].upper() + title[1:]


def _invocation(action: argparse.Action) -> str:
    """Render how one action is written on the command line.

    Args:
        action: The argparse action.

    Returns:
        e.g. ``"-tf, --target-file FILE"``, or ``"directory"`` for a
        positional.
    """
    if not action.option_strings:
        return _metavar(action) or action.dest
    if action.nargs == 0:
        return ", ".join(action.option_strings)
    return ", ".join(action.option_strings) + " " + (_metavar(action) or action.dest.upper())


def _metavar(action: argparse.Action) -> str:
    """One action's metavar as a single string.

    argparse allows a tuple of metavars, one per value, for an action
    taking several (``nargs=2``). Nothing here does, but the type is
    part of the API and joining is the right answer if one ever appears.

    Args:
        action: The argparse action.

    Returns:
        The metavar, or "" if it has none.
    """
    if action.metavar is None:
        return ""
    if isinstance(action.metavar, tuple):
        return " ".join(action.metavar)
    return action.metavar


def main(argv: list[str] | None = None) -> int:
    """CLI entry point (``secondeye`` console script).

    Args:
        argv: Arguments to parse; defaults to ``sys.argv[1:]``.

    Returns:
        The process exit code.
    """
    parser = _build_parser()
    argcomplete.autocomplete(parser)
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except SecondEyeError as exc:
        ui.error(str(exc))
        return 1
    except KeyboardInterrupt:
        return 130


def _build_parser() -> SecondEyeParser:
    parser = SecondEyeParser(
        prog="secondeye",
        description="A scope-gated, passive HTTP/HTTPS recording proxy for offensive "
        "security operators. Terminate and record only the traffic you are scoped "
        "for; everything else is relayed blind and never touched.",
        examples=(
            "# One-time setup: trust secondeye's CA in your browser.",
            "secondeye ca install",
            "# Check this machine is ready before an engagement.",
            "secondeye doctor",
            "# Terminal 1: run the daemon, chaining through Burp.",
            "secondeye proxy start --target example.com --upstream-ca burp-ca.pem",
            "# Terminal 2: record a window of traffic, then write it up.",
            "secondeye capture start --name auth-flow",
            "secondeye capture stop",
        ),
    )
    parser.add_argument("--version", "-V", action="version", version=f"%(prog)s {_VERSION}")
    nouns = parser.add_subparsers(dest="noun", required=True, metavar="COMMAND")

    proxy = nouns.add_parser(
        "proxy",
        description="Run and control the recording proxy daemon. 'proxy start' runs "
        "in the foreground and stays running for the whole engagement; 'stop' and "
        "'status' are short-lived clients you run from another terminal.",
        help="Run and control the recording proxy daemon.",
        examples=(
            "secondeye proxy start --target example.com --no-upstream",
            "secondeye proxy status",
            "secondeye proxy stop",
        ),
    )
    proxy_verbs = proxy.add_subparsers(dest="verb", required=True, metavar="VERB")

    start = proxy_verbs.add_parser(
        "start",
        description="Start the secondeye daemon in the foreground. Stays running until "
        "Ctrl+C or 'secondeye proxy stop', auto-flushing any active capture on exit. "
        "Requires a scope — at least one of --target, --target-file, --target-regex "
        "or --target-all — and an explicit decision about upstream TLS trust.",
        help="Start the daemon in the foreground (the main entry point).",
        examples=(
            "# Chain in-scope traffic through Burp, pinning Burp's CA.",
            "secondeye proxy start --target example.com --upstream-ca burp-ca.pem",
            "# Connect straight to each destination instead.",
            "secondeye proxy start --target example.com --no-upstream",
            "# Several targets, plus a pattern a glob can't express.",
            "secondeye proxy start --target example.com --target '*.corp.internal' \\",
            "    --target-regex '^(dev|stg)-.*\\.example\\.com$' --no-upstream",
        ),
    )

    scope_group = start.add_argument_group(
        "Scope",
        description="What gets terminated and inspected. At least one is required; "
        "everything you pass is OR'd together.",
    )
    scope_group.add_argument(
        "--target",
        metavar="DOMAIN",
        action="append",
        default=[],
        help="A domain to scope in, matched exactly plus all subdomains, or an explicit "
        "glob (e.g. '*.corp.internal'). Repeatable.",
    )
    scope_group.add_argument(
        "-tf",
        "--target-file",
        metavar="FILE",
        action="append",
        default=[],
        type=Path,
        help="A line-delimited file of --target-style entries (one per line; blank "
        "lines and lines starting with # are ignored). Repeatable, and merges with "
        "any --target values.",
    )
    scope_group.add_argument(
        "--target-regex",
        metavar="REGEX",
        action="append",
        default=[],
        help="A regular expression to scope in, for patterns a glob can't express "
        "(alternation, numeric ranges, wildcards on both sides). Repeatable. Prefer "
        "--target/--target-file for the common case.",
    )
    scope_group.add_argument(
        "--target-all",
        action="store_true",
        help="Bypass scope matching entirely: every domain is terminated/inspected "
        "for the life of this daemon. Useful for flows that redirect through "
        "third-party domains (OAuth/OIDC) that --target was never meant to "
        "enumerate. Recording still only happens while a capture is active.",
    )

    upstream_group = start.add_argument_group(
        "Upstream",
        description="Whether in-scope traffic is chained through an intercepting "
        "proxy, and how that leg's TLS is trusted. Exactly one trust decision is "
        "required — there is no silent default.",
    )
    upstream_group.add_argument(
        "--upstream-proxy",
        metavar="HOST:PORT",
        default=_DEFAULT_UPSTREAM,
        help=f"The upstream intercepting proxy's host:port (e.g. Burp or ZAP) to chain "
        f"in-scope traffic through. Default: {_DEFAULT_UPSTREAM}.",
    )
    # Exactly one, enforced here rather than only in
    # proxy/upstream.py's validate_upstream_tls_config: a required
    # mutually exclusive group puts the requirement in the usage line, so
    # the enforcement and the help text can no longer drift apart. The
    # library-level check stays as the invariant for any DaemonConfig
    # built without going through this parser.
    trust = upstream_group.add_mutually_exclusive_group(required=True)
    trust.add_argument(
        "--upstream-ca",
        metavar="FILE",
        type=Path,
        default=None,
        help="PEM file of the upstream proxy's CA certificate, used to validate the "
        "secondeye-to-upstream TLS leg. See 'secondeye ca import-upstream' to fetch one.",
    )
    trust.add_argument(
        "--upstream-insecure",
        action="store_true",
        help="Skip TLS verification on the upstream leg only (logs a warning at startup).",
    )
    trust.add_argument(
        "--no-upstream",
        action="store_true",
        help="Skip the upstream proxy entirely and connect directly to each "
        "destination, with full system trust store validation on that leg.",
    )

    output_group = start.add_argument_group(
        "Listener and output",
        description="Where the proxy listens, and where captures are written.",
    )
    output_group.add_argument(
        "--listen-address",
        metavar="HOST:PORT",
        default=_DEFAULT_LISTEN,
        help=f"The host:port the proxy listens on (e.g. '[::1]:8079' for IPv6). Host "
        f"must be loopback (127.0.0.1 or ::1) — no override exists. "
        f"Default: {_DEFAULT_LISTEN}.",
    )
    output_group.add_argument(
        "--captures-dir",
        metavar="DIR",
        type=Path,
        default=None,
        help="Directory to write capture output into, so captures can live "
        "alongside your engagement notes instead of under the state directory. "
        "Default: <state-dir>/captures (~/.local/state/secondeye/captures).",
    )
    output_group.add_argument(
        "--cluster-window",
        metavar="MS",
        type=int,
        default=DEFAULT_CLUSTER_WINDOW_MS,
        help="Milliseconds within which a request is grouped with the page "
        "navigation that preceded it, so its static assets are summarized in "
        "ANALYSIS.md rather than listed one by one. Does not affect polling "
        "deduplication, which keys off request interval rather than this "
        f"window. Default: {DEFAULT_CLUSTER_WINDOW_MS}.",
    )
    output_group.add_argument(
        "--max-connections",
        metavar="N",
        type=int,
        default=256,
        help="Maximum number of simultaneous client connections the proxy will "
        "accept. Default: 256.",
    )

    logging_group = start.add_argument_group(
        "Logging",
        description="Log verbosity on stderr. The startup banner is printed either way.",
    )
    verbosity = logging_group.add_mutually_exclusive_group()
    verbosity.add_argument(
        "-v", "--verbose", action="store_true", help="Log at DEBUG level instead of INFO."
    )
    verbosity.add_argument(
        "-q", "--quiet", action="store_true", help="Log at WARNING level instead of INFO."
    )
    start.set_defaults(handler=_cmd_proxy_start)

    proxy_verbs.add_parser(
        "stop",
        description="Stop a running secondeye daemon from another terminal. Any "
        "active capture is flushed to disk first, exactly as Ctrl+C would. "
        "Requires a running daemon.",
        help="Stop a running daemon from another terminal.",
        examples=("secondeye proxy stop",),
    ).set_defaults(handler=_cmd_proxy_stop)
    status = proxy_verbs.add_parser(
        "status",
        description="Report whether a daemon is running, its scope, its upstream, "
        "and the active capture's live request count. Exits 0 whether or not one is "
        "running — 'is it running?' is a question, not an error.",
        help="Report whether a daemon is running, its scope, and active capture.",
        examples=(
            "secondeye proxy status",
            "secondeye proxy status --json | jq .active_capture",
        ),
    )
    status.add_argument(
        "--json",
        action="store_true",
        help="Emit the status as JSON on stdout instead of a table, for scripting.",
    )
    status.set_defaults(handler=_cmd_proxy_status)

    capture = nouns.add_parser(
        "capture",
        description="Control recording windows against a running proxy daemon, and "
        "revisit finished ones. 'start' and 'stop' need a running daemon; 'list', "
        "'analyze' and 'recover' read the captures directory and need no daemon.",
        help="Control recording windows, and revisit finished captures.",
        examples=(
            "secondeye capture start --name auth-flow",
            "secondeye capture stop",
            "secondeye capture list",
        ),
    )
    capture_verbs = capture.add_subparsers(dest="verb", required=True, metavar="VERB")

    cap_start = capture_verbs.add_parser(
        "start",
        description="Start recording a named window of in-scope traffic. Requires a "
        "running daemon; only one capture may be active at a time.",
        help="Start recording a named window of in-scope traffic.",
        examples=("secondeye capture start --name auth-flow",),
    )
    cap_start.add_argument(
        "--name",
        metavar="LABEL",
        required=True,
        help="A label for this capture. Must be unique among today's captures for the "
        "current target; used in the output directory name.",
    )
    cap_start.set_defaults(handler=_cmd_capture_start)

    capture_verbs.add_parser(
        "stop",
        description="Stop the active capture and write raw.har, manifest.json and "
        "ANALYSIS.md into its output directory. Requires a running daemon.",
        help="Stop the active capture and write its three output files.",
        examples=("secondeye capture stop",),
    ).set_defaults(handler=_cmd_capture_stop)
    cap_list = capture_verbs.add_parser(
        "list",
        description="List captures on disk, newest first. Reads the captures "
        "directory, so it works with no daemon running and shows captures from "
        "previous runs too. No daemon required.",
        help="List captures on disk, newest first (no daemon required).",
        examples=(
            "secondeye capture list",
            "secondeye capture list --captures-dir ~/engagements/acme/captures",
        ),
    )
    cap_list.add_argument(
        "--captures-dir",
        metavar="DIR",
        type=Path,
        default=None,
        help="Captures directory to list. Default: <state-dir>/captures.",
    )
    cap_list.add_argument(
        "--json",
        action="store_true",
        help="Emit the listing as JSON on stdout instead of a table, for scripting.",
    )
    cap_list.set_defaults(handler=_cmd_capture_list)

    cap_analyze = capture_verbs.add_parser(
        "analyze",
        description="Re-render manifest.json and ANALYSIS.md from an existing "
        "capture's raw.har. Use this to bring an older capture up to the current "
        "analysis renderer, or to re-cluster it with a different "
        "--cluster-window. raw.har is never modified. No daemon required.",
        help="Re-render a capture's ANALYSIS.md/manifest.json from its raw.har.",
        examples=(
            "secondeye capture analyze ~/.local/state/secondeye/captures/2026-11-20_example-com/"
            "auth-flow",
            "# Re-group with a wider navigation window.",
            "secondeye capture analyze ./auth-flow --cluster-window 5000",
        ),
    )
    cap_analyze.add_argument(
        "directory",
        metavar="DIRECTORY",
        type=Path,
        help="A capture directory containing raw.har and manifest.json.",
    )
    cap_analyze.add_argument(
        "--cluster-window",
        metavar="MS",
        type=int,
        default=None,
        help="Clustering window in milliseconds for this re-render: how close a "
        "request must be to the preceding navigation to have its assets "
        f"summarized rather than listed. Default: {DEFAULT_CLUSTER_WINDOW_MS}.",
    )
    cap_analyze.set_defaults(handler=_cmd_capture_analyze)

    cap_recover = capture_verbs.add_parser(
        "recover",
        description="Rebuild a capture from the incremental JSONL buffer a "
        "crashed daemon left behind, writing the three output files that "
        "'capture stop' would have. No daemon required.",
        help="Rebuild a capture from a crashed daemon's leftover buffer.",
        examples=(
            "secondeye capture recover ./2026-11-20_example-com/auth-flow",
            f"secondeye capture recover ./auth-flow/{BUFFER_FILENAME} --keep-buffer",
        ),
    )
    cap_recover.add_argument(
        "path",
        metavar="PATH",
        type=Path,
        help=f"A capture directory containing a {BUFFER_FILENAME}, or that file itself.",
    )
    cap_recover.add_argument(
        "--name",
        metavar="LABEL",
        default=None,
        help="Capture name to record in the outputs. Default: the capture directory's own name.",
    )
    cap_recover.add_argument(
        "--keep-buffer",
        action="store_true",
        help="Leave the JSONL buffer in place instead of removing it once the "
        "capture has been written.",
    )
    cap_recover.add_argument(
        "--cluster-window",
        metavar="MS",
        type=int,
        default=DEFAULT_CLUSTER_WINDOW_MS,
        help=f"Clustering window in milliseconds. Default: {DEFAULT_CLUSTER_WINDOW_MS}.",
    )
    cap_recover.set_defaults(handler=_cmd_capture_recover)

    doctor = nouns.add_parser(
        "doctor",
        description="Check this machine is ready to capture: CA present and valid, "
        "state directory locked down, captures directory writable, listen port free, "
        "upstream reachable, certutil available, shell completion active. Changes "
        "nothing — in particular it never generates a CA. Exits non-zero if any "
        "check fails; warnings alone exit 0.",
        help="Check whether this machine is ready to capture, and say what isn't.",
        examples=(
            "secondeye doctor",
            "# Check the direct-connect setup rather than a Burp chain.",
            "secondeye doctor --no-upstream",
            "secondeye doctor --json",
        ),
    )
    doctor.add_argument(
        "--listen-address",
        metavar="HOST:PORT",
        default=_DEFAULT_LISTEN,
        help=f"The host:port to test for availability. Default: {_DEFAULT_LISTEN}.",
    )
    doctor.add_argument(
        "--upstream-proxy",
        metavar="HOST:PORT",
        default=_DEFAULT_UPSTREAM,
        help=f"The upstream proxy to test for reachability. Ignored with "
        f"--no-upstream. Default: {_DEFAULT_UPSTREAM}.",
    )
    doctor.add_argument(
        "--no-upstream",
        action="store_true",
        help="Check the direct-connection setup instead of an upstream proxy.",
    )
    doctor.add_argument(
        "--upstream-ca",
        metavar="FILE",
        type=Path,
        default=None,
        help="Check that this upstream CA file exists and is readable.",
    )
    doctor.add_argument(
        "--upstream-insecure",
        action="store_true",
        help="Check the setup that skips upstream TLS verification.",
    )
    doctor.add_argument(
        "--captures-dir",
        metavar="DIR",
        type=Path,
        default=None,
        help="Captures directory to test for writability. Default: <state-dir>/captures.",
    )
    doctor.add_argument(
        "--json",
        action="store_true",
        help="Emit the report as JSON on stdout instead of a table, for scripting.",
    )
    doctor.set_defaults(handler=_cmd_doctor)

    ca = nouns.add_parser(
        "ca",
        description="Manage secondeye's root CA and upstream trust. secondeye "
        "generates its own root CA on first use and signs a leaf per in-scope host; "
        "your browser has to trust that root before in-scope HTTPS will work.",
        help="Manage secondeye's root CA and upstream trust.",
        examples=(
            "secondeye ca install",
            "secondeye ca status",
            "secondeye ca import-upstream --from-burp",
        ),
    )
    ca_verbs = ca.add_subparsers(dest="verb", required=True, metavar="VERB")

    ca_export = ca_verbs.add_parser(
        "export",
        description="Export secondeye's root CA for import into a browser/device "
        "trust store. The certificate goes to stdout, so redirect it to a file. "
        "Generates the CA if this is the first run.",
        help="Export secondeye's root CA to stdout.",
        examples=(
            "secondeye ca export > secondeye-ca.pem",
            "secondeye ca export --format der > secondeye-ca.der",
        ),
    )
    ca_export.add_argument(
        "--format",
        metavar="ENCODING",
        choices=["der", "pem"],
        default="pem",
        help="Output encoding, written to stdout: der or pem. Default: pem.",
    )
    ca_export.set_defaults(handler=_cmd_ca_export)

    ca_install = ca_verbs.add_parser(
        "install",
        description="Install secondeye's CA into the local NSS trust stores "
        "(Firefox, Chromium, and the shared ~/.pki/nssdb) using certutil, then "
        "print the two commands to trust it system-wide. The system store needs "
        "sudo and is never written automatically — you should see the command "
        "that touches your root trust before it runs.",
        help="Trust secondeye's CA in Firefox/Chromium, and print system-store steps.",
        examples=(
            "secondeye ca install",
            "# See what would change, without changing it.",
            "secondeye ca install --dry-run",
            "secondeye ca install --remove",
        ),
    )
    ca_install.add_argument(
        "--remove",
        action="store_true",
        help="Remove secondeye's CA from the NSS trust stores instead of adding it.",
    )
    ca_install.add_argument(
        "--print-only",
        action="store_true",
        help="Change nothing: just print the manual steps, including the "
        "system-store commands. Useful when certutil isn't installed.",
    )
    ca_install.add_argument(
        "--dry-run",
        action="store_true",
        help="List the trust stores that would be modified, without touching them.",
    )
    ca_install.add_argument(
        "--home",
        type=Path,
        default=None,
        help=argparse.SUPPRESS,  # test seam: search a throwaway home instead
    )
    ca_install.set_defaults(handler=_cmd_ca_install)

    ca_verbs.add_parser(
        "status",
        description="Report the persisted CA's fingerprint and validity. Read-only: "
        "unlike 'ca export' and 'proxy start', this never generates a CA as a side "
        "effect of being run.",
        help="Report the persisted CA's fingerprint and validity.",
        examples=("secondeye ca status",),
    ).set_defaults(handler=_cmd_ca_status)

    ca_import = ca_verbs.add_parser(
        "import-upstream",
        description="Fetch an upstream intercepting proxy's CA certificate for use "
        "with 'proxy start --upstream-ca'. Requires the upstream proxy to be running.",
        help="Fetch an upstream proxy's CA certificate for --upstream-ca.",
        examples=(
            "secondeye ca import-upstream --from-burp",
            "secondeye ca import-upstream --from-burp --upstream-proxy 127.0.0.1:8081 \\",
            "    --output ~/engagements/acme/burp-ca.pem",
        ),
    )
    ca_import.add_argument(
        "--from-burp",
        action="store_true",
        required=True,
        help="Fetch the CA from Burp Suite's well-known /cert export endpoint. "
        "Currently the only supported source; required.",
    )
    ca_import.add_argument(
        "--upstream-proxy",
        metavar="HOST:PORT",
        default=_DEFAULT_UPSTREAM,
        help=f"The upstream proxy's host:port to fetch the CA from. Default: {_DEFAULT_UPSTREAM}.",
    )
    ca_import.add_argument(
        "--output",
        metavar="FILE",
        type=Path,
        default=Path("burp-ca.pem"),
        help="Where to write the converted PEM certificate. Default: burp-ca.pem.",
    )
    ca_import.set_defaults(handler=_cmd_ca_import_upstream)

    return parser


# --------------------------------------------------------------------------
# proxy start/stop/status
# --------------------------------------------------------------------------


def _cmd_proxy_start(args: argparse.Namespace) -> int:
    _configure_logging(args)
    listen_host, listen_port = _parse_host_port(args.listen_address, _DEFAULT_LISTEN_PORT)

    if args.no_upstream:
        upstream_host: str | None = None
        upstream_port: int | None = None
    else:
        upstream_host, upstream_port = _parse_host_port(args.upstream_proxy, _DEFAULT_UPSTREAM_PORT)

    targets = list(args.target)
    for target_file in args.target_file:
        targets.extend(_read_target_file(target_file))

    config = DaemonConfig(
        listen_host=listen_host,
        listen_port=listen_port,
        targets=targets,
        target_regex=args.target_regex,
        upstream_host=upstream_host,
        upstream_port=upstream_port,
        no_upstream=args.no_upstream,
        upstream_ca=args.upstream_ca,
        upstream_insecure=args.upstream_insecure,
        target_all=args.target_all,
        cluster_window_ms=args.cluster_window,
        max_connections=args.max_connections,
        state_dir=default_state_dir(),
        captures_dir=args.captures_dir,
    )
    daemon = Daemon(config)
    asyncio.run(daemon.run(on_started=lambda: _print_startup_banner(daemon, config)))
    return 0


def _print_startup_banner(daemon: Daemon, config: DaemonConfig) -> None:
    ui.startup_banner(
        StartupView(
            version=_VERSION,
            listen=f"{config.listen_host}:{daemon.listener_bound_port}",
            scope=ScopeView(
                targets=tuple(config.targets),
                target_regex=tuple(config.target_regex),
                target_all=config.target_all,
            ),
            upstream=(
                None if config.no_upstream else f"{config.upstream_host}:{config.upstream_port}"
            ),
            captures_dir=str(config.captures_dir or config.state_dir / "captures"),
            ca_was_created=daemon.ca_was_created,
        )
    )
    sys.stdout.flush()


def _cmd_proxy_stop(_args: argparse.Namespace) -> int:
    try:
        response = asyncio.run(send_request(_control_socket_path(), "proxy.stop"))
    except ControlSocketUnavailableError:
        ui.error("No running secondeye daemon found.")
        return 1
    if not response.get("ok"):
        ui.error(_error_message(response))
        return 1
    ui.success("secondeye daemon stopping.")
    return 0


def _cmd_proxy_status(args: argparse.Namespace) -> int:
    try:
        response = asyncio.run(send_request(_control_socket_path(), "proxy.status"))
    except ControlSocketUnavailableError:
        # Not an error: "is it running?" was answered, and the answer is no.
        if args.json:
            _emit_json({"running": False})
        else:
            ui.daemon_not_running()
        return 0
    if not response.get("ok"):
        ui.error(_error_message(response))
        return 1

    result = response["result"]
    assert isinstance(result, dict)
    scope = result["scope"]
    assert isinstance(scope, dict)

    active_raw = result["active_capture"]
    active: ActiveCaptureView | None = None
    if active_raw is not None:
        assert isinstance(active_raw, dict)
        active = ActiveCaptureView(
            name=str(active_raw["name"]),
            started_at=_format_local_time(str(active_raw["started_at"])),
            request_count=int(str(active_raw["request_count"])),
        )

    if args.json:
        _emit_json(
            {
                "running": True,
                "version": _VERSION,
                "listen": str(result["listen"]),
                "scope": scope,
                "active_capture": active_raw,
            }
        )
        return 0

    ui.proxy_status(
        StatusView(
            version=_VERSION,
            listen=str(result["listen"]),
            scope=_scope_view(scope),
            upstream=None if scope["no_upstream"] else str(scope["upstream"]),
            active=active,
        )
    )
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
        ui.error(
            "Cannot start capture: no running secondeye daemon found.",
            "Run 'secondeye proxy start --target <domain>' first.",
        )
        return 1

    if not response.get("ok"):
        error = response["error"]
        assert isinstance(error, dict)
        error_type = error.get("type")
        if error_type == "CaptureAlreadyActiveError":
            started_at = _format_local_time(str(error["started_at"]))
            ui.error(
                f"Cannot start capture: a capture is already active "
                f"({error['name']!r}, started {started_at}).",
                "Run 'secondeye capture stop' first.",
            )
        elif error_type == "CaptureNameConflictError":
            ui.error(
                f"Cannot start capture: a capture named {error['name']!r} "
                "already exists for today.",
                f"Pick a different name or remove {error['output_dir']}.",
            )
        else:
            ui.error(f"Cannot start capture: {error['message']}")
        return 1

    result = response["result"]
    assert isinstance(result, dict)
    scope = result["scope"]
    assert isinstance(scope, dict)

    ui.capture_started(
        CaptureStartedView(
            name=str(result["name"]),
            started_at=_format_utc_time(str(result["started_at"])),
            output_dir=f"{result['output_dir']}/",
            scope=_scope_view(scope),
        )
    )
    return 0


def _cmd_capture_stop(_args: argparse.Namespace) -> int:
    try:
        response = asyncio.run(send_request(_control_socket_path(), "capture.stop"))
    except ControlSocketUnavailableError:
        ui.error("Cannot stop capture: no running secondeye daemon found.")
        return 1

    if not response.get("ok"):
        ui.error(f"Cannot stop capture: {_error_message(response)}")
        return 1

    result = response["result"]
    assert isinstance(result, dict)
    output_dir = result.get("output_dir")
    ui.capture_stopped(
        CaptureStoppedView(
            name=str(result["name"]),
            request_count=int(str(result["request_count"])),
            total_bytes=int(str(result["total_bytes"])),
            output_dir=None if output_dir is None else str(output_dir),
            flow_count=int(str(result.get("flow_count") or 0)),
            finding_count=int(str(result.get("finding_count") or 0)),
        )
    )
    return 0


def _cmd_capture_list(args: argparse.Namespace) -> int:
    """List captures from disk rather than from a daemon's memory.

    Previously this asked the running daemon for its in-process history,
    so it required a live daemon and could not see any capture from an
    earlier run. Reading the captures directory answers the question the
    operator is actually asking — "what have I recorded?" — and keeps
    working after the daemon exits.
    """
    captures_dir = args.captures_dir or (default_state_dir() / "captures")
    summaries = discover_captures(captures_dir)
    if args.json:
        _emit_json(
            {
                "captures_dir": str(captures_dir),
                "captures": [
                    {
                        "name": summary.name,
                        "output_dir": str(summary.output_dir),
                        "started_at": (
                            None if summary.started_at is None else summary.started_at.isoformat()
                        ),
                        "target": summary.target,
                        "request_count": summary.request_count,
                        "total_bytes": summary.total_bytes,
                        "flow_count": summary.flow_count,
                        "finding_count": summary.finding_count,
                    }
                    for summary in summaries
                ],
            }
        )
        return 0
    if not summaries:
        ui.plain(f"No captures found in {captures_dir}")
        return 0

    active_name = _active_capture_name()
    ui.capture_list(
        [
            CaptureRow(
                name=summary.name,
                request_count=summary.request_count,
                total_bytes=summary.total_bytes,
                output_dir=str(summary.output_dir),
                target=summary.target,
                flow_count=summary.flow_count,
                finding_count=summary.finding_count,
                started_at=(
                    "" if summary.started_at is None else _format_capture_time(summary.started_at)
                ),
                active=summary.name == active_name,
            )
            for summary in summaries
        ],
        captures_dir=str(captures_dir),
    )
    return 0


def _active_capture_name() -> str | None:
    """Name of the in-progress capture, if a daemon happens to be running.

    Best-effort decoration for ``capture list``: the listing is built
    from disk and must not depend on a daemon, so any failure to reach
    one simply means nothing is marked active.
    """
    try:
        response = asyncio.run(send_request(_control_socket_path(), "proxy.status"))
    except ControlSocketUnavailableError:
        return None
    if not response.get("ok"):
        return None
    result = response.get("result")
    if not isinstance(result, dict):
        return None
    active = result.get("active_capture")
    if not isinstance(active, dict):
        return None
    return str(active["name"])


def _cmd_capture_analyze(args: argparse.Namespace) -> int:
    """Re-render an existing capture's manifest.json and ANALYSIS.md."""
    loaded = load_capture(args.directory)
    metadata = loaded.metadata
    if args.cluster_window is not None:
        metadata = replace(metadata, cluster_window_ms=args.cluster_window)
    outputs = write_capture_outputs(loaded.output_dir, loaded.entries, metadata)
    ui.capture_analyzed(
        CaptureStoppedView(
            name=metadata.name,
            request_count=outputs.request_count,
            total_bytes=outputs.total_bytes,
            flow_count=outputs.flow_count,
            finding_count=outputs.findings.total,
            output_dir=str(outputs.output_dir),
        )
    )
    return 0


def _cmd_capture_recover(args: argparse.Namespace) -> int:
    """Rebuild a capture from a crashed daemon's leftover JSONL buffer."""
    buffer_path = find_buffer(args.path)
    output_dir = buffer_path.parent
    entries = read_buffer(buffer_path)
    if not entries:
        ui.error(f"{buffer_path} contains no complete entries — nothing to recover.")
        return 1

    # A buffer records entries only: it carries no scope configuration and
    # no capture window. Those are left empty rather than inferred, so the
    # recovered manifest never claims provenance it doesn't have. The
    # timestamps come from the entries themselves, which is real data.
    started_at = min(entry.started_at for entry in entries)
    ended_at = max(entry.started_at for entry in entries)
    metadata = CaptureMetadata(
        name=args.name or output_dir.name,
        started_at=started_at,
        ended_at=ended_at,
        targets=[],
        cluster_window_ms=args.cluster_window,
    )
    outputs = write_capture_outputs(output_dir, entries, metadata)
    if not args.keep_buffer:
        buffer_path.unlink(missing_ok=True)
    ui.capture_recovered(
        CaptureStoppedView(
            name=metadata.name,
            request_count=outputs.request_count,
            total_bytes=outputs.total_bytes,
            flow_count=outputs.flow_count,
            finding_count=outputs.findings.total,
            output_dir=str(outputs.output_dir),
        )
    )
    return 0


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------


def _cmd_doctor(args: argparse.Namespace) -> int:
    """Report whether this machine is ready to capture.

    Returns:
        1 if any check failed, otherwise 0 — warnings alone are not a
        failure, since a missing CA is created on the next ``proxy
        start`` rather than being a blocker.
    """
    state_dir = default_state_dir()
    listen_host, listen_port = _parse_host_port(args.listen_address, _DEFAULT_LISTEN_PORT)
    upstream: tuple[str, int] | None = None
    if not args.no_upstream:
        upstream = _parse_host_port(args.upstream_proxy, _DEFAULT_UPSTREAM_PORT)

    report = run_checks(
        state_dir=state_dir,
        captures_dir=args.captures_dir or (state_dir / "captures"),
        listen_host=listen_host,
        listen_port=listen_port,
        upstream=upstream,
        upstream_ca=args.upstream_ca,
        upstream_insecure=args.upstream_insecure,
    )
    if args.json:
        _emit_json(
            {
                "version": report.version,
                "ready": not report.failed,
                "checks": [
                    {
                        "name": check.name,
                        "status": check.status.value,
                        "detail": check.detail,
                        "hint": check.hint,
                    }
                    for check in report.checks
                ],
            }
        )
    else:
        ui.doctor_report(report)
    return 1 if report.failed else 0


# --------------------------------------------------------------------------
# ca export/import-upstream
# --------------------------------------------------------------------------


def _cmd_ca_export(args: argparse.Namespace) -> int:
    ca = load_or_create_ca(default_state_dir())
    if ca.created:
        # stderr only: stdout carries the raw cert bytes for redirection
        # (`secondeye ca export ... > secondeye-ca.der`), so nothing human
        # may ever be written to stdout on this path.
        ui.warn(f"Generated a new secondeye CA (first run) at {ca.cert_path}.")
    encoding = serialization.Encoding.DER if args.format == "der" else serialization.Encoding.PEM
    sys.stdout.buffer.write(ca.certificate.public_bytes(encoding))
    return 0


def _cmd_ca_install(args: argparse.Namespace) -> int:
    """Trust secondeye's CA locally, and print the system-store steps.

    Read-only with respect to the CA itself: unlike every other
    CA-touching command except ``ca status``, this never generates one,
    because "install the CA you don't have yet" is a confusing thing to
    do silently.
    """
    state_dir = default_state_dir()
    if not ca_exists(state_dir):
        ui.error(
            "No CA to install yet.",
            "Run 'secondeye proxy start ...' (or 'secondeye ca export') to create one.",
        )
        return 1
    pem_path = state_dir / "ca" / "secondeye-ca.pem"

    profiles = discover_nss_profiles(home=args.home)
    if args.print_only:
        ui.ca_install_manual(
            str(pem_path),
            [
                (profile.label, shlex.join(build_install_command(profile, pem_path)))
                for profile in profiles
            ],
            system_store_instructions(pem_path),
        )
        return 0

    results: list[tuple[str, bool]] = []
    if profiles:
        for profile in profiles:
            if args.dry_run:
                results.append((profile.label, True))
                continue
            if args.remove:
                results.append((profile.label, remove_from_profile(profile)))
            else:
                install_into_profile(profile, pem_path)
                results.append((profile.label, True))

    ui.ca_install_result(
        results,
        removing=args.remove,
        dry_run=args.dry_run,
        system_instructions=None if args.remove else system_store_instructions(pem_path),
    )
    return 0


def _cmd_ca_status(_args: argparse.Namespace) -> int:
    state_dir = default_state_dir()
    if not ca_exists(state_dir):
        ui.plain(
            "No CA generated yet. Run 'secondeye ca export' or 'secondeye proxy start' "
            "to generate one."
        )
        return 0

    ca = load_or_create_ca(state_dir)  # safe: existence just confirmed, won't generate
    cert = ca.certificate
    fingerprint = cert.fingerprint(hashes.SHA256())
    fingerprint_hex = ":".join(f"{b:02X}" for b in fingerprint)
    subject_cn_value = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    subject_cn = (
        subject_cn_value if isinstance(subject_cn_value, str) else subject_cn_value.decode()
    )
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    now = datetime.datetime.now(datetime.UTC)
    expired = now > not_after

    ui.ca_status(
        CaStatusView(
            cert_path=str(ca.cert_path),
            subject=subject_cn,
            serial=cert.serial_number,
            fingerprint=fingerprint_hex,
            valid_from=not_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
            valid_until=not_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
            expired=expired,
            days=(now - not_after).days if expired else (not_after - now).days,
        )
    )
    return 0


def _cmd_ca_import_upstream(args: argparse.Namespace) -> int:
    host, port = _parse_host_port(args.upstream_proxy, _DEFAULT_UPSTREAM_PORT)
    der_bytes = asyncio.run(_fetch_upstream_cert(host, port))
    certificate = x509.load_der_x509_certificate(der_bytes)
    pem_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    args.output.write_bytes(pem_bytes)
    ui.success(
        f"Saved upstream CA to {args.output}",
        f"Use with: secondeye proxy start --upstream-ca {args.output} ...",
    )
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


def _read_target_file(path: Path) -> list[str]:
    """Parse a --target-file into a list of --target-style entries.

    One target per line (same syntax --target itself accepts, per SPEC.md
    §3.1/§3.2 — no separate matching logic needed). Blank lines and lines
    starting with # are ignored.

    Raises:
        ConfigError: If the file can't be read.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"failed to read --target-file {path}: {exc}") from exc
    return [
        stripped
        for line in text.splitlines()
        if (stripped := line.strip()) and not stripped.startswith("#")
    ]


def _parse_host_port(value: str, default_port: int) -> tuple[str, int]:
    if value.startswith("["):
        host, _, rest = value[1:].partition("]")
        port_str = rest.lstrip(":") or str(default_port)
        return host, int(port_str)
    host, sep, port_str = value.rpartition(":")
    if not sep:
        return value, default_port
    return host, int(port_str)


def _emit_json(payload: dict[str, object]) -> None:
    """Write a machine-readable payload to stdout.

    Deliberately bypasses ui.py: that renders for humans, and a Console
    would be entitled to style or wrap this. JSON output has to stay
    byte-exact regardless of whether stdout looks like a terminal.

    Args:
        payload: JSON-serializable data.
    """
    print(json.dumps(payload, indent=2))


def _scope_view(scope: dict[str, object]) -> ScopeView:
    """Adapt a control-socket scope block into a renderable view.

    Args:
        scope: The ``scope`` object from a ``proxy.status`` or
            ``capture.start`` response.

    Returns:
        The equivalent ScopeView.
    """
    targets = scope.get("targets") or []
    assert isinstance(targets, list)
    target_regex = scope.get("target_regex") or []
    assert isinstance(target_regex, list)
    return ScopeView(
        targets=tuple(str(t) for t in targets),
        target_regex=tuple(str(t) for t in target_regex),
        target_all=bool(scope.get("target_all")),
    )


def _format_utc_time(iso_value: str) -> str:
    dt = datetime.datetime.fromisoformat(iso_value.replace("Z", "+00:00"))
    return dt.astimezone(datetime.UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _format_capture_time(value: datetime.datetime) -> str:
    """Format a capture's start for the ``capture list`` table.

    Args:
        value: The capture's start time.

    Returns:
        ``"YYYY-MM-DD HH:MM"`` in UTC.
    """
    return value.astimezone(datetime.UTC).strftime("%Y-%m-%d %H:%M")


def _format_local_time(iso_value: str) -> str:
    dt = datetime.datetime.fromisoformat(iso_value.replace("Z", "+00:00"))
    return dt.astimezone(datetime.UTC).strftime("%H:%M:%S")


def _error_message(response: dict[str, object]) -> str:
    error = response.get("error")
    if isinstance(error, dict) and "message" in error:
        return str(error["message"])
    return "unknown error"


if __name__ == "__main__":
    sys.exit(main())
