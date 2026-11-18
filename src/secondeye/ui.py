"""Terminal presentation layer, built on ``rich`` (SPEC.md §7).

Every byte secondeye writes for a human goes through this module, so
there is exactly one place that decides what the program looks like.
cli.py stays argparse plumbing plus control-socket calls; it builds a
view dataclass and hands it here.

**Colour policy — light terminals first.** Only the 16 ANSI colours and
the ``bold``/``dim`` attributes are used. Those are resolved by the
user's own terminal theme against the user's own background, so the
output reads on a light terminal (the primary target) and a dark one
alike. Absolute values — 256-colour ``greyNN``, truecolor hex, or a
literal ``white``/``black`` — silently assume a background and become
unreadable on the opposite theme; ``bold white`` in particular
disappears on a light terminal. Two mechanisms keep that honest:
``color_system="standard"`` downgrades anything richer to the 16-colour
palette, and ``highlight=False`` stops rich's automatic highlighter from
injecting absolute colours of its own into numbers and paths.
tests/test_ui.py asserts both structurally.

**Stream policy.** Human output goes to stdout, diagnostics to stderr,
matching SPEC.md §7's rule that stdout stays clean for scriptable use.
``secondeye ca export`` is the one surface that must not come through
here at all: it writes raw certificate bytes to ``sys.stdout.buffer``,
and a Console attached to that stream would corrupt them.

**Separation for ``--json``.** Render functions take a fully-resolved
view dataclass and only format it; nothing here computes what to show.
A future ``--json`` flag serialises the same dataclass instead of
rendering it, rather than re-deriving the data.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import TextIO

from rich.box import SIMPLE_HEAD
from rich.console import Console, Group
from rich.table import Table
from rich.text import Text

__all__ = [
    "ActiveCaptureView",
    "CaStatusView",
    "CaptureRow",
    "CaptureStartedView",
    "CaptureStoppedView",
    "ScopeView",
    "StartupView",
    "StatusView",
    "Ui",
    "format_bytes",
    "ui",
]

# Style names only; never literal colour values. See the module docstring.
_LABEL = "dim"
_ACCENT = "cyan"
_REGEX = "magenta"
_OK = "green"
_WARN = "yellow"
_ERR = "red"

_LABEL_WIDTH = 10
_INDENT = 2


def format_bytes(n: int) -> str:
    """Render a byte count in the most readable unit.

    Args:
        n: A number of bytes.

    Returns:
        e.g. ``"500B"``, ``"4.2KB"``, ``"4.2MB"``.
    """
    if n < 1024:
        return f"{n}B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f}KB"
    return f"{n / (1024 * 1024):.1f}MB"


# --------------------------------------------------------------------------
# View dataclasses — what to show, resolved by the caller
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ScopeView:
    """A daemon run's configured scope (SPEC.md §3).

    Attributes:
        targets: --target/--target-file values.
        target_regex: --target-regex values.
        target_all: Whether --target-all bypassed scope matching.
    """

    targets: tuple[str, ...]
    target_regex: tuple[str, ...] = ()
    target_all: bool = False

    def summary(self) -> str:
        """One-line form, for surfaces too narrow for the full list.

        Returns:
            Comma-joined targets and regexes, ``"(none)"`` if neither,
            with a ``[--target-all]`` marker appended when set.
        """
        parts = [*self.targets, *self.target_regex]
        summary = ", ".join(parts) if parts else "(none)"
        if self.target_all:
            summary = "(none) [--target-all]" if not parts else f"{summary} [--target-all]"
        return summary


@dataclass(frozen=True)
class StartupView:
    """What ``proxy start`` reports once both sockets are bound.

    Attributes:
        version: The running secondeye version.
        listen: Bound ``host:port`` of the proxy listener.
        scope: Configured scope.
        upstream: Upstream ``host:port``, or None for --no-upstream.
        captures_dir: Where captures will be written.
        ca_was_created: Whether this run generated a brand-new CA.
    """

    version: str
    listen: str
    scope: ScopeView
    upstream: str | None
    captures_dir: str
    ca_was_created: bool = False


@dataclass(frozen=True)
class ActiveCaptureView:
    """The in-progress capture, as ``proxy status`` sees it.

    Attributes:
        name: The capture's --name label.
        started_at: Pre-formatted local start time.
        request_count: Requests recorded so far.
    """

    name: str
    started_at: str
    request_count: int


@dataclass(frozen=True)
class StatusView:
    """A full ``proxy status`` answer.

    Attributes:
        version: The running secondeye version.
        listen: Bound ``host:port``.
        scope: Configured scope.
        upstream: Upstream ``host:port``, or None for --no-upstream.
        active: The active capture, or None when idle.
    """

    version: str
    listen: str
    scope: ScopeView
    upstream: str | None
    active: ActiveCaptureView | None


@dataclass(frozen=True)
class CaptureStartedView:
    """Confirmation that recording has begun.

    Attributes:
        name: The capture's --name label.
        started_at: Pre-formatted UTC start time.
        output_dir: Where outputs will land on stop.
        scope: Configured scope.
    """

    name: str
    started_at: str
    output_dir: str
    scope: ScopeView


@dataclass(frozen=True)
class CaptureStoppedView:
    """Summary of a completed capture.

    Attributes:
        name: The capture's --name label.
        request_count: Requests recorded.
        total_bytes: Request+response body bytes recorded.
        output_dir: Where the three output files were written.
    """

    name: str
    request_count: int
    total_bytes: int
    output_dir: str | None = None


@dataclass(frozen=True)
class CaptureRow:
    """One row of ``capture list``.

    Attributes:
        name: The capture's --name label.
        request_count: Requests recorded.
        total_bytes: Request+response body bytes recorded.
        output_dir: Where its outputs live.
    """

    name: str
    request_count: int
    total_bytes: int
    output_dir: str


@dataclass(frozen=True)
class CaStatusView:
    """The persisted root CA's identity and validity.

    Attributes:
        cert_path: Path to the PEM certificate.
        subject: The certificate's subject common name.
        serial: Its serial number.
        fingerprint: Colon-separated SHA-256 fingerprint.
        valid_from: Pre-formatted notBefore.
        valid_until: Pre-formatted notAfter.
        expired: Whether notAfter is in the past.
        days: Days remaining, or days elapsed since expiry when expired.
    """

    cert_path: str
    subject: str
    serial: int
    fingerprint: str
    valid_from: str
    valid_until: str
    expired: bool
    days: int


# --------------------------------------------------------------------------
# Renderer
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Ui:
    """Renders secondeye's terminal output to a pair of streams.

    Attributes:
        stdout: Stream for human output; None means "whatever
            ``sys.stdout`` is at print time".
        stderr: Stream for diagnostics; None means "whatever
            ``sys.stderr`` is at print time".
        force_color: Emit ANSI even when the stream isn't a tty (used by
            the documentation generator). ``NO_COLOR`` still wins.
    """

    stdout: TextIO | None = None
    stderr: TextIO | None = None
    force_color: bool = False

    @property
    def _out(self) -> Console:
        return self._console(self.stdout, to_stderr=False)

    @property
    def _err(self) -> Console:
        return self._console(self.stderr, to_stderr=True)

    def _console(self, stream: TextIO | None, *, to_stderr: bool) -> Console:
        """Build a Console for one stream.

        Deliberately built per call rather than once at construction.
        ``ui`` below is a process-wide singleton created at import time,
        and a Console that captured ``sys.stdout``/``sys.stderr`` back
        then would keep writing to the original objects — writing past
        any later reassignment of those streams, which silently defeats
        both output redirection and pytest's capsys. Leaving ``file`` as
        None lets rich resolve the stream at print time, and rebuilding
        here re-evaluates the tty check against the stream in force now.

        Args:
            stream: An explicit stream, or None to track sys.stdout/stderr.
            to_stderr: Which standard stream None refers to.

        Returns:
            A configured Console.
        """
        target = stream if stream is not None else (sys.stderr if to_stderr else sys.stdout)
        colour = self._want_colour(target)
        return Console(
            file=stream,
            stderr=to_stderr,
            # 16 ANSI colours only: anything richer would be an absolute
            # value that assumes a background (see the module docstring).
            # Passing an explicit color_system also *overrides* rich's own
            # terminal detection, so it must be None whenever colour is
            # unwanted -- otherwise a redirected stream still gets ANSI.
            color_system="standard" if colour else None,
            # rich's automatic highlighter colours numbers, paths and
            # quoted strings using absolute colours from its own theme.
            highlight=False,
            emoji=False,
            force_terminal=True if colour else None,
            # Let the terminal wrap long values, the way plain print() did.
            # rich's own word-wrap inserts a trailing space at each wrap
            # point and gives continuation lines no alignment, which looks
            # worse than a soft wrap for paths, regexes and fingerprints.
            soft_wrap=True,
        )

    def _want_colour(self, stream: TextIO) -> bool:
        """Decide whether to style output for one stream.

        A tty, unless ``NO_COLOR`` is set or ``TERM=dumb``. Both
        ``FORCE_COLOR`` and the ``force_color`` attribute override the
        tty requirement, so styling survives a pipe; ``NO_COLOR`` beats
        both, as no-color.org specifies.

        ``NO_COLOR`` counts only when non-empty, again per that spec.
        That matters concretely: scripts/generate_doc_examples.py sets
        ``NO_COLOR=""`` next to ``FORCE_COLOR=1`` and relies on the
        empty value meaning "unset".

        Args:
            stream: The stream a Console will write to.

        Returns:
            True if ANSI styling should be emitted.
        """
        if os.environ.get("NO_COLOR"):
            return False
        if os.environ.get("TERM") == "dumb":
            return False
        if self.force_color or os.environ.get("FORCE_COLOR"):
            return True
        try:
            return bool(stream.isatty())
        except (AttributeError, ValueError):
            # ValueError: stream already closed. Either way, assume not a tty.
            return False

    # -- primitives --------------------------------------------------------

    def success(self, message: str, *details: str) -> None:
        """Print a ✓-prefixed confirmation to stdout.

        Args:
            message: The headline.
            details: Optional indented follow-up lines.
        """
        self._out.print(Text.assemble(("✓ ", f"bold {_OK}"), message))
        for detail in details:
            self._out.print(Text("  " + detail, style=_LABEL))

    def error(self, message: str, *details: str) -> None:
        """Print a ✗-prefixed failure to stderr.

        Args:
            message: The headline.
            details: Optional indented follow-up lines, e.g. what to run next.
        """
        self._err.print(Text.assemble(("✗ ", f"bold {_ERR}"), message))
        for detail in details:
            self._err.print(Text("  " + detail, style=_LABEL))

    def warn(self, message: str, *details: str) -> None:
        """Print a ⚠-prefixed warning to stderr.

        Args:
            message: The headline.
            details: Optional indented follow-up lines.
        """
        self._warn_on(self._err, message, *details)

    def _warn_on(self, console: Console, message: str, *details: str) -> None:
        """Print a ⚠-prefixed warning to a specific stream.

        Most warnings are diagnostics and belong on stderr. The
        first-run CA note is the exception: it is part of the ``proxy
        start`` banner the operator is reading on stdout, and splitting
        it onto stderr would reorder it against the banner when either
        stream is redirected.
        """
        console.print(Text.assemble(("⚠ ", f"bold {_WARN}"), message))
        for detail in details:
            console.print(Text("  " + detail, style=_LABEL))

    def plain(self, message: str) -> None:
        """Print an unadorned line to stdout.

        Args:
            message: The text to print.
        """
        self._out.print(Text(message))

    def blank(self) -> None:
        """Print an empty line to stdout."""
        self._out.print()

    # -- composed surfaces -------------------------------------------------

    def startup_banner(self, view: StartupView) -> None:
        """Print the ``proxy start`` banner once both sockets are bound.

        Args:
            view: The resolved startup facts.
        """
        self._header(view.version, Text.assemble(("listening ", _LABEL), (view.listen, _ACCENT)))
        self._out.print()
        self._out.print(
            _kv(
                [
                    ("scope", _scope_block(view.scope)),
                    ("upstream", _upstream_text(view.upstream)),
                    ("captures", Text(view.captures_dir, style=_LABEL)),
                ]
            )
        )
        self._out.print()
        self._out.print(
            Text.assemble(
                ("  Point your client's proxy at ", _LABEL),
                (view.listen, _ACCENT),
                (", then:", _LABEL),
            )
        )
        self._out.print(Text("    secondeye capture start --name <label>", style="bold"))
        if view.ca_was_created:
            self._out.print()
            self._warn_on(
                self._out,
                "Generated a new secondeye CA (first run).",
                "Your client won't trust in-scope HTTPS until you import it:",
                "run 'secondeye ca export' and see the README for trust-store setup.",
            )

    def proxy_status(self, view: StatusView) -> None:
        """Print a ``proxy status`` answer for a running daemon.

        Args:
            view: The resolved status facts.
        """
        self._header(
            view.version,
            Text.assemble(
                ("running", f"bold {_OK}"),
                "   ",
                (view.listen, _ACCENT),
                ("  →  ", _LABEL),
                _upstream_text(view.upstream),
            ),
        )
        self._out.print()
        if view.active is None:
            capture = Text("○ idle — nothing is being recorded", style=_LABEL)
        else:
            capture = Text.assemble(
                ("● ", f"bold {_OK}"),
                (view.active.name, "bold"),
                "   ",
                (str(view.active.request_count), "bold"),
                (" requests", _LABEL),
                # One segment, not "since " plus the time: a style change
                # between them would inject an escape sequence into the
                # middle of the phrase, which defeats any consumer
                # matching on it (scripts/generate_doc_examples.py masks
                # this timestamp to keep the committed docs stable).
                (f"   since {view.active.started_at}", _LABEL),
            )
        self._out.print(_kv([("scope", _scope_block(view.scope)), ("capture", capture)]))

    def daemon_not_running(self) -> None:
        """Report, on stdout, that no daemon is up.

        ``proxy status`` answering "no" is a successful answer to a
        question, not an error, so it stays on stdout and exits 0.
        """
        self._out.print(
            Text.assemble(("▌ ", f"bold {_ERR}"), ("secondeye", "bold"), ("   not running", _LABEL))
        )

    def capture_started(self, view: CaptureStartedView) -> None:
        """Confirm that recording has begun.

        Args:
            view: The resolved capture-start facts.
        """
        self._out.print(Text.assemble(("● ", f"bold {_OK}"), ("Recording", "bold"), " ", view.name))
        self._out.print()
        self._out.print(
            _kv(
                [
                    ("started", Text(view.started_at, style=_LABEL)),
                    ("output", Text(view.output_dir, style=_LABEL)),
                    ("scope", _scope_block(view.scope)),
                ]
            )
        )
        self._out.print()
        self._out.print(Text.assemble(("  Stop with ", _LABEL), ("secondeye capture stop", "bold")))

    def capture_stopped(self, view: CaptureStoppedView) -> None:
        """Summarise a completed capture and point at its outputs.

        Args:
            view: The resolved capture-stop facts.
        """
        self._out.print(Text.assemble(("✓ ", f"bold {_OK}"), ("Stopped", "bold"), " ", view.name))
        self._out.print()
        rows: list[tuple[str, Text]] = [
            (
                "recorded",
                Text.assemble(
                    (str(view.request_count), "bold"),
                    (" requests   ", _LABEL),
                    (format_bytes(view.total_bytes), "bold"),
                ),
            ),
            (
                "analysis",
                Text.assemble(("ANALYSIS.md", "bold"), ("   → hand to your AI chat", _LABEL)),
            ),
            ("also", Text("raw.har · manifest.json", style=_LABEL)),
        ]
        if view.output_dir is not None:
            rows.append(("output", Text(view.output_dir, style=_LABEL)))
        self._out.print(_kv(rows))

    def capture_list(self, rows: list[CaptureRow]) -> None:
        """Print one row per completed capture as a table.

        Args:
            rows: The captures to list, in display order.
        """
        table = Table(
            box=SIMPLE_HEAD,
            header_style="bold",
            border_style=_LABEL,
            expand=False,
            pad_edge=False,
            show_edge=False,
            padding=(0, 2),
        )
        table.add_column("CAPTURE", style="bold", no_wrap=True)
        table.add_column("REQS", justify="right", style=_ACCENT)
        table.add_column("SIZE", justify="right")
        # fold, not rich's default ellipsis truncation: a half-printed
        # capture path can't be copied or cd'd into.
        table.add_column("OUTPUT", style=_LABEL, overflow="fold")
        for row in rows:
            table.add_row(
                row.name, str(row.request_count), format_bytes(row.total_bytes), row.output_dir
            )
        self._out.print(table)

    def ca_status(self, view: CaStatusView) -> None:
        """Print the persisted CA's identity and validity.

        Args:
            view: The resolved CA facts.
        """
        if view.expired:
            validity = Text.assemble(
                view.valid_until, "  ", (f"EXPIRED {view.days} days ago", f"bold {_WARN}")
            )
        else:
            validity = Text.assemble(
                view.valid_until, ("  ", _LABEL), (f"{view.days} days remaining", _LABEL)
            )
        self._out.print(
            _kv(
                [
                    ("path", Text(view.cert_path, style=_LABEL)),
                    ("subject", Text(view.subject)),
                    ("serial", Text(str(view.serial), style=_LABEL)),
                    ("sha256", Text(view.fingerprint)),
                    ("from", Text(view.valid_from, style=_LABEL)),
                    ("until", validity),
                ]
            )
        )

    # -- internals ---------------------------------------------------------

    def _header(self, version: str, right: Text) -> None:
        self._out.print(
            Text.assemble(
                ("▌ ", f"bold {_OK}"),
                ("secondeye", "bold"),
                (f" {version}", _LABEL),
                "   ",
                right,
            )
        )


def _upstream_text(upstream: str | None) -> Text:
    if upstream is None:
        return Text("none (--no-upstream)", style=_LABEL)
    return Text.assemble(upstream, ("   Burp/ZAP chain", _LABEL))


def _scope_block(scope: ScopeView) -> Text:
    """Multi-line scope listing: one target per line, regexes marked."""
    if not scope.targets and not scope.target_regex:
        return Text(scope.summary(), style=_LABEL)
    block = Text()
    first = True
    for target in scope.targets:
        if not first:
            block.append("\n")
        block.append(target)
        first = False
    for pattern in scope.target_regex:
        if not first:
            block.append("\n")
        block.append(pattern, style=_REGEX)
        block.append("   regex", style=_LABEL)
        first = False
    if scope.target_all:
        block.append("\n")
        block.append("--target-all", style=_WARN)
        block.append("   scope matching bypassed", style=_LABEL)
    return block


def _kv(pairs: list[tuple[str, Text]]) -> Group:
    """Aligned label/value lines.

    Each line is assembled by hand rather than via a rich Table so that
    no line is right-padded to a column width (which would leave
    trailing whitespace on every line of output). The label is styled as
    a *span*, never as the line's base style: a base style is inherited
    by everything appended after it, so a bold value would render as
    bold+dim (SGR ``1;2``) — contradictory, and unpredictable across
    terminals.

    Args:
        pairs: ``(label, value)`` pairs; a value may contain newlines,
            in which case continuation lines are indented to align.

    Returns:
        The assembled lines as a single renderable.
    """
    lines: list[Text] = []
    for label, value in pairs:
        for index, segment in enumerate(value.split("\n")):
            line = Text()
            line.append(
                " " * _INDENT + (label if index == 0 else "").ljust(_LABEL_WIDTH), style=_LABEL
            )
            line.append_text(segment)
            lines.append(line)
    return Group(*lines)


ui = Ui()
"""Process-wide renderer writing to the real stdout/stderr."""
