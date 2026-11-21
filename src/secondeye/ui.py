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
import re
import sys
import textwrap
from dataclasses import dataclass
from typing import TextIO

from rich.box import SIMPLE_HEAD
from rich.console import Console, Group
from rich.table import Table
from rich.text import Text

from secondeye.doctor import CheckStatus, DoctorReport

__all__ = [
    "ActiveCaptureView",
    "CaStatusView",
    "CaptureRow",
    "CaptureStartedView",
    "CaptureStoppedView",
    "HelpEntry",
    "HelpSection",
    "HelpView",
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
# Blank columns between a flag's invocation and its help text.
_GUTTER = 2
# Floor for the help column, so a very narrow terminal still wraps
# words rather than breaking down to one character per line.
_MIN_TEXT_WIDTH = 20


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
        flow_count: Narrative flows in ANALYSIS.md.
        finding_count: Actionable findings tallied for this capture.
    """

    name: str
    request_count: int
    total_bytes: int
    output_dir: str | None = None
    flow_count: int = 0
    finding_count: int = 0


@dataclass(frozen=True)
class CaptureRow:
    """One row of ``capture list``.

    Attributes:
        name: The capture's --name label.
        request_count: Requests recorded.
        total_bytes: Request+response body bytes recorded.
        output_dir: Where its outputs live.
        target: First configured target, for display.
        flow_count: Narrative flows in its ANALYSIS.md.
        finding_count: Actionable findings tallied for it.
        started_at: Pre-formatted start time, or "" if unknown.
        active: Whether this capture is the one currently recording.
    """

    name: str
    request_count: int
    total_bytes: int
    output_dir: str
    target: str = ""
    flow_count: int = 0
    finding_count: int = 0
    started_at: str = ""
    active: bool = False


@dataclass(frozen=True)
class HelpEntry:
    """One flag or subcommand on a help screen.

    Attributes:
        invocation: How it is written on the command line, e.g.
            ``"-tf, --target-file FILE"``.
        help_text: Its one-paragraph explanation.
    """

    invocation: str
    help_text: str


@dataclass(frozen=True)
class HelpSection:
    """A titled block of help entries.

    Attributes:
        title: The section heading, e.g. ``"Scope"``.
        description: An optional line introducing the section.
        entries: The flags or subcommands it contains.
    """

    title: str
    description: str | None
    entries: tuple[HelpEntry, ...]


@dataclass(frozen=True)
class HelpView:
    """Everything one ``--help`` screen shows.

    Attributes:
        usage: The usage text as one unwrapped line, without argparse's
            ``usage: `` prefix. Wrapping it is this module's job.
        prog: The program name, used to size the usage hanging indent.
        description: The command's own explanation, if it has one.
        sections: Flag/subcommand blocks, in declaration order.
        examples: Runnable command lines, shown last.
    """

    usage: str
    prog: str
    description: str | None
    sections: tuple[HelpSection, ...]
    examples: tuple[str, ...]


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
        self._capture_summary("Stopped", view)

    def _capture_summary(
        self, headline: str, view: CaptureStoppedView, *, note: str | None = None
    ) -> None:
        """Shared layout for capture stop/analyze/recover confirmations.

        Args:
            headline: The verb to lead with ("Stopped", "Recovered", ...).
            view: The capture's facts.
            note: Optional clarifier appended to the headline.
        """
        head = Text.assemble(("✓ ", f"bold {_OK}"), (headline, "bold"), " ", view.name)
        if note is not None:
            head.append(f"   {note}", style=_LABEL)
        self._out.print(head)
        self._out.print()
        recorded = Text.assemble(
            (str(view.request_count), "bold"),
            (" requests   ", _LABEL),
            (format_bytes(view.total_bytes), "bold"),
        )
        if view.flow_count:
            recorded.append("   ", style=_LABEL)
            recorded.append(str(view.flow_count), style="bold")
            recorded.append(" flows", style=_LABEL)
        rows: list[tuple[str, Text]] = [("recorded", recorded)]
        if view.finding_count:
            rows.append(
                (
                    "signals",
                    Text.assemble(
                        (f"⚠ {view.finding_count}", f"bold {_WARN}"),
                        ("   see ## Capture Signals in ANALYSIS.md", _LABEL),
                    ),
                )
            )
        rows.append(
            (
                "analysis",
                Text.assemble(("ANALYSIS.md", "bold"), ("   → hand to your AI chat", _LABEL)),
            )
        )
        rows.append(("also", Text("raw.har · manifest.json", style=_LABEL)))
        if view.output_dir is not None:
            rows.append(("output", Text(view.output_dir, style=_LABEL)))
        self._out.print(_kv(rows))

    def capture_list(self, rows: list[CaptureRow], *, captures_dir: str | None = None) -> None:
        """Print one row per capture as a table.

        SIG is the count of actionable findings, so a capture that found
        something is visible without opening its ANALYSIS.md. The output
        path is deliberately *not* a column: at terminal widths it either
        truncates (uncopyable) or dominates the table. The captures
        directory is printed once underneath instead, and every capture
        lives at ``<captures-dir>/<date>_<target>/<name>/``.

        Args:
            rows: The captures to list, in display order.
            captures_dir: Directory they were read from, shown as a footer.
        """
        # Column budget: this has to stay readable at 80 columns, where
        # rich would otherwise ellipsis-truncate the *headers* themselves.
        # Hence single-space padding, the active marker folded into the
        # name column rather than occupying its own, and no FLOWS column
        # (the least useful of the candidates for triage -- REQS already
        # conveys size, and the flow count is in ANALYSIS.md).
        #
        # TARGET is the one column allowed to ellipsis-truncate. Left to
        # flex it collapses to *blank* cells at 80 columns while keeping
        # its header, and a truncated hostname still identifies a target
        # where an empty cell identifies nothing. Truncating is only
        # acceptable here because nobody needs to copy a hostname out of
        # a listing verbatim -- which is exactly why the capture path is
        # a footer rather than a column.
        table = Table(
            box=SIMPLE_HEAD,
            header_style="bold",
            border_style=_LABEL,
            expand=False,
            pad_edge=False,
            show_edge=False,
            padding=(0, 1),
        )
        # min_width pins the narrow columns so rich's proportional
        # shrinking cannot squeeze them to "R…"/"SI…" or, worse, blank
        # their cells while keeping their headers. CAPTURE then gets
        # whatever is left, because the name is how an operator refers to
        # a capture and two sharing a prefix must stay distinguishable.
        table.add_column("CAPTURE", style="bold", no_wrap=True, overflow="ellipsis", max_width=36)
        table.add_column("REQS", justify="right", style=_ACCENT, no_wrap=True, min_width=4)
        table.add_column("SIZE", justify="right", no_wrap=True, min_width=7)
        table.add_column("SIG", justify="right", style=_WARN, no_wrap=True, min_width=3)
        table.add_column("STARTED", style=_LABEL, no_wrap=True, min_width=16)
        for row in rows:
            name = Text()
            name.append("● " if row.active else "  ", style=f"bold {_OK}")
            name.append(row.name, style="bold")
            table.add_row(
                name,
                str(row.request_count),
                format_bytes(row.total_bytes),
                str(row.finding_count) if row.finding_count else Text("—", style=_LABEL),
                row.started_at,
            )
        # soft_wrap is right for the key/value surfaces (it keeps long
        # paths and fingerprints unmangled, letting the terminal wrap
        # them), but wrong for a table: without a width constraint rich
        # measures the table at its natural size and a long capture name
        # pushes it past the terminal, which then hard-wraps every row.
        # Constrain this one renderable so rich fits it instead.
        self._out.print(table, soft_wrap=False)
        if captures_dir is not None:
            footer = Text("  ")
            if any(row.active for row in rows):
                footer.append("● active   ", style=_OK)
            footer.append(f"{len(rows)} capture(s) in {captures_dir}", style=_LABEL)
            self._out.print(footer)
        # Target isn't a column: it is near-constant within an engagement
        # and is already encoded in each capture's <date>_<target>/
        # directory, and giving it a column either truncated a hostname
        # or blanked the cell at 80 columns. Name the targets only when
        # the listing actually spans more than one, where the omission
        # would otherwise lose information.
        targets = sorted({row.target for row in rows if row.target})
        if len(targets) > 1:
            self._out.print(Text("  targets: " + ", ".join(targets), style=_LABEL))

    def capture_analyzed(self, view: CaptureStoppedView) -> None:
        """Confirm a re-render of an existing capture.

        Args:
            view: The re-rendered capture's facts.
        """
        self._capture_summary("Re-analyzed", view, note="raw.har unchanged")

    def capture_recovered(self, view: CaptureStoppedView) -> None:
        """Confirm a capture rebuilt from a leftover buffer.

        Args:
            view: The recovered capture's facts.
        """
        self._capture_summary("Recovered", view, note="rebuilt from a leftover buffer")

    def doctor_report(self, report: DoctorReport) -> None:
        """Print one row per environment check, then a verdict.

        Args:
            report: The checks and their outcomes.
        """
        self._header(
            report.version,
            Text.assemble(("environment check", _LABEL)),
        )
        self._out.print()
        marker = {
            CheckStatus.OK: ("✓", f"bold {_OK}"),
            CheckStatus.WARN: ("⚠", f"bold {_WARN}"),
            CheckStatus.FAIL: ("✗", f"bold {_ERR}"),
        }
        width = max((len(check.name) for check in report.checks), default=0)
        for check in report.checks:
            glyph, style = marker[check.status]
            line = Text("  ")
            line.append(f"{glyph} ", style=style)
            line.append(check.name.ljust(width), style=_LABEL)
            line.append("  ")
            line.append(check.detail)
            self._out.print(line)
            if check.hint is not None and check.status is not CheckStatus.OK:
                hint = Text(" " * (width + 6))
                hint.append(f"→ {check.hint}", style=_LABEL)
                self._out.print(hint)
        self._out.print()
        counts = report.counts
        verdict = Text("  ")
        if report.failed:
            verdict.append("✗ not ready", style=f"bold {_ERR}")
        elif counts[CheckStatus.WARN]:
            verdict.append("✓ ready", style=f"bold {_OK}")
            verdict.append(" — with warnings", style=_LABEL)
        else:
            verdict.append("✓ ready", style=f"bold {_OK}")
        verdict.append(
            f"   {counts[CheckStatus.OK]} passed, "
            f"{counts[CheckStatus.WARN]} warning(s), "
            f"{counts[CheckStatus.FAIL]} failed",
            style=_LABEL,
        )
        self._out.print(verdict)

    def ca_install_result(
        self,
        results: list[tuple[str, bool]],
        *,
        removing: bool = False,
        dry_run: bool = False,
        system_instructions: list[str] | None = None,
    ) -> None:
        """Report which trust stores were changed, and the manual steps left.

        Args:
            results: ``(label, changed)`` per trust store, in order.
            removing: Whether the CA was being removed rather than added.
            dry_run: Whether nothing was actually written.
            system_instructions: Commands for the system store, printed
                for the operator to run; None when removing.
        """
        verb = "Would remove from" if (dry_run and removing) else None
        if verb is None:
            verb = (
                "Would install into"
                if dry_run
                else ("Removed from" if removing else "Installed into")
            )
        if not results:
            self.plain("No Firefox or Chromium trust stores found in your home directory.")
        else:
            self._out.print(
                Text.assemble(
                    ("✓ ", f"bold {_OK}"), (f"{verb} {len(results)} trust store(s)", "bold")
                )
            )
            self._out.print()
            for label, changed in results:
                line = Text("  ")
                if changed:
                    line.append("✓ ", style=f"bold {_OK}")
                    line.append(label)
                else:
                    line.append("· ", style=_LABEL)
                    line.append(label)
                    line.append("   nothing to remove", style=_LABEL)
                self._out.print(line)
            self._out.print()
            if not dry_run and not removing:
                self._out.print(
                    Text("  Restart the browser for the new trust to take effect.", style=_LABEL)
                )
                self._out.print()
        if system_instructions:
            self._system_store_block(system_instructions)

    def ca_install_manual(
        self,
        pem_path: str,
        store_commands: list[tuple[str, str]],
        system_instructions: list[str],
    ) -> None:
        """Print every manual trust-store step, changing nothing.

        Takes pre-formatted commands rather than trust-store objects, so
        this module stays pure rendering and never has to know how a
        certutil invocation is assembled.

        Args:
            pem_path: Path to the CA certificate, as text.
            store_commands: ``(label, command)`` per NSS trust store.
            system_instructions: Commands for the system store.
        """
        self._out.print(Text.assemble(("secondeye CA: ", "bold"), pem_path))
        self._out.print()
        if store_commands:
            self._out.print(Text("  Firefox / Chromium (needs certutil):", style=_LABEL))
            for label, command in store_commands:
                self._out.print(Text(f"    {command}"))
                self._out.print(Text(f"      ({label})", style=_LABEL))
            self._out.print()
        self._system_store_block(system_instructions)

    def _system_store_block(self, instructions: list[str]) -> None:
        """Print the system trust store commands, for the operator to run."""
        self._out.print(Text("  System trust store (run these yourself):", style=_LABEL))
        for command in instructions:
            self._out.print(Text(f"    {command}"))

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

    def help_screen(self, view: HelpView, *, width: int | None = None) -> str:
        """Render one ``--help`` screen.

        Returns a string rather than printing, because this is called
        from ``argparse.ArgumentParser.format_help``, whose contract is
        to hand text back for argparse to write. Styling still obeys the
        same stream policy as every other surface: the Console decides
        whether to emit escapes by looking at stdout, so a piped or
        ``NO_COLOR`` help capture comes out as plain text.

        Args:
            view: The resolved help content.
            width: Wrap width; defaults to the detected terminal width.

        Returns:
            The rendered screen, newline-terminated.
        """
        console = self._out
        columns = width or console.width
        lines: list[Text] = _usage_lines(view.usage, view.prog, width=columns)
        if view.description:
            lines.append(Text())
            lines.extend(_wrapped(view.description, width=columns, indent=0))

        for section in view.sections:
            if not section.entries:
                continue
            lines.append(Text())
            lines.append(Text(section.title, style="bold"))
            if section.description:
                lines.extend(
                    _wrapped(section.description, width=columns, indent=_INDENT, style=_LABEL)
                )
                lines.append(Text())
            lines.extend(_entry_lines(section.entries, width=columns))

        if view.examples:
            lines.append(Text())
            lines.append(Text("Examples", style="bold"))
            for example in view.examples:
                lines.append(
                    Text(" " * _INDENT + example, style=_LABEL if _is_comment(example) else "bold")
                )

        with console.capture() as captured:
            for line in lines:
                console.print(line)
        return captured.get()

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


def _is_comment(example: str) -> bool:
    """Whether an example line is a comment rather than a command."""
    return example.startswith("#")


# Whole bracket/paren groups, else a bare token. Mirrors how argparse
# itself tokenises a usage line, so an alternation group such as
# ``(--a | --b | --c)`` is never split across two lines.
_USAGE_PART = re.compile(r"\(.*?\)+(?=\s|$)|\[.*?\]+(?=\s|$)|\S+")


def _usage_lines(usage: str, prog: str, *, width: int) -> list[Text]:
    """Wrap a usage line, hanging-indented under the program name.

    argparse can synthesise this itself, but it indents continuation
    lines to the full width of ``usage: <prog> `` and then emits at least
    one part per line regardless — so on a narrow terminal every
    continuation line overflows. Wrapping here instead lets the indent
    collapse when there isn't room for it, and keeps all of this
    module's layout decisions in this module.

    Args:
        usage: The usage text, unwrapped, without the ``usage: `` prefix.
        prog: The program name, used to size the hanging indent.
        width: Total line width available.

    Returns:
        One Text per output line.
    """
    prefix = "usage: "
    parts = _USAGE_PART.findall(" ".join(usage.split()))
    hanging = len(prefix) + len(prog) + 1
    # Collapse the alignment indent rather than overflow with it. An
    # alternation group is one indivisible part, so a wide one -- the
    # required upstream-trust choice, say -- can make the aligned indent
    # unaffordable on its own.
    longest = max((len(part) for part in parts), default=0)
    if hanging > width // 2 or hanging + longest > width:
        hanging = _INDENT

    rows: list[str] = []
    current = prefix
    for part in parts:
        if not current.strip() or current == prefix:
            current += part
        elif len(current) + 1 + len(part) > width:
            rows.append(current)
            current = " " * hanging + part
        else:
            current += " " + part
    rows.append(current)

    # Only the literal "usage: " is dimmed; the command line itself is
    # what the reader is scanning for.
    styled = [Text.assemble((prefix, _LABEL), rows[0][len(prefix) :])]
    styled.extend(Text(row) for row in rows[1:])
    return styled


def _wrapped(text: str, *, width: int, indent: int, style: str = "") -> list[Text]:
    """Word-wrap a paragraph into styled lines.

    Wrapping is done here, with ``textwrap``, rather than left to rich.
    The Consoles in this module run with ``soft_wrap=True`` (see
    ``_console``) precisely so that rich never re-flows a line, which
    keeps paths, regexes and fingerprints intact everywhere else — but it
    also means help prose would run off the edge unless something wraps
    it first.

    Args:
        text: The paragraph.
        width: Total line width available.
        indent: Left margin, in spaces.
        style: Style for the whole paragraph.

    Returns:
        One Text per output line.
    """
    available = max(width - indent, _MIN_TEXT_WIDTH)
    prefix = " " * indent
    lines = textwrap.wrap(
        " ".join(text.split()),
        width=available,
        # Both default to True, and both corrupt the tokens this help
        # text is mostly made of. Hyphen-breaking turns "--no-upstream"
        # into "--no-" + "upstream" and "<state-dir>/captures" into
        # "<state-" + "dir>/captures"; long-word breaking chops a path
        # mid-character. A flag name or path that overflows a narrow
        # terminal is readable; one that has been split is a wrong
        # answer the reader may well retype.
        break_on_hyphens=False,
        break_long_words=False,
    )
    return [Text(prefix + line, style=style) for line in lines or [""]]


def _entry_lines(entries: tuple[HelpEntry, ...], *, width: int) -> list[Text]:
    """Lay out a section's entries as invocation + wrapped help.

    Two layouts, chosen per entry. Normally the help text sits in a
    second column aligned across the whole section. When an invocation is
    too long for that column, its help drops to the following line
    instead of being squeezed into a sliver — a flag name is the one part
    of a help screen that must never be truncated or wrapped, since it is
    what the reader is going to type.

    Args:
        entries: The section's entries.
        width: Total line width available.

    Returns:
        One Text per output line.
    """
    indent = " " * _INDENT
    # Cap the gutter so that one long flag can't starve the help column
    # on a narrow terminal.
    budget = max(width // 3, _MIN_TEXT_WIDTH)

    def fits(entry: HelpEntry) -> bool:
        return len(entry.invocation) + _INDENT + _GUTTER <= budget

    widths = [len(entry.invocation) for entry in entries if fits(entry)]
    column = (max(widths) if widths else 0) + _INDENT + _GUTTER

    lines: list[Text] = []
    for entry in entries:
        head = Text()
        head.append(indent + entry.invocation, style=_ACCENT)
        if not entry.help_text:
            lines.append(head)
            continue
        body = _wrapped(entry.help_text, width=width, indent=column)
        if fits(entry):
            head.append(" " * (column - _INDENT - len(entry.invocation)))
            head.append(body[0].plain.strip())
            lines.append(head)
            lines.extend(body[1:])
        else:
            lines.append(head)
            lines.extend(body)
    return lines


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
