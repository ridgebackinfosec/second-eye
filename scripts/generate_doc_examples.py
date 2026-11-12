#!/usr/bin/env python3
"""Capture documentation examples from the real code and inject them into docs.

Every command output, terminal screen and CLI help block shown in README.md or
docs/ is produced by this script from the actual renderers — never hand-written
and never a screenshot. Hand-pasted output rots silently: nothing fails when it
drifts, so it stays wrong until a reader follows a README that no longer
matches the program. ``--check`` (wired to tests/test_doc_examples.py) turns
that silent rot into a red test naming the command that fixes it.

Usage::

    python scripts/generate_doc_examples.py              # write
    python scripts/generate_doc_examples.py --check      # exit non-zero on drift
    python scripts/generate_doc_examples.py --only NAME  # iterate on one

Generated content lives between ``<!-- BEGIN GENERATED: name -->`` and
``<!-- END GENERATED: name -->`` markers. Everything outside them is
hand-owned prose and is never touched. A missing marker is a configuration
error, not something to skip silently — an example that is generated but never
displayed is invisible until someone notices the docs are missing a screen.

Determinism is what makes ``--check`` meaningful, so every source of
run-to-run variation is pinned rather than masked where that is possible:
fixture timestamps, the capture name, the listen port, and the console width
are all fixed constants below.

This script is not part of the distribution (hatchling ships only
src/secondeye) and nothing in the package imports it.
"""

from __future__ import annotations

import argparse
import datetime
import difflib
import http.server
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from secondeye.analysis.classify import ClassifiedEntry, classify_entries
from secondeye.analysis.manifest import Flow, build_flows, build_manifest
from secondeye.analysis.render import render_analysis_md
from secondeye.capture.har import HarEntry, parse_har_entry

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "demo_capture" / "raw.har"

# Exit codes. The caller (tests/test_doc_examples.py) distinguishes drift from
# "this machine can't produce the examples", because a missing optional
# fixture is not a drift failure.
EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_CONFIG = 2
EXIT_UNAVAILABLE = 3

# Pinned inputs. These are arguments to the real renderers, not masks applied
# afterwards, so the rendered output is byte-identical on every machine.
CAPTURE_NAME = "auth-flow-test"
CAPTURE_TARGETS = ["app.example-corp.com"]
CAPTURE_STARTED = datetime.datetime(2026, 3, 14, 9, 15, 0, tzinfo=datetime.UTC)
CAPTURE_ENDED = datetime.datetime(2026, 3, 14, 9, 16, 30, tzinfo=datetime.UTC)

DEFAULT_WIDTH = 100

MAX_DIFF_LINES = 40

REGENERATE_HINT = "python scripts/generate_doc_examples.py"


class ConfigurationError(RuntimeError):
    """A marker is missing, or an example is misconfigured."""


class FixtureUnavailableError(RuntimeError):
    """A tool or fixture this machine lacks, so the example can't be produced."""


@dataclass(frozen=True)
class Example:
    """One generated documentation example.

    Attributes:
        name: Marker name, also the SVG/file basename. Must be unique.
        render: Produces the example's content. Called with no arguments;
            returns the text to inject (or, for ``kind="svg"``, is used to
            produce the terminal capture that becomes the SVG).
        kind: ``text`` (fenced code block), ``markdown`` (injected raw),
            ``svg`` (written to an .svg file, injected as an <img> tag), or
            ``file`` (written whole to ``path``, no markers).
        fence: Code-fence language for ``kind="text"``.
        width: Console width for this example, in columns.
        targets: Markdown files to inject into, repo-relative.
        title: Titlebar text for ``kind="svg"``.
        path: Output path for ``kind="file"``, repo-relative.
    """

    name: str
    render: Callable[[], str]
    kind: str = "text"
    fence: str = "text"
    width: int = DEFAULT_WIDTH
    targets: tuple[str, ...] = ()
    title: str = "secondeye"
    path: str | None = None
    extra: dict[str, str] = field(default_factory=dict)


# --------------------------------------------------------------------------
# Fixture loading
# --------------------------------------------------------------------------


def _load_fixture_entries() -> list[HarEntry]:
    """Parse the committed demo capture with the real HAR parser.

    Returns:
        The fixture's entries, as HarEntry objects.

    Raises:
        FixtureUnavailableError: If the fixture file is missing.
    """
    if not FIXTURE.exists():
        raise FixtureUnavailableError(f"demo capture fixture not found at {FIXTURE}")
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    entries = raw["log"]["entries"]
    assert isinstance(entries, list)
    return [parse_har_entry(entry) for entry in entries]


def _analysis_pipeline() -> tuple[list[ClassifiedEntry], list[Flow]]:
    """Run the real classify -> flows pipeline over the fixture.

    Mirrors recording/manager.py's stop_capture() exactly, so the examples
    show what the program actually produces rather than a reimplementation.

    Returns:
        (classified, flows).
    """
    entries = _load_fixture_entries()
    classified = classify_entries(entries)
    flows = build_flows(classified)
    return classified, flows


def _render_full_analysis() -> str:
    """Render the complete ANALYSIS.md for the fixture capture."""
    classified, flows = _analysis_pipeline()
    return render_analysis_md(
        capture_name=CAPTURE_NAME,
        targets=CAPTURE_TARGETS,
        started_at=CAPTURE_STARTED,
        ended_at=CAPTURE_ENDED,
        classified=classified,
        flows=flows,
    )


# --------------------------------------------------------------------------
# Example capture functions — each calls the REAL renderer
# --------------------------------------------------------------------------


def _capture_analysis_excerpt() -> str:
    """The ANALYSIS.md header, Summary and Capture Signals sections.

    Sliced at a section boundary rather than a line count, so the excerpt
    can't end mid-sentence when the renderer changes.
    """
    full = _render_full_analysis()
    marker = "\n## Sequence Diagram"
    cut = full.find(marker)
    if cut == -1:
        raise ConfigurationError(
            "ANALYSIS.md no longer contains a '## Sequence Diagram' heading; "
            "the analysis-excerpt slice point needs updating."
        )
    return full[:cut].rstrip() + "\n"


def _capture_analysis_full() -> str:
    """The complete ANALYSIS.md, with a generated-file header."""
    body = _render_full_analysis()
    return (
        "<!--\n"
        "  GENERATED FILE - do not edit by hand.\n"
        f"  Produced from tests/fixtures/demo_capture/raw.har by:\n"
        f"      {REGENERATE_HINT}\n"
        "  Edit the fixture or the renderer, then regenerate.\n"
        "-->\n\n" + body
    )


def _capture_manifest_excerpt() -> str:
    """manifest.json for the fixture, with flows truncated to one entry.

    The truncation is why the surrounding prose says so: the real file carries
    every flow. Everything shown is the real build_manifest() output.
    """
    classified, flows = _analysis_pipeline()
    manifest = build_manifest(
        capture_name=CAPTURE_NAME,
        started_at=CAPTURE_STARTED,
        ended_at=CAPTURE_ENDED,
        targets=CAPTURE_TARGETS,
        target_regex=[],
        target_all=False,
        upstream=None,
        no_upstream=True,
        classified=classified,
        flows=flows,
    )
    shown = dict(manifest)
    manifest_flows = shown.get("flows")
    if isinstance(manifest_flows, list) and len(manifest_flows) > 1:
        shown["flows"] = manifest_flows[:1]
    return json.dumps(shown, indent=2) + "\n"


def _cli_help(*argv: str) -> str:
    """Capture ``secondeye <argv> --help`` from the real CLI.

    Runs the installed module in a subprocess with COLUMNS pinned, so the
    output cannot reflow on a different terminal. The parser sets
    ``prog="secondeye"``, so the usage line reads the same however it's
    invoked.
    """
    env = {**os.environ, "COLUMNS": str(DEFAULT_WIDTH), "NO_COLOR": "1"}
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "secondeye.cli", *argv, "--help"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        cwd=REPO_ROOT,
        check=False,
    )
    if result.returncode != 0:
        raise ConfigurationError(
            f"`secondeye {' '.join(argv)} --help` exited {result.returncode}:\n{result.stderr}"
        )
    return result.stdout


# --------------------------------------------------------------------------
# Live-daemon captures
#
# These run the real CLI against a real daemon in a throwaway HOME, because
# the startup banner and the capture summary are what a new operator most
# wants to see and there is no way to render them without the daemon that
# produces them. tls/ca.py's default_state_dir() resolves Path.home() at call
# time and no module caches a path at import time, so overriding HOME on the
# subprocess environment is sufficient isolation -- the developer's real CA
# and captures are never touched.
# --------------------------------------------------------------------------

# Pinned rather than free ports, so the banner's "Listening:" line and the
# recorded URLs are identical on every machine.
DEMO_PORT = 18079
DEMO_ORIGIN_PORT = 18099
# The live examples record real traffic, which means the daemon has to actually
# reach the destination. Resolving a pretty hostname would need DNS (or an
# /etc/hosts entry) and would make the generator non-hermetic, so the demo
# session targets a local origin server by IP. The surrounding prose in
# README.md says so; the ANALYSIS.md examples, which come from a committed
# fixture rather than live traffic, use a realistic hostname instead.
DEMO_TARGET = "127.0.0.1"
DEMO_CAPTURE_NAME = "auth-flow-test"

DEMO_REQUEST_PATHS = (
    "/api/v2/users/4815/profile",
    "/api/v2/reports?user_id=4815&org_id=162342&limit=25",
    "/api/v2/notifications?since=1773480000",
)

_SOCKET_WAIT_SECONDS = 10.0

# Substitutions applied to live terminal output. Everything that can be pinned
# is pinned instead (ports, capture name, HOME); these cover the values that
# genuinely cannot be -- the wall-clock date and time the capture ran.
#
# Deliberately unanchored: a \b in front of a digit fails when an ANSI escape
# sequence sits immediately before it (escapes end in a letter, so there is no
# word boundary), which would silently leave the real value in the docs.
_MASKS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC"), "2026-03-14 09:15:00 UTC"),
    (re.compile(r"started \d{2}:\d{2}:\d{2}"), "started 09:15:00"),
    (re.compile(r"\d{4}-\d{2}-\d{2}_"), "2026-03-14_"),
)


def _mask(text: str) -> str:
    """Apply the time/date substitutions to captured terminal output."""
    for pattern, replacement in _MASKS:
        text = pattern.sub(replacement, text)
    return text


def _demo_env(home: Path) -> dict[str, str]:
    return {
        **os.environ,
        "HOME": str(home),
        "COLUMNS": str(DEFAULT_WIDTH),
        # The banner and status output colorize a leading marker. Force it on
        # so the SVG shows what a real terminal shows; the text examples strip
        # it back out (see _strip_ansi).
        "FORCE_COLOR": "1",
        "NO_COLOR": "",
    }


def _run_cli(home: Path, *argv: str, timeout: float = 30.0) -> subprocess.CompletedProcess[str]:
    """Run one `secondeye` verb against the demo daemon."""
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "secondeye.cli", *argv],
        env=_demo_env(home),
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=REPO_ROOT,
        check=False,
    )


def _wait_for_socket(home: Path, proc: subprocess.Popen[str]) -> None:
    """Block until the daemon's control socket appears, or fail loudly."""
    socket_path = home / ".local" / "state" / "secondeye" / "control.sock"
    deadline = time.monotonic() + _SOCKET_WAIT_SECONDS
    while time.monotonic() < deadline:
        if socket_path.exists():
            return
        if proc.poll() is not None:
            stderr = proc.stderr.read() if proc.stderr else ""
            raise FixtureUnavailableError(f"demo daemon exited before starting:\n{stderr}")
        time.sleep(0.05)
    raise FixtureUnavailableError(
        f"demo daemon did not create its control socket within {_SOCKET_WAIT_SECONDS}s"
    )


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _mask_home(text: str, home: Path) -> str:
    """Replace the throwaway HOME with ``~``.

    Unanchored on purpose: a \\b before a path component fails when an escape
    sequence sits immediately in front of it, which would silently leave the
    real path in the committed docs.
    """
    return text.replace(str(home), "~")


class _DemoOriginHandler(http.server.BaseHTTPRequestHandler):
    """A tiny JSON origin for the demo session to record traffic against.

    HTTP/1.1 so the proxy's keep-alive path is exercised rather than the
    connection being torn down after each response.
    """

    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802  (http.server's required spelling)
        body = json.dumps({"ok": True, "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Silence per-request logging; it would interleave with --check output."""


def _drive_demo_traffic() -> None:
    """Send a few in-scope requests through the proxy, so counts are real.

    Raises:
        FixtureUnavailableError: If curl is not installed.
    """
    curl = shutil.which("curl")
    if curl is None:
        raise FixtureUnavailableError(
            "curl is required to record the demo session's traffic for the live examples"
        )
    for path in DEMO_REQUEST_PATHS:
        subprocess.run(  # noqa: S603
            [
                curl,
                "--silent",
                "--show-error",
                "--max-time",
                "15",
                "--proxy",
                f"127.0.0.1:{DEMO_PORT}",
                f"http://{DEMO_TARGET}:{DEMO_ORIGIN_PORT}{path}",
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )


@dataclass
class _LiveCapture:
    """Raw terminal output from one run of the demo operator loop."""

    banner: str
    status: str
    capture_start: str
    capture_stop: str


_live_cache: _LiveCapture | None = None


def _collect_live_capture() -> _LiveCapture:
    """Drive a real daemon through the operator loop once, capturing output.

    Cached: all the live examples come from one daemon run, so the numbers
    they show are internally consistent.

    Raises:
        FixtureUnavailableError: If the daemon can't be started here.
    """
    global _live_cache
    if _live_cache is not None:
        return _live_cache

    try:
        origin = http.server.ThreadingHTTPServer(
            ("127.0.0.1", DEMO_ORIGIN_PORT), _DemoOriginHandler
        )
    except OSError as exc:
        # Pinned ports are what make the recorded URLs identical everywhere,
        # but they can collide with something else on the machine. That's a
        # "can't produce the examples here", not documentation drift.
        raise FixtureUnavailableError(
            f"could not bind the demo origin on 127.0.0.1:{DEMO_ORIGIN_PORT}: {exc}"
        ) from exc

    # contextlib.closing-style ownership: everything from here on is inside a
    # try/finally that shuts the origin down, including the daemon spawn. An
    # earlier version started the origin outside this block and leaked the
    # port whenever the daemon failed to start.
    try:
        return _collect_with_origin(origin)
    finally:
        origin.shutdown()
        origin.server_close()


def _collect_with_origin(origin: http.server.ThreadingHTTPServer) -> _LiveCapture:
    """Run the demo operator loop against an already-listening origin."""
    global _live_cache

    origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    origin_thread.start()

    with tempfile.TemporaryDirectory(prefix="secondeye-docs-") as tmp:
        home = Path(tmp)
        proc = subprocess.Popen(  # noqa: S603
            [
                sys.executable,
                "-m",
                "secondeye.cli",
                "proxy",
                "start",
                "--target",
                DEMO_TARGET,
                "--no-upstream",
                "--listen-address",
                f"127.0.0.1:{DEMO_PORT}",
            ],
            env=_demo_env(home),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=REPO_ROOT,
        )
        try:
            _wait_for_socket(home, proc)
            capture_start = _run_cli(home, "capture", "start", "--name", DEMO_CAPTURE_NAME).stdout
            # Real in-scope traffic, so the live request count and the capture
            # summary show actual numbers rather than zeros.
            _drive_demo_traffic()
            status = _run_cli(home, "proxy", "status").stdout
            capture_stop = _run_cli(home, "capture", "stop").stdout
        finally:
            _run_cli(home, "proxy", "stop", timeout=15.0)
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            banner = proc.stdout.read() if proc.stdout else ""

        def clean(text: str) -> str:
            return _mask(_mask_home(text, home))

        _live_cache = _LiveCapture(
            banner=clean(banner),
            status=clean(status),
            capture_start=clean(capture_start),
            capture_stop=clean(capture_stop),
        )
    return _live_cache


def _capture_proxy_status() -> str:
    return _strip_ansi(_collect_live_capture().status)


def _capture_capture_stop() -> str:
    live = _collect_live_capture()
    return _strip_ansi(live.capture_start + "\n" + live.capture_stop)


def _capture_hero_terminal() -> str:
    """The full operator loop as one terminal session, ANSI intact."""
    live = _collect_live_capture()
    return live.banner.rstrip("\n") + "\n\n" + live.capture_start + "\n" + live.capture_stop


HERO_SVG_PATH = "docs/images/examples/hero.svg"


def _render_hero_svg() -> str:
    """Re-render the captured terminal session as an SVG and write it.

    Rich is used *only* here, and only to wrap output the program already
    produced — the captured ANSI is replayed into a recording console, so the
    SVG and the plain-text examples show exactly the same bytes. Nothing in
    src/secondeye imports rich, and it is a dev-extra dependency only.

    Returns:
        The SVG document text. The caller writes it to ``Example.path`` and
        injects an <img> tag pointing there, so the SVG's *content* takes part
        in --check like every other example — writing it as a side effect here
        would mean only the (constant) path was ever compared, and the image
        could rot undetected.

    Raises:
        FixtureUnavailableError: If rich isn't installed.
    """
    if importlib.util.find_spec("rich") is None:
        raise FixtureUnavailableError(
            "rich is required to render the SVG hero; install the dev extra "
            '(pip install -e ".[dev]")'
        )

    from rich.console import Console
    from rich.text import Text

    ansi = Text.from_ansi(_capture_hero_terminal())
    console = Console(
        file=io.StringIO(),
        record=True,
        width=DEFAULT_WIDTH,
        force_terminal=True,
        color_system="truecolor",
        # Keeps the output identical regardless of host platform.
        legacy_windows=False,
    )
    console.print(ansi, end="")
    svg = console.export_svg(title="secondeye")
    return svg if svg.endswith("\n") else svg + "\n"


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------


def _examples() -> list[Example]:
    """Build the example registry."""
    return [
        Example(
            name="analysis-excerpt",
            render=_capture_analysis_excerpt,
            kind="text",
            fence="markdown",
            targets=("README.md",),
        ),
        Example(
            name="analysis-full",
            render=_capture_analysis_full,
            kind="file",
            path="docs/examples/ANALYSIS.sample.md",
        ),
        Example(
            name="manifest-excerpt",
            render=_capture_manifest_excerpt,
            kind="text",
            fence="json",
            targets=("README.md",),
        ),
        Example(
            name="cli-help-root",
            render=lambda: _cli_help(),
            targets=("docs/CLI.md",),
        ),
        Example(
            name="cli-help-proxy-start",
            render=lambda: _cli_help("proxy", "start"),
            targets=("docs/CLI.md",),
        ),
        Example(
            name="cli-help-proxy-status",
            render=lambda: _cli_help("proxy", "status"),
            targets=("docs/CLI.md",),
        ),
        Example(
            name="cli-help-capture-start",
            render=lambda: _cli_help("capture", "start"),
            targets=("docs/CLI.md",),
        ),
        Example(
            name="cli-help-capture-stop",
            render=lambda: _cli_help("capture", "stop"),
            targets=("docs/CLI.md",),
        ),
        Example(
            name="hero",
            render=_render_hero_svg,
            kind="svg",
            path=HERO_SVG_PATH,
            title="secondeye",
            targets=("README.md",),
        ),
        Example(
            name="proxy-status",
            render=_capture_proxy_status,
            targets=("README.md",),
        ),
        Example(
            name="capture-stop-summary",
            render=_capture_capture_stop,
            targets=("README.md",),
        ),
        Example(
            name="cli-help-ca-export",
            render=lambda: _cli_help("ca", "export"),
            targets=("docs/CLI.md",),
        ),
    ]


# --------------------------------------------------------------------------
# Injection
# --------------------------------------------------------------------------


def _marker_pattern(name: str) -> re.Pattern[str]:
    escaped = re.escape(name)
    return re.compile(
        rf"(<!-- BEGIN GENERATED: {escaped} -->\n)(.*?)(<!-- END GENERATED: {escaped} -->)",
        re.DOTALL,
    )


def _block_for(example: Example, content: str) -> str:
    """Render an example's content as the text that sits between its markers."""
    if example.kind == "markdown":
        return content if content.endswith("\n") else content + "\n"
    if example.kind == "svg":
        if example.path is None:
            raise ConfigurationError(f"example {example.name!r} is kind=svg but has no path")
        return f'<img src="{example.path}" alt="{example.title} terminal session">\n'
    body = content.rstrip("\n")
    return f"```{example.fence}\n{body}\n```\n"


def _render_example(example: Example) -> str:
    """Produce the final injectable text (or file body) for one example."""
    return example.render()


def _plan_file_writes(example: Example, content: str, sources: dict[Path, str]) -> dict[Path, str]:
    """Compute every file this example wants to change, as {path: new text}.

    Args:
        example: The example being injected.
        content: Its freshly captured content.
        sources: The working text of every file touched so far this run. Several
            examples target the same document (docs/CLI.md holds six), so each
            must build on the previous one's edit rather than re-reading the
            file from disk — otherwise every example but the last is dropped,
            and ``--check`` disagrees with what a write actually produces.

    Returns:
        {path: new text} for the files this example changes.
    """
    writes: dict[Path, str] = {}

    if example.kind == "file":
        if example.path is None:
            raise ConfigurationError(f"example {example.name!r} is kind=file but has no path")
        writes[REPO_ROOT / example.path] = content
        return writes

    if example.kind == "svg":
        if example.path is None:
            raise ConfigurationError(f"example {example.name!r} is kind=svg but has no path")
        # The image file itself is a tracked output, so its bytes are compared
        # by --check alongside the <img> tag that points at it.
        writes[REPO_ROOT / example.path] = content

    block = _block_for(example, content)
    if not example.targets:
        raise ConfigurationError(f"example {example.name!r} has no targets to inject into")

    for target in example.targets:
        doc = REPO_ROOT / target
        if not doc.exists():
            raise ConfigurationError(
                f"example {example.name!r} targets {target}, which does not exist"
            )
        original = sources.get(doc)
        if original is None:
            original = doc.read_text(encoding="utf-8")
            sources[doc] = original
        pattern = _marker_pattern(example.name)
        if pattern.search(original) is None:
            raise ConfigurationError(
                f"{target} has no '<!-- BEGIN GENERATED: {example.name} -->' / "
                f"'<!-- END GENERATED: {example.name} -->' marker pair. "
                "An example that is generated but never displayed is invisible — "
                "add the markers or remove the example from the registry."
            )
        updated = pattern.sub(lambda m: m.group(1) + block + m.group(3), original, count=1)
        sources[doc] = updated
        writes[doc] = updated

    return writes


def _diff(path: Path, old: str, new: str) -> list[str]:
    rel = path.relative_to(REPO_ROOT)
    return list(
        difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
        )
    )


def _run(check: bool, only: str | None) -> int:
    """Generate (or verify) every selected example.

    Args:
        check: Verify only; do not write.
        only: Restrict to one example by name.

    Returns:
        A process exit code.
    """
    examples = _examples()
    if only is not None:
        examples = [e for e in examples if e.name == only]
        if not examples:
            known = ", ".join(sorted(e.name for e in _examples()))
            print(f"Error: no example named {only!r}. Known examples: {known}", file=sys.stderr)
            return EXIT_CONFIG

    # `sources` is the working text of every file as examples are applied in
    # order; `originals` is the pristine on-disk text. Staleness is the diff
    # between the two at the END of the run, never against intermediate state:
    # several examples share a document, so comparing mid-run reports every
    # example after the first as stale even when nothing changed.
    sources: dict[Path, str] = {}
    originals: dict[Path, str] = {}
    stale_examples: list[str] = []

    for example in examples:
        try:
            content = _render_example(example)
            writes = _plan_file_writes(example, content, sources)
        except FixtureUnavailableError as exc:
            print(f"Cannot generate {example.name!r}: {exc}", file=sys.stderr)
            return EXIT_UNAVAILABLE
        except ConfigurationError as exc:
            print(f"Error in example {example.name!r}: {exc}", file=sys.stderr)
            return EXIT_CONFIG

        for path, new_text in writes.items():
            if path not in originals:
                originals[path] = path.read_text(encoding="utf-8") if path.exists() else ""
            sources[path] = new_text

            # Per-example staleness: compare this example's own block against
            # whatever sits between its markers in the pristine file, so one
            # drifted example doesn't implicate the five that share its page.
            # Whole-file outputs (kind=file, and the .svg a kind=svg example
            # writes alongside its <img> tag) have no markers, so they're
            # compared in full instead.
            is_whole_file_output = example.path is not None and path == REPO_ROOT / example.path
            if is_whole_file_output or example.kind == "file":
                if new_text != originals[path] and example.name not in stale_examples:
                    stale_examples.append(example.name)
                continue
            existing = _marker_pattern(example.name).search(originals[path])
            fresh = _block_for(example, content)
            if (existing is None or existing.group(2) != fresh) and (
                example.name not in stale_examples
            ):
                stale_examples.append(example.name)

    stale: dict[Path, list[str]] = {
        path: _diff(path, originals[path], text)
        for path, text in sources.items()
        if text != originals[path]
    }

    if check:
        if not stale:
            print(f"All {len(examples)} documentation example(s) are up to date.")
            return EXIT_OK

        print("Documentation examples are out of date.\n", file=sys.stderr)
        shown = 0
        for path, lines in stale.items():
            print(f"--- {path.relative_to(REPO_ROOT)}", file=sys.stderr)
            for line in lines:
                if shown >= MAX_DIFF_LINES:
                    break
                print(line.rstrip("\n"), file=sys.stderr)
                shown += 1
            if shown >= MAX_DIFF_LINES:
                print(f"... diff truncated at {MAX_DIFF_LINES} lines ...", file=sys.stderr)
                break
        print("", file=sys.stderr)
        print(f"Stale example(s): {', '.join(stale_examples)}", file=sys.stderr)
        stale_paths = ", ".join(str(p.relative_to(REPO_ROOT)) for p in stale)
        print(f"Stale file(s):    {stale_paths}", file=sys.stderr)
        print("", file=sys.stderr)
        print(f"Regenerate with:  {REGENERATE_HINT}", file=sys.stderr)
        return EXIT_DRIFT

    written = 0
    for path, new_text in sources.items():
        if new_text == originals[path]:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(new_text, encoding="utf-8")
        print(f"updated {path.relative_to(REPO_ROOT)}")
        written += 1

    if written == 0:
        print(f"All {len(examples)} documentation example(s) already up to date.")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="generate_doc_examples.py",
        description="Capture documentation examples from the real code.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify committed examples match a fresh capture; exit non-zero on drift.",
    )
    parser.add_argument(
        "--only",
        metavar="NAME",
        help="Generate just one example by name, for iterating.",
    )
    args = parser.parse_args(argv)
    return _run(check=args.check, only=args.only)


if __name__ == "__main__":
    sys.exit(main())
