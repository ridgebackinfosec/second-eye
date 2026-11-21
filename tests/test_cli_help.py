"""Tests for the CLI's help surface and its flag-conflict gates.

Two things live here, because they are the same feature from two sides:
what ``--help`` *says* a command accepts, and what the parser actually
*enforces*. ``proxy start`` used to require one of
``--upstream-ca``/``--upstream-insecure``/``--no-upstream`` with nothing
in its help text saying so — the requirement was discovered by running
the command and reading the error. Moving that gate into a required
mutually exclusive group makes argparse state it in the usage line, so
the enforcement and the documentation can no longer drift apart.

Help text is asserted structurally (section headings are present, an
example block is present, a constraint is mentioned) rather than by
matching whole screens: ``docs/CLI.md`` plus
``tests/test_doc_examples.py`` already pin the exact rendering, and
duplicating that here would make every wording tweak fail twice.
"""

from __future__ import annotations

import io
import re
import subprocess
import sys
from pathlib import Path

import pytest

from secondeye import cli

_ESC = re.compile(r"\x1b\[[0-9;]*m")


def _help(*argv: str, columns: int = 100) -> str:
    """Render one parser's help screen as plain text.

    Args:
        argv: The command path, e.g. ``("proxy", "start")``.
        columns: Terminal width to render at.

    Returns:
        The help screen with any ANSI styling stripped.
    """
    parser = cli._build_parser()
    for name in argv:
        parser = _subparser(parser, name)
    stream = io.StringIO()
    parser.help_columns = columns  # type: ignore[attr-defined]
    parser.print_help(stream)
    return _ESC.sub("", stream.getvalue())


def _subparser(parser: object, name: str) -> object:
    """Find the subparser one command name deeper.

    Args:
        parser: The parser to descend from.
        name: The subcommand name.

    Returns:
        That subcommand's parser.
    """
    for action in parser._actions:  # type: ignore[attr-defined]
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict) and name in choices:
            return choices[name]
    raise AssertionError(f"no subparser named {name!r}")


def _description(*argv: str) -> str:
    """One parser's description text, unwrapped.

    Read off the parser rather than out of the rendered screen: the
    renderer word-wraps, so a phrase like "No daemon required" can
    straddle a line break and defeat a substring assertion that is
    really about the wording, not the layout.

    Args:
        argv: The command path.

    Returns:
        The description, or "" if it has none.
    """
    parser = cli._build_parser()
    for name in argv:
        parser = _subparser(parser, name)
    return str(getattr(parser, "description", "") or "")


def _parse_exit_code(*argv: str) -> int:
    """Parse arguments and report how argparse exited.

    Deliberately stops at ``parse_args`` rather than going through
    ``cli.main``: ``proxy start`` with an accepted argument set runs the
    daemon in the foreground and never returns, so a test that reached
    dispatch would hang rather than fail. The flag-conflict gates under
    test are argparse's, and argparse has finished its work here.

    Args:
        argv: The full command line, without the program name.

    Returns:
        argparse's exit status, or 0 if it accepted the arguments.
    """
    try:
        cli._build_parser().parse_args(list(argv))
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


# --------------------------------------------------------------------------
# Flag-conflict gates
# --------------------------------------------------------------------------


class TestUpstreamTrustFlagIsRequired:
    """One of the three upstream-trust flags must be chosen explicitly.

    ``proxy/upstream.py``'s ``validate_upstream_tls_config`` is still the
    library-level invariant; these tests cover the earlier, CLI-only gate
    that also puts the requirement in the usage line.
    """

    def test_omitting_all_three_fails_at_argument_parsing(self) -> None:
        assert _parse_exit_code("proxy", "start", "--target", "x.example") == 2

    def test_the_error_names_every_acceptable_flag(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _parse_exit_code("proxy", "start", "--target", "x.example")
        err = capsys.readouterr().err
        assert "--upstream-ca" in err
        assert "--upstream-insecure" in err
        assert "--no-upstream" in err

    def test_ca_and_insecure_together_are_rejected(self, tmp_path: Path) -> None:
        pem = tmp_path / "upstream.pem"
        pem.write_text("", encoding="utf-8")
        code = _parse_exit_code(
            "proxy",
            "start",
            "--target",
            "x.example",
            "--upstream-ca",
            str(pem),
            "--upstream-insecure",
        )
        assert code == 2

    def test_no_upstream_with_a_ca_is_rejected_rather_than_silently_ignored(
        self, tmp_path: Path
    ) -> None:
        """A discarded trust flag is worse than a refused one.

        Before this gate, ``--no-upstream --upstream-ca foo.pem`` was
        accepted and the CA ignored, so an operator could believe they
        had pinned the upstream leg when nothing was validating it.
        """
        pem = tmp_path / "upstream.pem"
        pem.write_text("", encoding="utf-8")
        code = _parse_exit_code(
            "proxy",
            "start",
            "--target",
            "x.example",
            "--no-upstream",
            "--upstream-ca",
            str(pem),
        )
        assert code == 2

    def test_each_flag_alone_passes_the_gate(self, tmp_path: Path) -> None:
        """Parsing succeeds; only the gate is under test, not startup."""
        pem = tmp_path / "upstream.pem"
        pem.write_text("", encoding="utf-8")
        parser = cli._build_parser()
        for extra in (["--no-upstream"], ["--upstream-insecure"], ["--upstream-ca", str(pem)]):
            args = parser.parse_args(["proxy", "start", "--target", "x.example", *extra])
            assert args.target == ["x.example"]

    def test_the_usage_line_marks_the_choice_as_required(self) -> None:
        """argparse brackets optional groups and parenthesises required ones.

        Asserting the parenthesised form is what distinguishes "you may
        pass one of these" from "you must" — the whole point of the gate.
        """
        usage = _help("proxy", "start", columns=200).split("\n\n", 1)[0]
        assert re.search(r"\((?=[^)]*--no-upstream)[^)]*\|", usage), usage


class TestVerbosityFlagsConflict:
    def test_verbose_and_quiet_together_are_rejected(self) -> None:
        code = _parse_exit_code(
            "proxy", "start", "--target", "x.example", "--no-upstream", "-v", "-q"
        )
        assert code == 2

    def test_either_one_alone_is_accepted(self) -> None:
        parser = cli._build_parser()
        for flag in ("-v", "-q"):
            args = parser.parse_args(
                ["proxy", "start", "--target", "x.example", "--no-upstream", flag]
            )
            assert args.verbose or args.quiet


# --------------------------------------------------------------------------
# Help structure
# --------------------------------------------------------------------------


class TestProxyStartHelpIsGrouped:
    def test_flags_are_split_into_named_sections(self) -> None:
        text = _help("proxy", "start")
        for heading in ("Scope", "Upstream", "Listener and output", "Logging"):
            assert heading in text, f"missing {heading!r} section"

    def test_the_bare_help_flag_does_not_lead_the_screen(self) -> None:
        """``-h`` is the least interesting thing on a grouped screen.

        argparse yields its built-in groups first, so without reordering
        every screen opens with a lone "-h, --help" above the flags the
        reader actually came for.
        """
        text = _help("proxy", "start")
        assert text.index("Scope") < text.index("-h, --help")

    def test_every_flag_still_appears_somewhere(self) -> None:
        text = _help("proxy", "start")
        for flag in (
            "--target",
            "--target-file",
            "--target-regex",
            "--target-all",
            "--listen-address",
            "--upstream-proxy",
            "--no-upstream",
            "--upstream-ca",
            "--upstream-insecure",
            "--captures-dir",
            "--cluster-window",
            "--max-connections",
            "--verbose",
            "--quiet",
        ):
            assert flag in text, f"{flag} vanished from the help"

    def test_metavars_describe_what_the_value_is(self) -> None:
        text = _help("proxy", "start")
        assert "--target DOMAIN" in text
        assert "--listen-address HOST:PORT" in text
        assert "--cluster-window MS" in text
        assert "--captures-dir DIR" in text

    def test_uninformative_shouting_metavars_are_gone(self) -> None:
        text = _help("proxy", "start")
        for shouted in ("TARGET_FILE", "LISTEN_ADDRESS", "CLUSTER_WINDOW", "MAX_CONNECTIONS"):
            assert shouted not in text, f"{shouted} is still used as a metavar"


class TestHelpCarriesExamples:
    def test_root_help_shows_the_first_run_workflow(self) -> None:
        text = _help()
        assert "Examples" in text
        assert "secondeye ca install" in text
        assert "secondeye proxy start" in text
        assert "secondeye capture start" in text
        assert "secondeye capture stop" in text

    def test_root_help_points_at_doctor(self) -> None:
        assert "secondeye doctor" in _help()

    @pytest.mark.parametrize(
        "command",
        [
            ("proxy", "start"),
            ("proxy", "status"),
            ("capture", "start"),
            ("capture", "stop"),
            ("capture", "list"),
            ("capture", "analyze"),
            ("capture", "recover"),
            ("doctor",),
            ("ca", "export"),
            ("ca", "install"),
            ("ca", "status"),
            ("ca", "import-upstream"),
        ],
    )
    def test_every_leaf_command_has_a_runnable_example(self, command: tuple[str, ...]) -> None:
        text = _help(*command)
        assert "Examples" in text, f"{' '.join(command)} has no example block"
        assert "secondeye " + command[0] in text


class TestSubcommandsAreListed:
    """A noun page's whole job is saying which verbs exist.

    The subparsers action renders as a bare metavar unless its choices
    are expanded explicitly, which silently reduces every noun page to a
    usage line and an ``-h``.
    """

    def test_root_help_names_every_noun_with_its_summary(self) -> None:
        text = _help()
        assert "Commands" in text
        for noun, phrase in [
            ("proxy", "recording proxy daemon"),
            ("capture", "recording windows"),
            ("doctor", "ready to capture"),
            ("ca", "root CA"),
        ]:
            assert noun in text
            assert phrase in text, f"{noun}'s summary is missing"

    @pytest.mark.parametrize(
        ("noun", "verbs"),
        [
            ("proxy", ("start", "stop", "status")),
            ("capture", ("start", "stop", "list", "analyze", "recover")),
            ("ca", ("export", "install", "status", "import-upstream")),
        ],
    )
    def test_each_noun_page_lists_its_verbs(self, noun: str, verbs: tuple[str, ...]) -> None:
        text = _help(noun)
        for verb in verbs:
            assert re.search(rf"^\s+{re.escape(verb)}\s", text, re.MULTILINE), (
                f"'secondeye {noun} --help' does not list {verb!r}"
            )


class TestGroupPagesAreOriented:
    @pytest.mark.parametrize("noun", ["proxy", "capture", "ca"])
    def test_a_noun_page_explains_itself_before_listing_verbs(self, noun: str) -> None:
        """A bare list of verbs doesn't say what the noun is for.

        Checked on the parser rather than the rendered text, because a
        description's absence shows up in the rendering only as a missing
        paragraph — indistinguishable from a layout change.
        """
        parser = _subparser(cli._build_parser(), noun)
        description = getattr(parser, "description", None)
        assert description, f"'secondeye {noun} --help' has no description"
        assert len(description.split()) >= 8, description

    def test_capture_commands_say_whether_a_daemon_is_needed(self) -> None:
        for verb in ("start", "stop"):
            assert "running daemon" in _description("capture", verb).lower()

    def test_daemon_free_capture_commands_still_say_so(self) -> None:
        for verb in ("analyze", "recover", "list"):
            assert "no daemon" in _description("capture", verb).lower()


class TestSuppressedFlagsStayHidden:
    def test_the_ca_install_test_seam_is_not_advertised(self) -> None:
        assert "--home" not in _help("ca", "install")


class TestHelpRendersAtAnyWidth:
    @pytest.mark.parametrize("columns", [40, 60, 80, 100, 200])
    @pytest.mark.parametrize(
        "command",
        [("proxy", "start"), ("capture", "analyze"), ("doctor",), ("ca", "install")],
    )
    def test_prose_wraps_to_the_terminal_unless_one_token_cannot(
        self, command: tuple[str, ...], columns: int
    ) -> None:
        """All prose below the usage block is wrapped to fit.

        A line may exceed the width only when it holds a single token
        that is itself wider — a long flag name or path. Those are left
        whole on purpose: ``--no-upstream`` broken across lines becomes
        ``--no-`` plus ``upstream``, which reads as something the reader
        could retype and get wrong. Overflow is the lesser harm, and the
        terminal soft-wraps it.

        The usage block and the examples are excluded here; each has its
        own test below.
        """
        screen = _help(*command, columns=columns)
        body = screen.split("Examples")[0].split("\n\n", 1)[1]
        for line in body.splitlines():
            if len(line) <= columns:
                continue
            assert len(line.split()) == 1, f"over-long line is wrappable: {line!r}"

    @pytest.mark.parametrize("columns", [40, 60, 80, 100, 200])
    def test_usage_lines_fit_unless_one_token_cannot(self, columns: int) -> None:
        """A usage line holds whole tokens or nothing.

        An alternation group like ``(--upstream-ca FILE | ... )`` is one
        indivisible token: splitting it across lines would read as two
        separate constraints. So the usage block wraps between tokens
        and, when a single token is wider than the terminal, lets that
        one line overflow rather than lie about the grammar.
        """
        usage = _help("proxy", "start", columns=columns).split("\n\n", 1)[0]
        for line in usage.splitlines():
            if len(line) <= columns:
                continue
            stripped = line.strip().removeprefix("usage: ")
            assert stripped.startswith(("(", "[")) and stripped.endswith((")", "]")), (
                f"over-long usage line is not a single token: {line!r}"
            )

    @pytest.mark.parametrize("columns", [40, 60, 200])
    def test_example_commands_are_never_wrapped(self, columns: int) -> None:
        """A wrapped command line can't be copied and run.

        Examples overflow a narrow terminal and let it soft-wrap them,
        the same call ``ui.py`` already makes for paths, regexes and
        fingerprints. Breaking one across lines would silently produce
        text that looks runnable and isn't.
        """
        examples = _help("proxy", "start", columns=columns).split("Examples", 1)[1]
        assert "secondeye proxy start --target example.com --no-upstream" in examples

    @pytest.mark.parametrize("columns", [40, 60, 80])
    def test_flag_names_are_never_truncated(self, columns: int) -> None:
        text = _help("proxy", "start", columns=columns)
        for flag in ("--upstream-insecure", "--max-connections", "--cluster-window"):
            assert flag in text, f"{flag} was truncated at {columns} columns"


class TestHelpIsPlainWhenColourIsUnwanted:
    """``--help`` is piped into docs and into grep far more than it is read.

    ``scripts/generate_doc_examples.py`` captures it with ``NO_COLOR=1``,
    so the generated blocks in ``docs/CLI.md`` only stay byte-stable while
    a non-tty render emits no escapes at all.
    """

    def test_a_subprocess_help_capture_contains_no_escape_sequences(self) -> None:
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "secondeye.cli", "proxy", "start", "--help"],
            capture_output=True,
            text=True,
            check=True,
            env={"PATH": "/usr/bin:/bin", "COLUMNS": "100", "NO_COLOR": "1"},
        )
        assert "\x1b[" not in result.stdout

    def test_the_same_capture_is_stable_across_runs(self) -> None:
        def once() -> str:
            return subprocess.run(  # noqa: S603
                [sys.executable, "-m", "secondeye.cli", "proxy", "start", "--help"],
                capture_output=True,
                text=True,
                check=True,
                env={"PATH": "/usr/bin:/bin", "COLUMNS": "100", "NO_COLOR": "1"},
            ).stdout

        assert once() == once()
