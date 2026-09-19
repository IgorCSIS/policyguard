"""The command line interface.

Reads a log, classifies it against a rule pack, and prints either a table a
person can read or JSON another program can consume. Nothing here opens a
socket: the whole tool reads files and writes to standard output.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Final, Iterator, Sequence

from policyguard import __version__
from policyguard.engine import PolicyEngine
from policyguard.errors import LogSourceError, PolicyGuardError
from policyguard.report import REPORTERS, Reporter
from policyguard.rule import Decision, RulePack

#: Where the shipped rule pack and sample log live, relative to the repo root.
_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
DEFAULT_POLICY: Final[Path] = _ROOT / 'policies' / 'baseline.json'
DEFAULT_SAMPLE: Final[Path] = _ROOT / 'samples' / 'office-auth.log'

#: Process exit codes. The third is what makes --fail-on-alert useful in CI.
EXIT_OK: Final[int] = 0
EXIT_ERROR: Final[int] = 1
EXIT_ALERTS_FOUND: Final[int] = 2


def _read_lines(path: str | None) -> Iterator[str]:
    """Yield lines from a file, or from standard input when asked.

    Parameters
    ----------
    path : str or None
        The log file to read. ``-`` or ``None`` means standard input.

    Yields
    ------
    str
        One line at a time, so a large log never has to fit in memory.

    Raises
    ------
    LogSourceError
        If the file is missing or cannot be decoded as text.
    """
    if path is None or path == '-':
        yield from sys.stdin
        return

    target = Path(path)
    try:
        with target.open('r', encoding='utf-8', errors='replace') as handle:
            yield from handle
    except FileNotFoundError as error:
        raise LogSourceError(f'No log file at {target}.') from error
    except OSError as error:
        raise LogSourceError(f'Could not read {target}: {error}') from error


def _build_reporter(args: argparse.Namespace, automaton_summary: str) -> Reporter:
    """Choose the reporter the flags ask for.

    ``--json`` is kept as a shorthand for ``--format json`` because the parity
    check and anything else scripted against this tool already use it, and
    breaking them to tidy up an interface would be a poor trade.

    Parameters
    ----------
    args : argparse.Namespace
        The parsed command line.
    automaton_summary : str
        One line describing the compiled automaton, included when ``--stats``
        was given.

    Returns
    -------
    Reporter
        A reporter ready to render the run.
    """
    summary = automaton_summary if args.stats else ''
    if args.json or args.format == 'json':
        return REPORTERS['json'](automaton_summary=summary)
    return REPORTERS['table'](explain=args.explain, automaton_summary=summary)


def build_parser() -> argparse.ArgumentParser:
    """Define the command line interface.

    Returns
    -------
    argparse.ArgumentParser
        The configured parser.
    """
    parser = argparse.ArgumentParser(
        prog='policyguard',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            'Classify log lines against a policy rule pack compiled into a DFA. '
            'Reads files, writes a report, and makes no network calls.'
        ),
        epilog=(
            'Precedence: when several rules match one line, the highest priority\n'
            'wins, and equal priorities break the tie by order in the pack. An\n'
            'explicit allow outranks an alert by default, which is how an allow\n'
            'list is meant to behave.'
        ),
    )
    parser.add_argument(
        'logfile',
        nargs='?',
        default=None,
        help=f'Log file to classify. Use - for standard input. Default: {DEFAULT_SAMPLE.name}',
    )
    parser.add_argument(
        '-p',
        '--policy',
        default=str(DEFAULT_POLICY),
        help=f'Rule pack to enforce (default: {DEFAULT_POLICY.name})',
    )
    parser.add_argument(
        '--explain',
        action='store_true',
        help='Print the automaton state path and the reason under each matched line',
    )
    parser.add_argument(
        '--only',
        choices=[decision.value for decision in Decision],
        help='Show only lines with this decision',
    )
    parser.add_argument(
        '-f',
        '--format',
        choices=sorted(REPORTERS),
        default='table',
        help='How to print the verdicts (default: table)',
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Shorthand for --format json, which is what the parity check uses',
    )
    parser.add_argument(
        '--dot',
        metavar='FILE',
        help='Write the compiled automaton to a Graphviz DOT file and exit',
    )
    parser.add_argument(
        '--fail-on-alert',
        action='store_true',
        help=f'Exit with status {EXIT_ALERTS_FOUND} if any line is an alert',
    )
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Print the compiled automaton size alongside the summary',
    )
    parser.add_argument('--version', action='version', version=f'policyguard {__version__}')
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line tool.

    Parameters
    ----------
    argv : sequence of str, optional
        Arguments to parse. Defaults to ``sys.argv[1:]``.

    Returns
    -------
    int
        ``EXIT_OK`` on success, ``EXIT_ALERTS_FOUND`` when alerts were found
        and ``--fail-on-alert`` was given, ``EXIT_ERROR`` on a usage problem.
    """
    args = build_parser().parse_args(argv)

    try:
        pack = RulePack.from_file(args.policy)
        engine = PolicyEngine(pack)

        if args.dot:
            Path(args.dot).write_text(engine.automaton.to_dot(), encoding='utf-8')
            print(f'Wrote {args.dot}: {engine.automaton}')
            return EXIT_OK

        source = args.logfile
        if source is None:
            source = str(DEFAULT_SAMPLE)
        verdicts = list(engine.classify_lines(_read_lines(source)))
    except PolicyGuardError as error:
        print(f'Error: {error}', file=sys.stderr)
        return EXIT_ERROR

    shown = verdicts
    if args.only:
        wanted = Decision.parse(args.only)
        shown = [verdict for verdict in verdicts if verdict.decision is wanted]

    # The CLI holds a Reporter without knowing which one. Adding a format
    # means adding a class in report.py, not a branch here.
    reporter: Reporter = _build_reporter(args, str(engine.automaton))
    print(reporter.render(shown, engine.counts, engine.alerts, pack.name))

    if args.fail_on_alert and engine.alerts:
        return EXIT_ALERTS_FOUND
    return EXIT_OK
