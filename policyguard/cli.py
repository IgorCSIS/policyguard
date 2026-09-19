"""The command line interface.

Reads a log, classifies it against a rule pack, and prints either a table a
person can read or JSON another program can consume. Nothing here opens a
socket: the whole tool reads files and writes to standard output.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Final, Iterator, Sequence, TextIO

from policyguard import __version__
from policyguard.alert import Verdict
from policyguard.engine import PolicyEngine
from policyguard.errors import LogSourceError, PolicyGuardError
from policyguard.rule import Decision, RulePack

#: Where the shipped rule pack and sample log live, relative to the repo root.
_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
DEFAULT_POLICY: Final[Path] = _ROOT / 'policies' / 'baseline.json'
DEFAULT_SAMPLE: Final[Path] = _ROOT / 'samples' / 'office-auth.log'

#: Process exit codes. The third is what makes --fail-on-alert useful in CI.
EXIT_OK: Final[int] = 0
EXIT_ERROR: Final[int] = 1
EXIT_ALERTS_FOUND: Final[int] = 2

#: Column widths for the text report.
_LINE_WIDTH: Final[int] = 5
_DECISION_WIDTH: Final[int] = 7
_RULE_WIDTH: Final[int] = 24


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


def _print_table(verdicts: Sequence[Verdict], stream: TextIO, explain: bool) -> None:
    """Print the verdicts as a readable table.

    Parameters
    ----------
    verdicts : sequence of Verdict
        The classified lines.
    stream : TextIO
        Where to write.
    explain : bool
        Whether to print the automaton path under each matched line.
    """
    header = (
        f'{"LINE":>{_LINE_WIDTH}}  {"DECISION":<{_DECISION_WIDTH}}  '
        f'{"RULE":<{_RULE_WIDTH}}  EVENT'
    )
    print(header, file=stream)
    print('-' * (len(header) + 12), file=stream)

    for verdict in verdicts:
        raw = verdict.event.raw
        print(
            f'{verdict.event.line_number:>{_LINE_WIDTH}}  '
            f'{verdict.decision.value:<{_DECISION_WIDTH}}  '
            f'{verdict.rule_id:<{_RULE_WIDTH}}  {raw}',
            file=stream,
        )
        if explain and verdict.rule is not None:
            print(f'{"":>{_LINE_WIDTH}}  path: {verdict.describe_path()}', file=stream)
            print(f'{"":>{_LINE_WIDTH}}  why:  {verdict.reason}', file=stream)


def _print_summary(engine: PolicyEngine, stream: TextIO) -> None:
    """Print the counts and the alert list.

    Parameters
    ----------
    engine : PolicyEngine
        The engine that did the classifying.
    stream : TextIO
        Where to write.
    """
    counts = engine.counts
    total = sum(counts.values())
    print('', file=stream)
    print(
        f'{total} lines classified: '
        + ', '.join(f'{counts[decision]} {decision}' for decision in Decision),
        file=stream,
    )

    if engine.alerts:
        print('', file=stream)
        print(f'{len(engine.alerts)} alert(s):', file=stream)
        for alert in engine.alerts:
            print(f'  {alert}', file=stream)
    print('', file=stream)
    print(
        'PolicyGuard classifies logs. It does not block, scan, or contact anything.',
        file=stream,
    )


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
        '--json',
        action='store_true',
        help='Print the verdicts as JSON instead of a table (used by the parity check)',
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

    if args.json:
        payload = {
            'policy': pack.name,
            'counts': {decision.value: count for decision, count in engine.counts.items()},
            'verdicts': [verdict.to_dict() for verdict in shown],
        }
        print(json.dumps(payload, indent=2))
    else:
        _print_table(shown, sys.stdout, explain=args.explain)
        _print_summary(engine, sys.stdout)
        if args.stats:
            print(f'{engine.automaton}', file=sys.stdout)

    if args.fail_on_alert and engine.alerts:
        return EXIT_ALERTS_FOUND
    return EXIT_OK
