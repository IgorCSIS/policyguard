"""Rendering verdicts for whoever is reading them.

The CLI can print a table for a person or JSON for another program. Those are
two answers to the same question, so they are two implementations of one
abstract type rather than a branch in the middle of the command line code.

Adding a third format, say CSV for a spreadsheet, means writing one class and
registering it. Nothing in :mod:`policyguard.cli` has to change, and nothing
else in the package knows or cares how a verdict gets displayed.

This is also where the package demonstrates abstraction and polymorphism for
the coursework: :class:`Reporter` cannot be instantiated, it declares what
every reporter must provide, and the CLI holds one without knowing which.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Final, Mapping, Sequence

from policyguard.alert import Alert, Verdict
from policyguard.rule import Decision

#: Column widths for the text report, wide enough for the shipped sample.
_LINE_WIDTH: Final[int] = 5
_DECISION_WIDTH: Final[int] = 7
_RULE_WIDTH: Final[int] = 24

#: Printed at the end of every human readable report, so the scope of the
#: tool is restated every time somebody runs it rather than only in a README
#: they may never open.
SCOPE_NOTE: Final[str] = (
    'PolicyGuard classifies logs. It does not block, scan, or contact anything.'
)


class Reporter(ABC):
    """Turns verdicts into text for some audience.

    Abstract on purpose. A reporter that silently produced nothing would be
    worse than no reporter at all, so :meth:`render` has no default: a
    subclass has to say what it renders, and Python refuses to instantiate
    one that does not.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """str: A short name for this format, used in help text and errors."""

    @abstractmethod
    def render(
        self,
        verdicts: Sequence[Verdict],
        counts: Mapping[Decision, int],
        alerts: Sequence[Alert],
        policy_name: str,
    ) -> str:
        """Render a classification run.

        Parameters
        ----------
        verdicts : sequence of Verdict
            The lines to show. Already filtered by the caller, so a reporter
            never has to know about the ``--only`` flag.
        counts : mapping of Decision to int
            How many lines fell into each decision across the whole run, not
            just the ones being shown.
        alerts : sequence of Alert
            Every alert raised during the run.
        policy_name : str
            The rule pack that was enforced.

        Returns
        -------
        str
            The finished report, without a trailing newline.
        """

    def __str__(self) -> str:
        """Return which format this reporter produces."""
        return f'{self.name} reporter'

    def __repr__(self) -> str:
        """Return an unambiguous form for debugging."""
        return f'{type(self).__name__}()'


class TableReporter(Reporter):
    """Renders a table meant to be read by a person.

    One row per line, optionally followed by the automaton path and the
    reason, then a summary and the alert list.
    """

    __slots__ = ('_explain', '_show_stats', '_automaton_summary')

    def __init__(self, explain: bool = False, automaton_summary: str = '') -> None:
        """Configure the table.

        Parameters
        ----------
        explain : bool, optional
            Whether to print the state path and the reason under each line
            that a rule decided.
        automaton_summary : str, optional
            One line describing the compiled automaton. Printed at the end
            when given, which is what ``--stats`` asks for.
        """
        self._explain = explain
        self._automaton_summary = automaton_summary

    @property
    def name(self) -> str:
        """str: The format's name."""
        return 'table'

    @property
    def explain(self) -> bool:
        """bool: Whether paths and reasons are printed."""
        return self._explain

    def render(
        self,
        verdicts: Sequence[Verdict],
        counts: Mapping[Decision, int],
        alerts: Sequence[Alert],
        policy_name: str,
    ) -> str:
        """Render the table, the summary, and the alert list.

        Parameters
        ----------
        verdicts : sequence of Verdict
            The lines to show.
        counts : mapping of Decision to int
            Totals across the whole run.
        alerts : sequence of Alert
            Every alert raised.
        policy_name : str
            The rule pack that was enforced.

        Returns
        -------
        str
            The finished report.
        """
        header = (
            f'{"LINE":>{_LINE_WIDTH}}  {"DECISION":<{_DECISION_WIDTH}}  '
            f'{"RULE":<{_RULE_WIDTH}}  EVENT'
        )
        lines: list[str] = [header, '-' * (len(header) + 12)]

        for verdict in verdicts:
            lines.append(
                f'{verdict.event.line_number:>{_LINE_WIDTH}}  '
                f'{verdict.decision.value:<{_DECISION_WIDTH}}  '
                f'{verdict.rule_id:<{_RULE_WIDTH}}  {verdict.event.raw}'
            )
            if self._explain and verdict.rule is not None:
                pad = ' ' * _LINE_WIDTH
                lines.append(f'{pad}  path: {verdict.describe_path()}')
                lines.append(f'{pad}  why:  {verdict.reason}')

        total = sum(counts.values())
        lines.append('')
        lines.append(
            f'{total} lines classified: '
            + ', '.join(f'{counts[decision]} {decision}' for decision in Decision)
        )

        if alerts:
            lines.append('')
            lines.append(f'{len(alerts)} alert(s):')
            lines.extend(f'  {alert}' for alert in alerts)

        lines.append('')
        lines.append(SCOPE_NOTE)
        if self._automaton_summary:
            lines.append(self._automaton_summary)
        return '\n'.join(lines)


class JsonReporter(Reporter):
    """Renders JSON meant to be read by another program.

    The key names are the wire format shared with the browser demo, so the
    parity check compares these objects directly. They are a contract rather
    than a style choice, which is why they are camelCase while the rest of
    this package is not.
    """

    __slots__ = ('_indent', '_automaton_summary')

    def __init__(self, indent: int = 2, automaton_summary: str = '') -> None:
        """Configure the JSON output.

        Parameters
        ----------
        indent : int, optional
            Indentation passed to :func:`json.dumps`. Two spaces by default,
            because a person reads this during a demo as often as a program
            consumes it.
        automaton_summary : str, optional
            One line describing the compiled automaton, included under the
            ``automaton`` key when given.
        """
        self._indent = indent
        self._automaton_summary = automaton_summary

    @property
    def name(self) -> str:
        """str: The format's name."""
        return 'json'

    def render(
        self,
        verdicts: Sequence[Verdict],
        counts: Mapping[Decision, int],
        alerts: Sequence[Alert],
        policy_name: str,
    ) -> str:
        """Render the run as a JSON document.

        Parameters
        ----------
        verdicts : sequence of Verdict
            The lines to show.
        counts : mapping of Decision to int
            Totals across the whole run.
        alerts : sequence of Alert
            Every alert raised.
        policy_name : str
            The rule pack that was enforced.

        Returns
        -------
        str
            A JSON document.
        """
        payload = {
            'policy': policy_name,
            'counts': {decision.value: count for decision, count in counts.items()},
            'verdicts': [verdict.to_dict() for verdict in verdicts],
            'alerts': [alert.to_dict() for alert in alerts],
        }
        if self._automaton_summary:
            payload['automaton'] = self._automaton_summary
        return json.dumps(payload, indent=self._indent)


#: Every format the CLI can produce, by the name the ``--format`` flag uses.
#: Adding a format means adding a class and one entry here.
REPORTERS: Final[Mapping[str, type[Reporter]]] = {
    'table': TableReporter,
    'json': JsonReporter,
}
