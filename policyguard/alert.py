"""What the engine hands back for each line.

Two records live here and the difference is deliberate.

:class:`Verdict`
    Produced for every line, whatever the outcome. It is the row in the
    report and the row in the demo table.

:class:`Alert`
    Produced only when a verdict is an alert. It carries the extra context a
    person needs to act: severity, the source the line came from, and how
    many events it took to trip a threshold rule.

Keeping them apart means the alert list is the alert list, rather than
something a caller has to filter a bag of verdicts to obtain.
"""

from __future__ import annotations

from typing import Any

from policyguard.event import Event
from policyguard.rule import Decision, Rule


class Verdict:
    """The classification of one log line.

    Immutable. A verdict is the record of a decision that was already made,
    so nothing downstream should be able to edit it.
    """

    __slots__ = ('_event', '_decision', '_rule', '_path', '_reason')

    def __init__(
        self,
        event: Event,
        decision: Decision,
        rule: Rule | None = None,
        path: tuple[int, ...] = (),
        reason: str = '',
    ) -> None:
        """Record a decision about one line.

        Parameters
        ----------
        event : Event
            The line being classified.
        decision : Decision
            What the line was called.
        rule : Rule, optional
            The rule that decided it. ``None`` when nothing matched and the
            pack's default applied.
        path : tuple of int, optional
            The automaton states that spell out the matching rule.
        reason : str, optional
            One line of prose explaining the decision.
        """
        self._event = event
        self._decision = decision
        self._rule = rule
        self._path = tuple(path)
        self._reason = reason

    @property
    def event(self) -> Event:
        """Event: The line this verdict is about."""
        return self._event

    @property
    def decision(self) -> Decision:
        """Decision: What the line was called."""
        return self._decision

    @property
    def rule(self) -> Rule | None:
        """Rule or None: The rule that decided, if any matched."""
        return self._rule

    @property
    def path(self) -> tuple[int, ...]:
        """tuple of int: The states that spell out the matching rule."""
        return self._path

    @property
    def reason(self) -> str:
        """str: One line of prose explaining the decision."""
        return self._reason

    @property
    def rule_id(self) -> str:
        """str: The deciding rule's id, or ``default`` when none matched."""
        return self._rule.rule_id if self._rule else 'default'

    @property
    def is_alert(self) -> bool:
        """bool: Whether this line needs somebody to look at it."""
        return self._decision is Decision.ALERT

    def describe_path(self) -> str:
        """Render the state path the way ``--explain`` prints it.

        Returns
        -------
        str
            Something like ``q0 -> q4 -> q7 -> ACCEPT: brute_force_ssh``, or
            a note that no rule matched.
        """
        if not self._path or self._rule is None:
            return 'q0 (no rule matched, pack default applied)'
        states = ' -> '.join(f'q{state}' for state in self._path)
        return f'{states} -> ACCEPT: {self._rule.rule_id}'

    def to_dict(self) -> dict[str, Any]:
        """Return the verdict as plain data.

        This is the wire format shared with the browser demo. The parity
        check compares these dictionaries against the TypeScript matcher's
        output, so the key names are a contract and not a style choice.

        Returns
        -------
        dict
            A JSON-serializable view of the verdict.
        """
        return {
            'line': self._event.line_number,
            'raw': self._event.raw,
            'decision': self._decision.value,
            'ruleId': self.rule_id,
            'ruleLabel': self._rule.label if self._rule else '',
            'severity': self._rule.severity if self._rule and self.is_alert else '',
            'path': list(self._path),
            'pathText': self.describe_path(),
            'reason': self._reason,
            'source': self._event.source,
        }

    def __str__(self) -> str:
        """Return the line as the text report prints it."""
        return (
            f'{self._event.line_number:>4}  {self._decision.value:<6}  '
            f'{self.rule_id:<22}  {self._event.raw}'
        )

    def __repr__(self) -> str:
        """Return an unambiguous form for debugging."""
        return (
            f'Verdict(line={self._event.line_number}, '
            f'decision={self._decision.value!r}, rule={self.rule_id!r})'
        )


class Alert:
    """A verdict that needs a person to look at it.

    Built from a verdict rather than replacing it, so the report can show
    every line while the alert list stays short.
    """

    __slots__ = ('_verdict', '_hits')

    def __init__(self, verdict: Verdict, hits: int = 1) -> None:
        """Raise an alert for a verdict.

        Parameters
        ----------
        verdict : Verdict
            The verdict this alert is about. Must be an alert verdict.
        hits : int, optional
            How many matching events were in the window when the rule fired.
            One for a rule that fires on sight.

        Raises
        ------
        ValueError
            If the verdict is not an alert, since an alert about an allowed
            line would be a contradiction that hides a bug.
        """
        if not verdict.is_alert:
            raise ValueError(
                f'Cannot raise an alert for a {verdict.decision} verdict on line '
                f'{verdict.event.line_number}.'
            )
        self._verdict = verdict
        self._hits = max(1, hits)

    @property
    def verdict(self) -> Verdict:
        """Verdict: The verdict this alert reports."""
        return self._verdict

    @property
    def hits(self) -> int:
        """int: How many matching events were in the window."""
        return self._hits

    @property
    def severity(self) -> str:
        """str: How serious the deciding rule says this is."""
        return self._verdict.rule.severity if self._verdict.rule else 'medium'

    @property
    def source(self) -> str:
        """str: The address the line came from, or ``-``."""
        return self._verdict.event.source

    def to_dict(self) -> dict[str, Any]:
        """Return the alert as plain data.

        Returns
        -------
        dict
            The verdict's fields plus the alert-only ones.
        """
        payload = self._verdict.to_dict()
        payload['hits'] = self._hits
        return payload

    def __str__(self) -> str:
        """Return the alert as the summary section prints it."""
        window = f' after {self._hits} events' if self._hits > 1 else ''
        return (
            f'[{self.severity}] line {self._verdict.event.line_number} '
            f'{self._verdict.rule_id} from {self.source}{window}'
        )

    def __repr__(self) -> str:
        """Return an unambiguous form for debugging."""
        return f'Alert(rule={self._verdict.rule_id!r}, hits={self._hits})'
