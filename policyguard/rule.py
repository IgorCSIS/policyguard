"""Policy rules and the packs they arrive in.

A rule says: when these tokens appear in a line, call the line this. Rules
are data rather than code on purpose, so the interesting part of the project
stays the automaton and so a rule pack can be reviewed by somebody who does
not read Python.

Two kinds of rule exist, and the difference matters:

``pattern``
    Fires the moment its token sequence is seen in a single line. All of
    these compile into one shared automaton, which is why adding rules does
    not slow classification down.

``threshold``
    Fires only when its pattern has been seen a given number of times, from
    the same source, inside a sliding window. A single failed login is
    normal. Twelve of them in a minute from one address is not. The window
    is held in a queue, which is where the queue ADT earns its place in this
    project.
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Any, Final, Iterator, Mapping, Sequence

from policyguard.errors import RulePackError


class Decision(Enum):
    """What a rule says to do with a line.

    The three values are deliberately not a free-form string. A typo in a
    rule pack should fail loudly when the pack loads, not quietly produce a
    fourth category that nothing downstream knows how to report.
    """

    ALLOW = 'allow'
    ALERT = 'alert'
    IGNORE = 'ignore'

    @classmethod
    def parse(cls, value: str) -> 'Decision':
        """Turn a string from a rule pack into a decision.

        Parameters
        ----------
        value : str
            The ``decision`` field of a rule.

        Returns
        -------
        Decision
            The matching member.

        Raises
        ------
        RulePackError
            If the string is not one of the three decisions.
        """
        try:
            return cls(value.strip().lower())
        except ValueError as error:
            allowed = ', '.join(member.value for member in cls)
            raise RulePackError(
                f'Unknown decision {value!r}. Use one of: {allowed}.'
            ) from error

    def __str__(self) -> str:
        """Return the decision as it is written in a rule pack."""
        return self.value


#: Default priority per decision, used when a rule does not set one.
#:
#: An explicit allow outranks an alert. That is the allow-list behaviour a
#: policy engine is expected to have: once an operator has written down that
#: a particular pattern is their own backup job, it should stop paging them.
#: It is also the sharpest edge in the whole design, so it is written down
#: here, in the README, and in the CLI help rather than left to be discovered.
DEFAULT_PRIORITY: Final[Mapping[Decision, int]] = {
    Decision.ALLOW: 100,
    Decision.ALERT: 50,
    Decision.IGNORE: 10,
}

#: Severity labels accepted on alert rules, lowest to highest.
SEVERITIES: Final[tuple[str, ...]] = ('info', 'low', 'medium', 'high')

#: Severity used when an alert rule does not name one.
DEFAULT_SEVERITY: Final[str] = 'medium'


class Rule:
    """One policy rule.

    Immutable once built. A rule that could change after the automaton was
    compiled would make the compiled automaton a lie.
    """

    __slots__ = (
        '_rule_id',
        '_label',
        '_decision',
        '_pattern',
        '_priority',
        '_severity',
        '_description',
        '_threshold',
        '_window_seconds',
    )

    def __init__(
        self,
        rule_id: str,
        label: str,
        decision: Decision,
        pattern: Sequence[str],
        priority: int | None = None,
        severity: str = DEFAULT_SEVERITY,
        description: str = '',
        threshold: int = 1,
        window_seconds: int = 0,
    ) -> None:
        """Build a rule.

        Parameters
        ----------
        rule_id : str
            Stable identifier, unique within a pack, used in output.
        label : str
            Short human name, shown in reports.
        decision : Decision
            What to call a line this rule matches.
        pattern : sequence of str
            The token sequence to look for, already lower-cased.
        priority : int, optional
            Higher wins when several rules match one line. Defaults to the
            value in :data:`DEFAULT_PRIORITY` for the decision.
        severity : str, optional
            One of :data:`SEVERITIES`. Only meaningful on alert rules.
        description : str, optional
            One line of prose for the report and the demo page.
        threshold : int, optional
            How many matches are needed before the rule fires. One means the
            rule fires on sight.
        window_seconds : int, optional
            How wide the sliding window is, in seconds. Zero means the
            window is counted in events rather than time.

        Raises
        ------
        RulePackError
            If the pattern is empty, the identifier is blank, the threshold
            is below one, or the severity is not recognized.
        """
        if not rule_id.strip():
            raise RulePackError('Every rule needs a non-empty id.')
        cleaned = [token.strip().lower() for token in pattern if token.strip()]
        if not cleaned:
            raise RulePackError(f'Rule {rule_id!r} has an empty pattern.')
        if threshold < 1:
            raise RulePackError(f'Rule {rule_id!r} has a threshold below one.')
        if severity not in SEVERITIES:
            raise RulePackError(
                f'Rule {rule_id!r} has severity {severity!r}. '
                f'Use one of: {", ".join(SEVERITIES)}.'
            )

        self._rule_id = rule_id.strip()
        self._label = label.strip() or self._rule_id
        self._decision = decision
        self._pattern = tuple(cleaned)
        self._priority = DEFAULT_PRIORITY[decision] if priority is None else priority
        self._severity = severity
        self._description = description.strip()
        self._threshold = threshold
        self._window_seconds = max(0, window_seconds)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> 'Rule':
        """Build a rule from one entry of a rule pack.

        Parameters
        ----------
        raw : mapping
            The decoded JSON object for a single rule.

        Returns
        -------
        Rule
            The parsed rule.

        Raises
        ------
        RulePackError
            If a required field is missing or a field has the wrong type.
        """
        for field in ('id', 'decision', 'pattern'):
            if field not in raw:
                raise RulePackError(f'Rule is missing the required field {field!r}.')

        pattern = raw['pattern']
        if isinstance(pattern, str):
            pattern = pattern.split()
        if not isinstance(pattern, list):
            raise RulePackError(
                f'Rule {raw["id"]!r} has a pattern that is neither a string nor a list.'
            )

        priority = raw.get('priority')
        if priority is not None and not isinstance(priority, int):
            raise RulePackError(f'Rule {raw["id"]!r} has a non-integer priority.')

        return cls(
            rule_id=str(raw['id']),
            label=str(raw.get('label', '')),
            decision=Decision.parse(str(raw['decision'])),
            pattern=pattern,
            priority=priority,
            severity=str(raw.get('severity', DEFAULT_SEVERITY)),
            description=str(raw.get('description', '')),
            threshold=int(raw.get('threshold', 1)),
            window_seconds=int(raw.get('window_seconds', 0)),
        )

    @property
    def rule_id(self) -> str:
        """str: The rule's stable identifier."""
        return self._rule_id

    @property
    def label(self) -> str:
        """str: The rule's human readable name."""
        return self._label

    @property
    def decision(self) -> Decision:
        """Decision: What this rule calls a matching line."""
        return self._decision

    @property
    def pattern(self) -> tuple[str, ...]:
        """tuple of str: The token sequence this rule looks for."""
        return self._pattern

    @property
    def priority(self) -> int:
        """int: Higher wins when several rules match the same line."""
        return self._priority

    @property
    def severity(self) -> str:
        """str: How serious a match is. Only meaningful for alerts."""
        return self._severity

    @property
    def description(self) -> str:
        """str: One line of prose explaining why the rule exists."""
        return self._description

    @property
    def threshold(self) -> int:
        """int: How many matches are needed before the rule fires."""
        return self._threshold

    @property
    def window_seconds(self) -> int:
        """int: Width of the sliding window in seconds, or zero for events."""
        return self._window_seconds

    @property
    def is_threshold_rule(self) -> bool:
        """bool: Whether this rule needs repeats before it fires."""
        return self._threshold > 1

    def __str__(self) -> str:
        """Return the rule as a report line."""
        shape = f' x{self._threshold}' if self.is_threshold_rule else ''
        return f'{self._rule_id} [{self._decision}{shape}] {" ".join(self._pattern)}'

    def __repr__(self) -> str:
        """Return an unambiguous form for debugging."""
        return f'Rule(rule_id={self._rule_id!r}, decision={self._decision.value!r})'


class RulePack:
    """An ordered collection of rules loaded from one file.

    The pack owns identifier uniqueness. Two rules sharing an id would make
    every report ambiguous, so that is refused at load time rather than
    producing confusing output later.
    """

    __slots__ = ('_name', '_rules', '_default_decision')

    def __init__(
        self,
        rules: Sequence[Rule],
        name: str = 'rule pack',
        default_decision: Decision = Decision.IGNORE,
    ) -> None:
        """Build a pack.

        Parameters
        ----------
        rules : sequence of Rule
            The rules, in the order they appeared in the file. Order breaks
            ties between rules of equal priority.
        name : str, optional
            A human name for the pack, shown in reports.
        default_decision : Decision, optional
            What to call a line that no rule matches. Defaults to ignore,
            because calling every unmatched line an alert would bury the
            real ones.

        Raises
        ------
        RulePackError
            If the pack is empty or two rules share an identifier.
        """
        if not rules:
            raise RulePackError('A rule pack needs at least one rule.')

        seen: set[str] = set()
        for rule in rules:
            if rule.rule_id in seen:
                raise RulePackError(f'Duplicate rule id {rule.rule_id!r} in the pack.')
            seen.add(rule.rule_id)

        self._rules = tuple(rules)
        self._name = name.strip() or 'rule pack'
        self._default_decision = default_decision

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any], name: str = '') -> 'RulePack':
        """Build a pack from a decoded rule pack document.

        Parameters
        ----------
        raw : mapping
            The decoded JSON document.
        name : str, optional
            Falls back to the ``name`` field of the document.

        Returns
        -------
        RulePack
            The parsed pack.

        Raises
        ------
        RulePackError
            If the document has no ``rules`` list, or any rule is invalid.
        """
        rules_raw = raw.get('rules')
        if not isinstance(rules_raw, list):
            raise RulePackError('A rule pack needs a "rules" list.')

        default_raw = raw.get('default_decision', Decision.IGNORE.value)
        return cls(
            rules=[Rule.from_dict(entry) for entry in rules_raw],
            name=name or str(raw.get('name', 'rule pack')),
            default_decision=Decision.parse(str(default_raw)),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> 'RulePack':
        """Load a pack from a JSON file.

        Parameters
        ----------
        path : str or Path
            The rule pack to read.

        Returns
        -------
        RulePack
            The parsed pack.

        Raises
        ------
        RulePackError
            If the file is missing, unreadable, or not valid JSON.
        """
        target = Path(path)
        try:
            text = target.read_text(encoding='utf-8')
        except FileNotFoundError as error:
            raise RulePackError(f'No rule pack at {target}.') from error
        except OSError as error:
            raise RulePackError(f'Could not read {target}: {error}') from error

        try:
            document = json.loads(text)
        except json.JSONDecodeError as error:
            raise RulePackError(f'{target} is not valid JSON: {error}') from error

        if not isinstance(document, dict):
            raise RulePackError(f'{target} should contain a JSON object.')

        return cls.from_dict(document, name=str(document.get('name', target.stem)))

    @property
    def name(self) -> str:
        """str: The pack's human readable name."""
        return self._name

    @property
    def rules(self) -> tuple[Rule, ...]:
        """tuple of Rule: The rules, in file order."""
        return self._rules

    @property
    def default_decision(self) -> Decision:
        """Decision: What an unmatched line is called."""
        return self._default_decision

    def __len__(self) -> int:
        """Return how many rules the pack holds."""
        return len(self._rules)

    def __iter__(self) -> Iterator[Rule]:
        """Iterate the rules in file order."""
        return iter(self._rules)

    def __str__(self) -> str:
        """Return a one-line summary for the report header."""
        kinds = {decision: 0 for decision in Decision}
        for rule in self._rules:
            kinds[rule.decision] += 1
        counts = ', '.join(f'{kinds[decision]} {decision}' for decision in Decision)
        return f'{self._name}: {len(self._rules)} rules ({counts})'

    def __repr__(self) -> str:
        """Return an unambiguous form for debugging."""
        return f'RulePack(name={self._name!r}, rules={len(self._rules)})'
