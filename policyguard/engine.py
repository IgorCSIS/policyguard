"""The engine that turns log lines into verdicts.

This is where the three interesting data structures meet:

* a **hash table**, the automaton's transition dictionary, doing the matching
* a **queue**, the sliding window that decides when a threshold rule fires
* a **graph**, the automaton itself, whose path is reported with each verdict

It is also where precedence lives. Several rules can match one line, so one
of them has to win. The rule is simple and is stated in the README, the CLI
help, and here: the highest priority match wins, and rules of equal priority
break the tie by their order in the pack.

The important consequence is that an explicit allow outranks an alert by
default. That is the behaviour an operator expects from an allow list, and
it is also the sharpest edge in the design, so it is written down in all
three places rather than left to be discovered.
"""

from __future__ import annotations

from collections import deque
from typing import Final, Iterable, Iterator

from policyguard.alert import Alert, Verdict
from policyguard.automaton import Automaton
from policyguard.event import Event, events_from_lines
from policyguard.rule import Decision, Rule, RulePack

#: How many recent events a threshold rule keeps per source when its rule
#: does not set a time window. Bounding this is what stops a long log from
#: growing the engine's memory without limit.
DEFAULT_WINDOW_EVENTS: Final[int] = 50


class _SlidingWindow:
    """Recent hits for one threshold rule, grouped by source.

    The queue is the point. Every time the rule's pattern is seen the event's
    position joins the back; anything that has fallen outside the window
    leaves the front. The rule fires when the queue is as long as the
    threshold. Both ends are touched in constant time, which is exactly what
    a deque is for and exactly what a list would do badly.
    """

    __slots__ = ('_threshold', '_span', '_hits')

    def __init__(self, threshold: int, span: int) -> None:
        """Create a window.

        Parameters
        ----------
        threshold : int
            How many hits are needed before the rule fires.
        span : int
            How many events wide the window is.
        """
        self._threshold = threshold
        self._span = max(span, threshold)
        self._hits: dict[str, deque[int]] = {}

    def record(self, source: str, position: int) -> int:
        """Record a hit and report how many are currently in the window.

        Parameters
        ----------
        source : str
            The address the event came from. Counting per source is what
            keeps one noisy host from tripping a rule for everyone else.
        position : int
            The event's position in the stream, counting from one.

        Returns
        -------
        int
            How many hits from this source are inside the window now.
        """
        queue = self._hits.setdefault(source, deque())
        queue.append(position)

        # Drop anything that has slid out of the window. Cheap, because only
        # the front can ever be stale.
        while queue and position - queue[0] >= self._span:
            queue.popleft()

        return len(queue)

    def is_tripped(self, count: int) -> bool:
        """Report whether a hit count is enough to fire the rule.

        Parameters
        ----------
        count : int
            The number returned by :meth:`record`.

        Returns
        -------
        bool
            Whether the rule should fire.
        """
        return count >= self._threshold

    def __str__(self) -> str:
        """Return a one-line summary for debugging output."""
        tracked = sum(len(queue) for queue in self._hits.values())
        return (
            f'window threshold={self._threshold} span={self._span} '
            f'sources={len(self._hits)} tracked={tracked}'
        )

    def __repr__(self) -> str:
        """Return an unambiguous form for debugging."""
        return f'_SlidingWindow(threshold={self._threshold}, span={self._span})'


class PolicyEngine:
    """Classifies log lines against a rule pack.

    Build one per pack. The automaton is compiled once in the constructor,
    so classifying a second file costs nothing extra.
    """

    __slots__ = ('_pack', '_automaton', '_windows', '_alerts', '_counts', '_order')

    def __init__(self, pack: RulePack) -> None:
        """Compile a pack into a ready engine.

        Parameters
        ----------
        pack : RulePack
            The rules to enforce.
        """
        self._pack = pack
        self._automaton = Automaton().compile(pack.rules)
        self._windows: dict[str, _SlidingWindow] = {
            rule.rule_id: _SlidingWindow(
                threshold=rule.threshold,
                span=rule.window_seconds or DEFAULT_WINDOW_EVENTS,
            )
            for rule in pack.rules
            if rule.is_threshold_rule
        }
        # Where each rule sits in the pack. Two rules of equal priority break
        # their tie by this, which is what the README and the CLI help both
        # promise. Without it the winner would be whichever rule happened to
        # finish earliest in the line, which is not something a rule author
        # can see or reason about.
        self._order: dict[str, int] = {
            rule.rule_id: index for index, rule in enumerate(pack.rules)
        }
        self._alerts: list[Alert] = []
        self._counts: dict[Decision, int] = {decision: 0 for decision in Decision}

    @property
    def pack(self) -> RulePack:
        """RulePack: The rules this engine enforces."""
        return self._pack

    @property
    def automaton(self) -> Automaton:
        """Automaton: The compiled DFA, for inspection and DOT export."""
        return self._automaton

    @property
    def alerts(self) -> tuple[Alert, ...]:
        """tuple of Alert: Every alert raised since the last reset."""
        return tuple(self._alerts)

    @property
    def counts(self) -> dict[Decision, int]:
        """dict: How many lines fell into each decision since the last reset."""
        return dict(self._counts)

    def reset(self) -> None:
        """Forget every alert, count, and sliding window.

        Call this between files. Without it a threshold rule would carry
        yesterday's failed logins into today's report.
        """
        self._alerts.clear()
        self._counts = {decision: 0 for decision in Decision}
        for rule in self._pack.rules:
            if rule.is_threshold_rule:
                self._windows[rule.rule_id] = _SlidingWindow(
                    threshold=rule.threshold,
                    span=rule.window_seconds or DEFAULT_WINDOW_EVENTS,
                )

    def classify(self, event: Event, position: int = 0) -> Verdict:
        """Classify one event.

        Parameters
        ----------
        event : Event
            The line to classify.
        position : int, optional
            The event's position in the stream, used by the sliding windows.
            Defaults to the event's line number.

        Returns
        -------
        Verdict
            What the line was called, and why.
        """
        index = position or event.line_number
        winner: Rule | None = None
        winning_path: tuple[int, ...] = ()
        winning_hits = 1

        for match in self._automaton.match(event.tokens):
            rule = match.rule
            hits = 1

            if rule.is_threshold_rule:
                hits = self._windows[rule.rule_id].record(event.source, index)
                if not self._windows[rule.rule_id].is_tripped(hits):
                    # Seen, counted, not yet enough to say anything about.
                    continue

            if winner is None or self._outranks(rule, winner):
                winner, winning_path, winning_hits = rule, match.path, hits

        if winner is None:
            verdict = Verdict(
                event=event,
                decision=self._pack.default_decision,
                reason='No rule matched, so the pack default applied.',
            )
        else:
            verdict = Verdict(
                event=event,
                decision=winner.decision,
                rule=winner,
                path=winning_path,
                reason=self._explain(winner, winning_hits),
            )

        self._counts[verdict.decision] += 1
        if verdict.is_alert:
            self._alerts.append(Alert(verdict, hits=winning_hits))
        return verdict

    def _outranks(self, candidate: Rule, holder: Rule) -> bool:
        """Report whether one matching rule should beat another.

        Higher priority wins. Equal priorities break the tie by order in the
        pack, earlier first, which is the only ordering a rule author can
        actually see and control.

        Parameters
        ----------
        candidate : Rule
            The rule being considered.
        holder : Rule
            The rule currently winning.

        Returns
        -------
        bool
            Whether the candidate should take over.
        """
        if candidate.priority != holder.priority:
            return candidate.priority > holder.priority
        return self._order[candidate.rule_id] < self._order[holder.rule_id]

    @staticmethod
    def _explain(rule: Rule, hits: int) -> str:
        """Write the one-line reason shown with a verdict.

        Parameters
        ----------
        rule : Rule
            The rule that decided.
        hits : int
            How many events were in the window when it fired.

        Returns
        -------
        str
            A sentence a person can read without knowing the rule pack.
        """
        if rule.description:
            base = rule.description
        else:
            base = f'Matched {" ".join(rule.pattern)}.'
        if rule.is_threshold_rule:
            return f'{base} Fired after {hits} matching events from one source.'
        return base

    def classify_events(self, events: Iterable[Event]) -> Iterator[Verdict]:
        """Classify a stream of events, skipping blank lines.

        The events are pulled through a queue rather than a list. Nothing
        here needs random access, and a deque keeps the memory flat no matter
        how long the log is, which is the point of streaming it at all.

        Parameters
        ----------
        events : iterable of Event
            The events to classify, in order.

        Yields
        ------
        Verdict
            One per non-blank line.
        """
        pending: deque[Event] = deque()
        position = 0

        for event in events:
            pending.append(event)
            while pending:
                current = pending.popleft()
                if current.is_blank:
                    continue
                position += 1
                yield self.classify(current, position=position)

    def classify_lines(self, lines: Iterable[str]) -> Iterator[Verdict]:
        """Classify raw log lines.

        Parameters
        ----------
        lines : iterable of str
            Raw lines, with or without trailing newlines. A file object works
            directly, which is what keeps memory flat on a large log.

        Returns
        -------
        iterator of Verdict
            One per non-blank line. This returns the iterator rather than
            yielding, so nothing is read until the caller starts consuming it.
        """
        return self.classify_events(events_from_lines(lines))

    def __str__(self) -> str:
        """Return a one-line summary for the report header."""
        return f'PolicyEngine over {self._pack} using {self._automaton}'

    def __repr__(self) -> str:
        """Return an unambiguous form for debugging."""
        return f'PolicyEngine(pack={self._pack.name!r}, alerts={len(self._alerts)})'
