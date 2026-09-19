"""The deterministic finite automaton that does the matching.

The model, stated plainly
-------------------------
Every rule is a sequence of tokens. All of the sequences are compiled into
one automaton built the Aho-Corasick way:

1. **Trie.** Each rule's token sequence is threaded into a prefix tree. Every
   node of that tree is a state. State ``0`` is the start.
2. **Failure links.** A breadth-first pass over the trie gives every state a
   fallback: the state representing the longest proper suffix of what has
   been read that is still a prefix of some rule. The queue that drives this
   pass is a ``collections.deque``.
3. **Goto completion.** Those failure links are then folded into the
   transition table itself, so every state has an answer for every token it
   can see. That last step is what makes this a genuine DFA rather than an
   NFA with a fallback rule: from any state, one token gives exactly one
   next state, with no backtracking ever.

Why this matters for the complexity
-----------------------------------
Matching one line costs one table lookup per token. It does not get slower
as rules are added. Classifying ``n`` lines of ``m`` tokens each is
``O(n * m + z)`` where ``z`` is the number of matches reported, no matter
whether the pack holds five rules or five hundred. Building the automaton is
``O(t)`` in the total number of tokens across all patterns.

The transition table is a ``dict`` keyed by ``(state, token)``. That is the
hash table this project is built on: the average constant-time lookup is
exactly the property that makes the bound above hold.
"""

from __future__ import annotations

from collections import deque
from typing import Final, Iterator, Sequence

from policyguard.errors import AutomatonError
from policyguard.rule import Rule
from policyguard.transition import Transition

#: The start state. Reading nothing leaves the automaton here.
START_STATE: Final[int] = 0


class Match:
    """One rule firing at one position in a line.

    Carries the path the automaton walked to get there, because a decision a
    person cannot retrace is a decision they cannot trust.
    """

    __slots__ = ('_rule', '_end_index', '_path')

    def __init__(self, rule: Rule, end_index: int, path: Sequence[int]) -> None:
        """Record a match.

        Parameters
        ----------
        rule : Rule
            The rule that fired.
        end_index : int
            Index of the token that completed the pattern, counting from zero.
        path : sequence of int
            The rule's own path down the trie, from the start state to its
            accepting state.
        """
        self._rule = rule
        self._end_index = end_index
        self._path = tuple(path)

    @property
    def rule(self) -> Rule:
        """Rule: The rule that fired."""
        return self._rule

    @property
    def end_index(self) -> int:
        """int: Index of the token that completed the pattern."""
        return self._end_index

    @property
    def path(self) -> tuple[int, ...]:
        """tuple of int: The states walked, start first."""
        return self._path

    def describe_path(self) -> str:
        """Render the path the way ``--explain`` prints it.

        Returns
        -------
        str
            Something like ``q0 -> q4 -> q7 -> ACCEPT: brute_force_ssh``.
        """
        states = ' -> '.join(f'q{state}' for state in self._path)
        return f'{states} -> ACCEPT: {self._rule.rule_id}'

    def __str__(self) -> str:
        """Return the path description."""
        return self.describe_path()

    def __repr__(self) -> str:
        """Return an unambiguous form for debugging."""
        return f'Match(rule={self._rule.rule_id!r}, end_index={self._end_index})'


class Automaton:
    """A DFA compiled from a set of rule patterns.

    Build it once, run every line through it. The class refuses to match
    before anything has been compiled, because an automaton with no accepting
    states would silently call every line clean, which is the worst possible
    failure for a security tool.
    """

    __slots__ = (
        '_goto',
        '_failure',
        '_outputs',
        '_state_count',
        '_compiled',
        '_alphabet',
        '_rule_paths',
    )

    def __init__(self) -> None:
        """Create an empty automaton holding only the start state."""
        # The transition table. Keyed by (state, token) so a lookup is one
        # hash of a small tuple rather than a walk down a list of edges.
        self._goto: dict[tuple[int, str], int] = {}
        self._failure: dict[int, int] = {}
        self._outputs: dict[int, list[Rule]] = {}
        self._alphabet: set[str] = set()
        # Each rule's own path down the trie, recorded while it is threaded
        # in. A match found through a failure link is reported at a state
        # that is not the rule's accepting state, so the walked states are
        # the wrong thing to show a person. This is the right thing: the
        # states that spell out that rule's pattern.
        self._rule_paths: dict[str, tuple[int, ...]] = {}
        self._state_count = 1
        self._compiled = False

    @property
    def state_count(self) -> int:
        """int: How many states the automaton has."""
        return self._state_count

    @property
    def transition_count(self) -> int:
        """int: How many edges the transition table holds."""
        return len(self._goto)

    @property
    def alphabet(self) -> frozenset[str]:
        """frozenset of str: Every token that appears in some rule.

        Tokens outside this set cannot change the automaton's state, which is
        why an unknown word in a log line costs one failed lookup and nothing
        more.
        """
        return frozenset(self._alphabet)

    @property
    def is_compiled(self) -> bool:
        """bool: Whether :meth:`compile` has run."""
        return self._compiled

    def compile(self, rules: Sequence[Rule]) -> 'Automaton':
        """Build the automaton from a set of rules.

        Runs the three steps described at the top of this module: thread each
        pattern into the trie, walk the trie breadth first to compute failure
        links, and fold those links into the transition table so the result
        is deterministic.

        Parameters
        ----------
        rules : sequence of Rule
            The rules to compile. Order does not matter here: precedence is
            settled later, by the engine, using rule priority.

        Returns
        -------
        Automaton
            This automaton, so a caller can build and use it in one line.

        Raises
        ------
        AutomatonError
            If no rules were given.
        """
        if not rules:
            raise AutomatonError('Cannot compile an automaton from zero rules.')

        self._build_trie(rules)
        self._link_failures()
        self._compiled = True
        return self

    def _build_trie(self, rules: Sequence[Rule]) -> None:
        """Thread every rule pattern into the prefix tree.

        Patterns that share a prefix share states, which is what keeps the
        automaton small when a pack has many similar rules.

        Parameters
        ----------
        rules : sequence of Rule
            The rules to add.
        """
        for rule in rules:
            state = START_STATE
            walked = [START_STATE]
            for token in rule.pattern:
                self._alphabet.add(token)
                key = (state, token)
                if key not in self._goto:
                    self._goto[key] = self._state_count
                    self._state_count += 1
                state = self._goto[key]
                walked.append(state)
            self._outputs.setdefault(state, []).append(rule)
            self._rule_paths[rule.rule_id] = tuple(walked)

    def _link_failures(self) -> None:
        """Compute failure links, then fold them into the transition table.

        The breadth-first order is what makes this correct: a state's failure
        link is only computable once its parent's is known, and a queue
        visits parents before children by construction.
        """
        pending: deque[int] = deque()

        # Sorted rather than raw set order. Python randomizes string hashing
        # between runs, so iterating the set directly would build a machine
        # that is correct but not identical twice in a row. A DOT export and a
        # cross-language parity check both want the same bytes every time.
        ordered = sorted(self._alphabet)

        # Depth one falls back to the start. Nothing shorter exists.
        for token in ordered:
            key = (START_STATE, token)
            if key in self._goto:
                child = self._goto[key]
                self._failure[child] = START_STATE
                pending.append(child)

        while pending:
            state = pending.popleft()
            for token in ordered:
                key = (state, token)
                if key in self._goto:
                    child = self._goto[key]
                    self._failure[child] = self._goto.get(
                        (self._failure[state], token), START_STATE
                    )
                    # A state inherits the matches of the state it falls back
                    # to, so overlapping rules all report rather than the
                    # longest one hiding the others.
                    inherited = self._outputs.get(self._failure[child])
                    if inherited:
                        own = self._outputs.setdefault(child, [])
                        seen = {rule.rule_id for rule in own}
                        own.extend(
                            rule for rule in inherited if rule.rule_id not in seen
                        )
                    pending.append(child)
                else:
                    # Fold the fallback in. After this the table answers every
                    # (state, token) pair in the alphabet, so matching never
                    # has to follow a failure link at run time.
                    self._goto[key] = self._goto.get(
                        (self._failure[state], token), START_STATE
                    )

        # Finish the start state too. Every other state was completed by the
        # loop above, but the start state is never anybody's child, so a token
        # it cannot advance on had no entry at all. Reading it already landed
        # back here through the lookup default, so this changes no behaviour.
        # It is written down because the claim being made is that the table is
        # total, and a claim worth making in a README is worth being true.
        for token in ordered:
            self._goto.setdefault((START_STATE, token), START_STATE)

    def match(self, tokens: Sequence[str]) -> Iterator[Match]:
        """Run one line's tokens through the automaton.

        Parameters
        ----------
        tokens : sequence of str
            The normalized tokens of a single log line.

        Yields
        ------
        Match
            One per rule firing, in the order the firings complete.

        Raises
        ------
        AutomatonError
            If the automaton has not been compiled yet.
        """
        if not self._compiled:
            raise AutomatonError('Compile the automaton before matching against it.')

        state = START_STATE
        for index, token in enumerate(tokens):
            # One dictionary lookup per token. A token that appears in no rule
            # is absent from the table and drops the automaton back to the
            # start, which is the correct behaviour and costs the same.
            state = self._goto.get((state, token), START_STATE)

            for rule in self._outputs.get(state, ()):
                yield Match(
                    rule,
                    end_index=index,
                    path=self._rule_paths.get(rule.rule_id, (START_STATE, state)),
                )

    def transitions(self) -> Iterator[Transition]:
        """Yield every edge of the transition table.

        Used by the DOT export and by tests that assert on the shape of the
        compiled automaton.

        Yields
        ------
        Transition
            One per entry in the table, in no particular order.
        """
        for (source, token), target in self._goto.items():
            yield Transition(source, token, target)

    def accepting_states(self) -> dict[int, tuple[Rule, ...]]:
        """Return the states that report a match, and what they report.

        Returns
        -------
        dict
            Mapping of state number to the rules that fire there.
        """
        return {state: tuple(rules) for state, rules in self._outputs.items()}

    def to_dot(self, *, include_fallbacks: bool = False) -> str:
        """Render the automaton as a Graphviz DOT document.

        Nothing in this package needs Graphviz installed. This returns text,
        and whether anybody draws it is their business.

        Parameters
        ----------
        include_fallbacks : bool, optional
            Whether to draw the folded fallback edges as well as the trie
            edges. Off by default: including them is correct but produces a
            dense graph that is hard to read, since every state has an edge
            for every token in the alphabet.

        Returns
        -------
        str
            A DOT document.
        """
        accepting = self.accepting_states()
        lines = [
            'digraph policyguard {',
            '  rankdir=LR;',
            '  node [shape=circle, fontname="monospace"];',
            f'  q{START_STATE} [shape=doublecircle];',
        ]

        for state, rules in sorted(accepting.items()):
            labels = ', '.join(rule.rule_id for rule in rules)
            lines.append(
                f'  q{state} [shape=doubleoctagon, label="q{state}\\n{labels}"];'
            )

        # A trie edge is one where the target's own failure link is not the
        # source: fallback edges were folded in later and point sideways.
        for transition in sorted(
            self.transitions(), key=lambda edge: (edge.source, edge.token)
        ):
            is_trie_edge = self._failure.get(transition.target, START_STATE) != transition.target
            is_forward = transition.target > transition.source
            if not include_fallbacks and not (is_trie_edge and is_forward):
                continue
            lines.append(
                f'  q{transition.source} -> q{transition.target} '
                f'[label="{transition.token}"];'
            )

        lines.append('}')
        return '\n'.join(lines)

    def __str__(self) -> str:
        """Return a one-line summary for the report header."""
        if not self._compiled:
            return 'Automaton (not compiled)'
        return (
            f'Automaton: {self._state_count} states, '
            f'{len(self._goto)} transitions, '
            f'{len(self._alphabet)} tokens in the alphabet'
        )

    def __repr__(self) -> str:
        """Return an unambiguous form for debugging."""
        return f'Automaton(states={self._state_count}, compiled={self._compiled})'
