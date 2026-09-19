"""Tests for the DFA itself.

These are the tests that matter most to the claim the project makes. If the
automaton is not deterministic, or if a token outside the alphabet can change
its state in some unexpected way, then the complexity argument in the README
is not true and neither is the state path shown with every verdict.
"""

from __future__ import annotations

import unittest

from policyguard.automaton import START_STATE, Automaton
from policyguard.errors import AutomatonError
from policyguard.rule import Decision, Rule


def _rule(rule_id: str, pattern: list[str], decision: Decision = Decision.ALERT) -> Rule:
    """Build a rule for a test.

    Parameters
    ----------
    rule_id : str
        The rule identifier.
    pattern : list of str
        The token sequence.
    decision : Decision, optional
        What the rule calls a match.

    Returns
    -------
    Rule
        The assembled rule.
    """
    return Rule(rule_id=rule_id, label=rule_id, decision=decision, pattern=pattern)


class TestCompile(unittest.TestCase):
    """Building the automaton."""

    def test_an_empty_rule_set_is_refused(self) -> None:
        """An automaton with no accepting states would call every line clean."""
        with self.assertRaises(AutomatonError):
            Automaton().compile([])

    def test_matching_before_compiling_is_refused(self) -> None:
        """Silently matching nothing is the worst failure a detector can have."""
        with self.assertRaises(AutomatonError):
            list(Automaton().match(['failed', 'password']))

    def test_shared_prefixes_share_states(self) -> None:
        """Two rules starting the same way must not duplicate the trie."""
        separate = Automaton().compile([_rule('a', ['failed', 'password'])])
        shared = Automaton().compile(
            [_rule('a', ['failed', 'password']), _rule('b', ['failed', 'publickey'])]
        )
        # One extra token of pattern, so exactly one extra state.
        self.assertEqual(shared.state_count, separate.state_count + 1)

    def test_the_alphabet_is_exactly_the_rule_tokens(self) -> None:
        """Nothing outside the rules is part of the machine's alphabet."""
        automaton = Automaton().compile([_rule('a', ['sudo', 'authentication', 'failure'])])
        self.assertEqual(automaton.alphabet, frozenset({'sudo', 'authentication', 'failure'}))

    def test_every_state_answers_every_token(self) -> None:
        """This is what makes it a DFA rather than an NFA with a fallback.

        After the failure links are folded in, one state plus one token gives
        exactly one next state, with no backtracking at match time.
        """
        automaton = Automaton().compile(
            [_rule('a', ['failed', 'password', 'for']), _rule('b', ['invalid', 'user'])]
        )
        table = {(edge.source, edge.token) for edge in automaton.transitions()}
        for state in range(automaton.state_count):
            for token in automaton.alphabet:
                self.assertIn((state, token), table, f'q{state} has no answer for {token!r}')


class TestMatching(unittest.TestCase):
    """Running lines through the machine."""

    def setUp(self) -> None:
        """Compile a small automaton used by most tests here."""
        self._automaton = Automaton().compile(
            [
                _rule('failed_password', ['failed', 'password', 'for']),
                _rule('invalid_user', ['invalid', 'user']),
                _rule('good_login', ['accepted', 'publickey'], Decision.ALLOW),
            ]
        )

    def test_a_pattern_in_the_middle_of_a_line_is_found(self) -> None:
        """Rules describe a phrase, not a whole line."""
        tokens = 'sep 19 sshd 4001 failed password for root from 10 0 0 1'.split()
        found = [match.rule.rule_id for match in self._automaton.match(tokens)]
        self.assertEqual(found, ['failed_password'])

    def test_two_rules_can_fire_on_one_line(self) -> None:
        """Overlapping detections both report rather than one hiding the other."""
        tokens = 'failed password for invalid user admin'.split()
        found = {match.rule.rule_id for match in self._automaton.match(tokens)}
        self.assertEqual(found, {'failed_password', 'invalid_user'})

    def test_unknown_tokens_cannot_derail_the_machine(self) -> None:
        """A word that appears in no rule costs one failed lookup and nothing else."""
        noise = 'zzz qqq 998877 !!! unrelated'.split()
        self.assertEqual(list(self._automaton.match(noise)), [])

        # Noise wrapped around a real pattern must not stop it matching.
        tokens = ['zzz', *'invalid user'.split(), 'qqq']
        found = [match.rule.rule_id for match in self._automaton.match(tokens)]
        self.assertEqual(found, ['invalid_user'])

    def test_empty_input_matches_nothing(self) -> None:
        """An empty line is not an error and is not a detection."""
        self.assertEqual(list(self._automaton.match([])), [])

    def test_a_partial_pattern_does_not_fire(self) -> None:
        """Two thirds of a rule is not a match."""
        tokens = 'failed password but not the rest'.split()
        self.assertEqual(list(self._automaton.match(tokens)), [])

    def test_the_reported_path_spells_out_the_rule(self) -> None:
        """The path is the rule's own states, so it is the same every time.

        A match found through a failure link is reported at a state that is
        not the rule's accepting state, so the walked states would be the
        wrong thing to show a person.
        """
        tokens = 'noise noise invalid user bob'.split()
        match = next(self._automaton.match(tokens))
        self.assertEqual(match.path[0], START_STATE)
        self.assertEqual(len(match.path), len(match.rule.pattern) + 1)
        self.assertIn('ACCEPT: invalid_user', match.describe_path())
        self.assertTrue(match.describe_path().startswith('q0 -> '))

    def test_the_same_line_always_gives_the_same_path(self) -> None:
        """Nothing here is random or order dependent."""
        tokens = 'failed password for invalid user admin'.split()
        first = [(m.rule.rule_id, m.path) for m in self._automaton.match(tokens)]
        second = [(m.rule.rule_id, m.path) for m in self._automaton.match(tokens)]
        self.assertEqual(first, second)

    def test_end_index_points_at_the_last_token_of_the_match(self) -> None:
        """Callers use this to say where in the line the rule fired."""
        tokens = 'a b invalid user'.split()
        match = next(self._automaton.match(tokens))
        self.assertEqual(match.end_index, 3)


class TestDotExport(unittest.TestCase):
    """The Graphviz export."""

    def setUp(self) -> None:
        """Compile a two rule automaton."""
        self._automaton = Automaton().compile(
            [_rule('failed_password', ['failed', 'password']), _rule('invalid_user', ['invalid', 'user'])]
        )

    def test_it_produces_a_dot_document_without_needing_graphviz(self) -> None:
        """The package returns text. Drawing it is somebody else's business."""
        dot = self._automaton.to_dot()
        self.assertTrue(dot.startswith('digraph policyguard {'))
        self.assertTrue(dot.rstrip().endswith('}'))
        self.assertIn('rankdir=LR;', dot)

    def test_accepting_states_are_labelled_with_their_rules(self) -> None:
        """A picture of the machine is only useful if the ends are named."""
        dot = self._automaton.to_dot()
        self.assertIn('failed_password', dot)
        self.assertIn('invalid_user', dot)
        self.assertIn('doubleoctagon', dot)

    def test_fallback_edges_are_left_out_unless_asked_for(self) -> None:
        """Including every folded edge is correct and unreadable."""
        lean = self._automaton.to_dot()
        dense = self._automaton.to_dot(include_fallbacks=True)
        self.assertLess(lean.count('->'), dense.count('->'))


class TestStr(unittest.TestCase):
    """Human readable forms."""

    def test_an_uncompiled_automaton_says_so(self) -> None:
        """Printing one during debugging should not look like a working machine."""
        self.assertIn('not compiled', str(Automaton()))

    def test_a_compiled_automaton_reports_its_size(self) -> None:
        """The numbers behind the complexity claim should be easy to check."""
        text = str(Automaton().compile([_rule('a', ['failed', 'password'])]))
        self.assertIn('states', text)
        self.assertIn('transitions', text)


if __name__ == '__main__':
    unittest.main()
