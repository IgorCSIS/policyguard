"""Tests for rules and rule packs.

A rule pack is the part of this project a person edits, so the failures that
matter are the ones caused by a typo. Every one of them should be refused
when the pack loads, with a message naming the rule, rather than producing a
quietly wrong classification hours later.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from policyguard.errors import RulePackError
from policyguard.rule import DEFAULT_PRIORITY, Decision, Rule, RulePack


class TestDecision(unittest.TestCase):
    """The three decisions."""

    def test_the_spellings_a_pack_may_use_are_accepted(self) -> None:
        """Case and surrounding space are a typo, not a new category."""
        self.assertIs(Decision.parse('alert'), Decision.ALERT)
        self.assertIs(Decision.parse('  ALLOW '), Decision.ALLOW)

    def test_a_fourth_decision_is_refused_with_the_valid_ones_named(self) -> None:
        """A typo must not create a category nothing downstream can report."""
        with self.assertRaises(RulePackError) as caught:
            Decision.parse('block')
        self.assertIn('allow', str(caught.exception))
        self.assertIn('alert', str(caught.exception))


class TestRule(unittest.TestCase):
    """A single rule."""

    def test_a_pattern_is_normalized_on_the_way_in(self) -> None:
        """Rule authors should not have to think about case."""
        rule = Rule('r', 'label', Decision.ALERT, ['Failed', ' PASSWORD ', 'for'])
        self.assertEqual(rule.pattern, ('failed', 'password', 'for'))

    def test_an_empty_pattern_is_refused(self) -> None:
        """A rule that matches nothing is always a mistake."""
        with self.assertRaises(RulePackError):
            Rule('r', 'label', Decision.ALERT, [])
        with self.assertRaises(RulePackError):
            Rule('r', 'label', Decision.ALERT, ['  ', ''])

    def test_a_blank_id_is_refused(self) -> None:
        """Every report line names a rule, so every rule needs a name."""
        with self.assertRaises(RulePackError):
            Rule('   ', 'label', Decision.ALERT, ['failed'])

    def test_an_unknown_severity_is_refused_and_names_the_valid_ones(self) -> None:
        """Severity drives triage, so a typo there is worth stopping for."""
        with self.assertRaises(RulePackError) as caught:
            Rule('r', 'label', Decision.ALERT, ['failed'], severity='catastrophic')
        self.assertIn('medium', str(caught.exception))

    def test_a_threshold_below_one_is_refused(self) -> None:
        """A rule that fires after zero events is not a rule."""
        with self.assertRaises(RulePackError):
            Rule('r', 'label', Decision.ALERT, ['failed'], threshold=0)

    def test_priority_defaults_by_decision_and_allow_outranks_alert(self) -> None:
        """This is the sharpest edge in the design, so it is pinned by a test."""
        allow = Rule('a', 'a', Decision.ALLOW, ['x'])
        alert = Rule('b', 'b', Decision.ALERT, ['y'])
        ignore = Rule('c', 'c', Decision.IGNORE, ['z'])
        self.assertEqual(allow.priority, DEFAULT_PRIORITY[Decision.ALLOW])
        self.assertGreater(allow.priority, alert.priority)
        self.assertGreater(alert.priority, ignore.priority)

    def test_an_explicit_priority_wins_over_the_default(self) -> None:
        """Tuning a noisy detection is the whole reason priority is editable."""
        rule = Rule('c', 'c', Decision.IGNORE, ['z'], priority=999)
        self.assertEqual(rule.priority, 999)

    def test_a_rule_cannot_be_edited_after_the_automaton_is_built(self) -> None:
        """A compiled automaton would become a lie."""
        rule = Rule('r', 'label', Decision.ALERT, ['failed'])
        with self.assertRaises(AttributeError):
            rule.pattern = ('something', 'else')  # type: ignore[misc]

    def test_from_dict_accepts_a_pattern_written_as_a_string(self) -> None:
        """Rule packs are written by hand, so the friendly spelling works."""
        rule = Rule.from_dict({'id': 'r', 'decision': 'alert', 'pattern': 'failed password for'})
        self.assertEqual(rule.pattern, ('failed', 'password', 'for'))

    def test_from_dict_names_the_missing_field(self) -> None:
        """The error has to say which field, or it is not worth raising."""
        with self.assertRaises(RulePackError) as caught:
            Rule.from_dict({'id': 'r', 'decision': 'alert'})
        self.assertIn('pattern', str(caught.exception))

    def test_str_reads_like_a_report_line(self) -> None:
        """``__str__`` is what a person sees when a rule is printed."""
        rule = Rule('brute', 'Brute force', Decision.ALERT, ['failed', 'password'], threshold=5)
        self.assertEqual(str(rule), 'brute [alert x5] failed password')


class TestRulePack(unittest.TestCase):
    """A pack of rules."""

    def _pack_file(self, document: dict) -> Path:
        """Write a rule pack to a temporary file.

        Parameters
        ----------
        document : dict
            The pack to serialize.

        Returns
        -------
        Path
            The file, removed when the test finishes.
        """
        handle = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8')
        with handle:
            json.dump(document, handle)
        path = Path(handle.name)
        self.addCleanup(path.unlink)
        return path

    def test_the_shipped_pack_loads(self) -> None:
        """The pack that ships with the repo has to be valid."""
        pack = RulePack.from_file(Path(__file__).resolve().parent.parent / 'policies' / 'baseline.json')
        self.assertGreaterEqual(len(pack), 10)
        self.assertIs(pack.default_decision, Decision.IGNORE)

    def test_duplicate_ids_are_refused(self) -> None:
        """Two rules with one id would make every report ambiguous."""
        with self.assertRaises(RulePackError) as caught:
            RulePack(
                [
                    Rule('same', 'a', Decision.ALERT, ['x']),
                    Rule('same', 'b', Decision.IGNORE, ['y']),
                ]
            )
        self.assertIn('same', str(caught.exception))

    def test_an_empty_pack_is_refused(self) -> None:
        """A pack with no rules would call every line clean."""
        with self.assertRaises(RulePackError):
            RulePack([])

    def test_a_missing_file_says_so(self) -> None:
        """The CLI turns this into one line rather than a traceback."""
        with self.assertRaises(RulePackError) as caught:
            RulePack.from_file('/nonexistent/policy.json')
        self.assertIn('No rule pack', str(caught.exception))

    def test_invalid_json_says_so(self) -> None:
        """A trailing comma is the most common way to break a pack."""
        handle = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8')
        with handle:
            handle.write('{"rules": [ }')
        path = Path(handle.name)
        self.addCleanup(path.unlink)
        with self.assertRaises(RulePackError) as caught:
            RulePack.from_file(path)
        self.assertIn('not valid JSON', str(caught.exception))

    def test_a_pack_without_a_rules_list_is_refused(self) -> None:
        """A pack that is valid JSON but the wrong shape still has to fail."""
        path = self._pack_file({'name': 'no rules here'})
        with self.assertRaises(RulePackError):
            RulePack.from_file(path)

    def test_str_counts_the_rules_by_decision(self) -> None:
        """The report header should say what is being enforced."""
        pack = RulePack(
            [Rule('a', 'a', Decision.ALERT, ['x']), Rule('b', 'b', Decision.ALLOW, ['y'])],
            name='test pack',
        )
        text = str(pack)
        self.assertIn('test pack', text)
        self.assertIn('1 alert', text)
        self.assertIn('1 allow', text)


if __name__ == '__main__':
    unittest.main()
