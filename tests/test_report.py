"""Tests for the reporters.

The point of having an abstract Reporter is that the CLI can hold one without
knowing which, and that a broken subclass fails loudly rather than quietly
rendering nothing. Both of those are worth a test.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Final, Mapping, Sequence

from policyguard.alert import Alert, Verdict
from policyguard.engine import PolicyEngine
from policyguard.report import REPORTERS, JsonReporter, Reporter, TableReporter
from policyguard.rule import Decision, RulePack

_POLICY: Final[Path] = Path(__file__).resolve().parent.parent / 'policies' / 'baseline.json'
_SAMPLE: Final[Path] = Path(__file__).resolve().parent.parent / 'samples' / 'office-auth.log'


class TestAbstraction(unittest.TestCase):
    """The abstract base."""

    def test_the_base_class_cannot_be_instantiated(self) -> None:
        """A reporter that rendered nothing would be worse than none at all."""
        with self.assertRaises(TypeError):
            Reporter()  # type: ignore[abstract]

    def test_a_subclass_missing_render_cannot_be_instantiated(self) -> None:
        """Inheriting the name does not let a subclass skip the work."""

        class Incomplete(Reporter):
            """A reporter that forgot the important half."""

            @property
            def name(self) -> str:
                """str: The format's name."""
                return 'incomplete'

        with self.assertRaises(TypeError):
            Incomplete()  # type: ignore[abstract]

    def test_both_shipped_reporters_are_reporters(self) -> None:
        """The registry is what the CLI chooses from, so it has to be honest."""
        for name, factory in REPORTERS.items():
            with self.subTest(name=name):
                reporter = factory()
                self.assertIsInstance(reporter, Reporter)
                self.assertEqual(reporter.name, name)

    def test_str_names_the_format(self) -> None:
        """Inherited from the base, which is the point of putting it there."""
        self.assertEqual(str(TableReporter()), 'table reporter')
        self.assertEqual(str(JsonReporter()), 'json reporter')


class TestRendering(unittest.TestCase):
    """What the two reporters actually produce."""

    def setUp(self) -> None:
        """Classify the shipped sample once for every test here."""
        self._engine = PolicyEngine(RulePack.from_file(_POLICY))
        self._verdicts: Sequence[Verdict] = list(
            self._engine.classify_lines(_SAMPLE.read_text().splitlines())
        )
        self._counts: Mapping[Decision, int] = self._engine.counts
        self._alerts: Sequence[Alert] = self._engine.alerts

    def _render(self, reporter: Reporter) -> str:
        """Render the classified sample with a reporter.

        Parameters
        ----------
        reporter : Reporter
            The reporter to use.

        Returns
        -------
        str
            Its output.
        """
        return reporter.render(self._verdicts, self._counts, self._alerts, 'baseline')

    def test_the_table_has_a_header_and_one_row_per_line(self) -> None:
        """The default output is meant to be read by a person."""
        output = self._render(TableReporter())
        self.assertIn('LINE  DECISION', output)
        self.assertIn('brute_force_ssh', output)
        self.assertIn('lines classified', output)

    def test_the_table_restates_the_scope_every_run(self) -> None:
        """Somebody who never opens the README still sees what this is."""
        self.assertIn('does not block, scan, or contact anything', self._render(TableReporter()))

    def test_explain_adds_the_path_and_the_reason(self) -> None:
        """Off by default, because most runs want the table alone."""
        plain = self._render(TableReporter())
        explained = self._render(TableReporter(explain=True))
        self.assertNotIn('path: q0', plain)
        self.assertIn('path: q0 -> ', explained)
        self.assertIn('why:  ', explained)

    def test_the_automaton_summary_is_only_shown_when_asked_for(self) -> None:
        """This is what --stats controls."""
        self.assertNotIn('states', self._render(TableReporter()))
        self.assertIn('states', self._render(TableReporter(automaton_summary='9 states')))

    def test_json_is_valid_and_carries_the_wire_keys(self) -> None:
        """These key names are a contract with the parity check."""
        payload = json.loads(self._render(JsonReporter()))
        self.assertEqual(payload['policy'], 'baseline')
        self.assertEqual(len(payload['verdicts']), len(self._verdicts))
        self.assertEqual(sum(payload['counts'].values()), len(self._verdicts))
        self.assertEqual(len(payload['alerts']), len(self._alerts))
        self.assertIn('pathText', payload['verdicts'][0])

    def test_json_omits_the_automaton_key_unless_asked(self) -> None:
        """A key that is sometimes absent is better than one that is empty."""
        self.assertNotIn('automaton', json.loads(self._render(JsonReporter())))
        self.assertIn('automaton', json.loads(self._render(JsonReporter(automaton_summary='9 states'))))

    def test_an_empty_run_renders_without_blowing_up(self) -> None:
        """Nothing to report is a normal outcome, not an error."""
        empty_counts = {decision: 0 for decision in Decision}
        for factory in REPORTERS.values():
            with self.subTest(reporter=factory.__name__):
                output = factory().render([], empty_counts, [], 'baseline')
                self.assertTrue(output.strip())

    def test_the_two_formats_agree_on_the_counts(self) -> None:
        """Two views of one run that disagreed would make both useless."""
        table = self._render(TableReporter())
        payload = json.loads(self._render(JsonReporter()))
        for decision, count in self._counts.items():
            self.assertIn(f'{count} {decision}', table)
            self.assertEqual(payload['counts'][decision.value], count)


if __name__ == '__main__':
    unittest.main()
