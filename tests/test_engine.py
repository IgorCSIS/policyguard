"""Tests for the engine: precedence, thresholds, and the queue.

The automaton decides what matched. This decides what it means, which is
where the interesting mistakes live.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import Final

from policyguard.alert import Alert, Verdict
from policyguard.engine import PolicyEngine
from policyguard.event import Event
from policyguard.rule import Decision, Rule, RulePack

_POLICY: Final[Path] = Path(__file__).resolve().parent.parent / 'policies' / 'baseline.json'
_SAMPLE: Final[Path] = Path(__file__).resolve().parent.parent / 'samples' / 'office-auth.log'


def _engine(rules: list[Rule], default: Decision = Decision.IGNORE) -> PolicyEngine:
    """Build an engine over a throwaway pack.

    Parameters
    ----------
    rules : list of Rule
        The rules to enforce.
    default : Decision, optional
        What an unmatched line is called.

    Returns
    -------
    PolicyEngine
        A ready engine.
    """
    return PolicyEngine(RulePack(rules, name='test pack', default_decision=default))


class TestDecisions(unittest.TestCase):
    """The three outcomes, one test each."""

    def test_a_line_that_matches_an_alert_rule_alerts(self) -> None:
        """The basic detection path."""
        engine = _engine([Rule('probe', 'probe', Decision.ALERT, ['invalid', 'user'])])
        verdict = engine.classify(Event('sshd: Failed password for invalid user admin', 1))
        self.assertIs(verdict.decision, Decision.ALERT)
        self.assertEqual(verdict.rule_id, 'probe')
        self.assertTrue(verdict.is_alert)

    def test_a_line_that_matches_an_allow_rule_is_allowed(self) -> None:
        """Known good traffic should be labelled, not merely not alerted."""
        engine = _engine([Rule('good', 'good', Decision.ALLOW, ['accepted', 'publickey'])])
        verdict = engine.classify(Event('sshd: Accepted publickey for itadmin', 1))
        self.assertIs(verdict.decision, Decision.ALLOW)
        self.assertFalse(verdict.is_alert)

    def test_a_line_that_matches_an_ignore_rule_is_ignored(self) -> None:
        """Noise rules are how the alert list stays short enough to read."""
        engine = _engine([Rule('noise', 'noise', Decision.IGNORE, ['health', 'probe', 'ok'])])
        verdict = engine.classify(Event('healthcheck: health probe ok target=x', 1))
        self.assertIs(verdict.decision, Decision.IGNORE)

    def test_an_unmatched_line_falls_back_to_the_pack_default(self) -> None:
        """Every line gets a verdict, including the ones nothing knows about."""
        engine = _engine([Rule('probe', 'probe', Decision.ALERT, ['invalid', 'user'])])
        verdict = engine.classify(Event('kernel: usb 2-1 new high-speed device', 1))
        self.assertIs(verdict.decision, Decision.IGNORE)
        self.assertEqual(verdict.rule_id, 'default')
        self.assertIn('No rule matched', verdict.reason)

    def test_a_blank_line_is_skipped_rather_than_classified(self) -> None:
        """A verdict on an empty line is noise in a report."""
        engine = _engine([Rule('probe', 'probe', Decision.ALERT, ['invalid', 'user'])])
        verdicts = list(engine.classify_lines(['', '   ', 'invalid user bob', '\n']))
        self.assertEqual(len(verdicts), 1)
        self.assertEqual(verdicts[0].event.raw, 'invalid user bob')

    def test_empty_input_produces_no_verdicts_and_no_error(self) -> None:
        """An empty log is a normal thing to hand a classifier."""
        engine = _engine([Rule('probe', 'probe', Decision.ALERT, ['invalid', 'user'])])
        self.assertEqual(list(engine.classify_lines([])), [])
        self.assertEqual(engine.alerts, ())


class TestPrecedence(unittest.TestCase):
    """Which rule wins when several match."""

    def test_an_explicit_allow_outranks_an_alert(self) -> None:
        """The allow-list behaviour, pinned so it cannot drift silently."""
        engine = _engine(
            [
                Rule('alerting', 'alerting', Decision.ALERT, ['session', 'opened']),
                Rule('allowed', 'allowed', Decision.ALLOW, ['session', 'opened', 'for', 'backupsvc']),
            ]
        )
        verdict = engine.classify(Event('session opened for backupsvc', 1))
        self.assertIs(verdict.decision, Decision.ALLOW)
        self.assertEqual(verdict.rule_id, 'allowed')

    def test_an_explicit_priority_can_tune_a_noisy_detection(self) -> None:
        """Cron sessions for root are the real case this exists for."""
        engine = _engine(
            [
                Rule('root_shell', 'root shell', Decision.ALERT, ['session', 'opened', 'for', 'user', 'root']),
                Rule('cron', 'cron', Decision.IGNORE, ['cron', 'session', 'opened'], priority=60),
            ]
        )
        verdict = engine.classify(Event('CRON: cron session opened for user root by (uid=0)', 1))
        self.assertIs(verdict.decision, Decision.IGNORE)
        self.assertEqual(verdict.rule_id, 'cron')

    def test_equal_priorities_break_the_tie_by_order_in_the_pack(self) -> None:
        """Documented behaviour, so a test has to hold it in place."""
        engine = _engine(
            [
                Rule('first', 'first', Decision.ALERT, ['failed', 'password'], priority=50),
                Rule('second', 'second', Decision.ALERT, ['failed'], priority=50),
            ]
        )
        verdict = engine.classify(Event('failed password for root', 1))
        self.assertEqual(verdict.rule_id, 'first')


class TestThresholdWindow(unittest.TestCase):
    """The sliding window, which is where the queue lives."""

    def setUp(self) -> None:
        """Build an engine with one five-in-a-window rule."""
        self._engine = _engine(
            [
                Rule(
                    'brute',
                    'brute force',
                    Decision.ALERT,
                    ['failed', 'password', 'for'],
                    threshold=5,
                    window_seconds=20,
                )
            ]
        )

    def test_below_the_threshold_nothing_fires(self) -> None:
        """One failed password is a typo, not an incident."""
        lines = [f'sshd: Failed password for root from 10.0.0.9 attempt {n}' for n in range(4)]
        verdicts = list(self._engine.classify_lines(lines))
        self.assertTrue(all(v.decision is Decision.IGNORE for v in verdicts))
        self.assertEqual(self._engine.alerts, ())

    def test_the_rule_fires_on_the_event_that_reaches_the_threshold(self) -> None:
        """Not before, and not one late."""
        lines = [f'sshd: Failed password for root from 10.0.0.9 attempt {n}' for n in range(6)]
        verdicts = list(self._engine.classify_lines(lines))
        decisions = [v.decision for v in verdicts]
        self.assertEqual(decisions[:4], [Decision.IGNORE] * 4)
        self.assertIs(decisions[4], Decision.ALERT)
        self.assertIs(decisions[5], Decision.ALERT)
        self.assertEqual(self._engine.alerts[0].hits, 5)

    def test_hits_are_counted_per_source(self) -> None:
        """One noisy host must not trip the rule on everybody else's behalf."""
        lines = [
            f'sshd: Failed password for root from 10.0.0.{host} attempt {n}'
            for n in range(4)
            for host in (1, 2)
        ]
        verdicts = list(self._engine.classify_lines(lines))
        self.assertTrue(all(v.decision is Decision.IGNORE for v in verdicts))

    def test_hits_that_slide_out_of_the_window_stop_counting(self) -> None:
        """This is the whole point of a window rather than a running total."""
        spaced: list[str] = []
        for _ in range(4):
            spaced.append('sshd: Failed password for root from 10.0.0.9')
            spaced.extend(['kernel: unrelated chatter'] * 25)
        verdicts = list(self._engine.classify_lines(spaced))
        self.assertEqual([v for v in verdicts if v.is_alert], [])

    def test_reset_clears_the_windows(self) -> None:
        """Without this, yesterday's failures would land in today's report."""
        lines = [f'sshd: Failed password for root from 10.0.0.9 attempt {n}' for n in range(4)]
        list(self._engine.classify_lines(lines))
        self._engine.reset()
        self.assertEqual(self._engine.counts[Decision.ALERT], 0)
        again = list(self._engine.classify_lines(lines))
        self.assertTrue(all(v.decision is Decision.IGNORE for v in again))


class TestVerdictAndAlert(unittest.TestCase):
    """The records handed back."""

    def setUp(self) -> None:
        """Classify the shipped sample against the shipped pack."""
        self._engine = PolicyEngine(RulePack.from_file(_POLICY))
        self._verdicts = list(self._engine.classify_lines(_SAMPLE.read_text().splitlines()))

    def test_the_shipped_sample_produces_all_three_decisions(self) -> None:
        """A demo that only ever shows one outcome teaches nothing."""
        seen = {verdict.decision for verdict in self._verdicts}
        self.assertEqual(seen, set(Decision))

    def test_the_sample_raises_alerts_including_the_brute_force_rule(self) -> None:
        """The headline detection has to actually fire on the shipped data."""
        fired = {alert.verdict.rule_id for alert in self._engine.alerts}
        self.assertIn('brute_force_ssh', fired)
        self.assertIn('invalid_user_probe', fired)

    def test_cron_noise_never_alerts_in_the_sample(self) -> None:
        """The tuning rule has to hold on real-shaped data, not just a unit test."""
        for verdict in self._verdicts:
            if 'CRON' in verdict.event.raw:
                self.assertIsNot(verdict.decision, Decision.ALERT, verdict.event.raw)

    def test_path_explain_names_the_rule_and_starts_at_the_start_state(self) -> None:
        """The explain output is the project's headline feature."""
        matched = [v for v in self._verdicts if v.rule is not None]
        self.assertTrue(matched)
        for verdict in matched:
            described = verdict.describe_path()
            self.assertTrue(described.startswith('q0 -> '), described)
            self.assertIn(f'ACCEPT: {verdict.rule_id}', described)

    def test_an_unmatched_verdict_says_so_instead_of_faking_a_path(self) -> None:
        """An empty path rendered as an arrow chain would be a lie."""
        unmatched = next(v for v in self._verdicts if v.rule is None)
        self.assertIn('no rule matched', unmatched.describe_path())

    def test_the_wire_format_has_the_keys_the_browser_demo_expects(self) -> None:
        """These key names are a contract with the parity check, not a style choice."""
        payload = self._verdicts[0].to_dict()
        self.assertEqual(
            sorted(payload),
            [
                'decision',
                'line',
                'path',
                'pathText',
                'raw',
                'reason',
                'ruleId',
                'ruleLabel',
                'severity',
                'source',
            ],
        )

    def test_counts_add_up_to_the_number_of_verdicts(self) -> None:
        """A line counted twice or not at all would make the summary wrong."""
        self.assertEqual(sum(self._engine.counts.values()), len(self._verdicts))

    def test_an_alert_cannot_be_raised_for_an_allowed_line(self) -> None:
        """A contradiction like that would hide a real bug."""
        allowed = next(v for v in self._verdicts if v.decision is Decision.ALLOW)
        with self.assertRaises(ValueError):
            Alert(allowed)

    def test_a_verdict_cannot_be_edited_after_the_fact(self) -> None:
        """A verdict is the record of a decision already made."""
        with self.assertRaises(AttributeError):
            self._verdicts[0].decision = Decision.ALLOW  # type: ignore[misc]

    def test_classification_is_repeatable(self) -> None:
        """Same log, same pack, same answers, every time."""
        self._engine.reset()
        again = list(self._engine.classify_lines(_SAMPLE.read_text().splitlines()))
        self.assertEqual(
            [v.to_dict() for v in self._verdicts],
            [v.to_dict() for v in again],
        )


if __name__ == '__main__':
    unittest.main()
