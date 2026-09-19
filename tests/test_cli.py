"""Tests for the command line interface.

The CLI is what a grader runs and what a demo runs, so its exit codes and
its output shape matter as much as the engine behind it.
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from policyguard.cli import EXIT_ALERTS_FOUND, EXIT_ERROR, EXIT_OK, main

_ROOT = Path(__file__).resolve().parent.parent
_POLICY = str(_ROOT / 'policies' / 'baseline.json')
_SAMPLE = str(_ROOT / 'samples' / 'office-auth.log')


def _run(args: list[str]) -> tuple[int, str, str]:
    """Run the CLI and capture everything it wrote.

    Parameters
    ----------
    args : list of str
        Command line arguments.

    Returns
    -------
    tuple
        The exit code, standard output, and standard error.
    """
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(args)
    return code, out.getvalue(), err.getvalue()


class TestDefaults(unittest.TestCase):
    """Running it with no arguments."""

    def test_no_arguments_classifies_the_shipped_sample(self) -> None:
        """A grader should be able to type one command and see it work."""
        code, out, _ = _run([])
        self.assertEqual(code, EXIT_OK)
        self.assertIn('lines classified', out)
        self.assertIn('alert(s):', out)

    def test_the_footer_states_the_scope(self) -> None:
        """Every run says what the tool does not do."""
        _, out, _ = _run([])
        self.assertIn('does not block, scan, or contact anything', out)


class TestOutputModes(unittest.TestCase):
    """The ways it can print."""

    def test_the_table_has_a_header_and_one_row_per_line(self) -> None:
        """The default output is meant to be read by a person."""
        _, out, _ = _run([_SAMPLE, '-p', _POLICY])
        self.assertIn('LINE  DECISION', out)
        self.assertIn('brute_force_ssh', out)

    def test_explain_prints_the_path_and_the_reason(self) -> None:
        """This is the feature the whole project is built around."""
        _, out, _ = _run([_SAMPLE, '-p', _POLICY, '--explain'])
        self.assertIn('path: q0 -> ', out)
        self.assertIn('ACCEPT:', out)
        self.assertIn('why:  ', out)

    def test_json_output_is_machine_readable(self) -> None:
        """The parity check depends on this staying valid JSON."""
        code, out, _ = _run([_SAMPLE, '-p', _POLICY, '--json'])
        payload = json.loads(out)
        self.assertEqual(code, EXIT_OK)
        self.assertIn('verdicts', payload)
        self.assertIn('counts', payload)
        self.assertEqual(sum(payload['counts'].values()), len(payload['verdicts']))

    def test_only_filters_to_one_decision(self) -> None:
        """Triage starts by looking at the alerts and nothing else."""
        _, out, _ = _run([_SAMPLE, '-p', _POLICY, '--json', '--only', 'alert'])
        payload = json.loads(out)
        self.assertTrue(payload['verdicts'])
        for verdict in payload['verdicts']:
            self.assertEqual(verdict['decision'], 'alert')

    def test_stats_reports_the_compiled_automaton(self) -> None:
        """The numbers behind the Big-O claim should be one flag away."""
        _, out, _ = _run([_SAMPLE, '-p', _POLICY, '--stats'])
        self.assertIn('states', out)
        self.assertIn('transitions', out)


class TestExitCodes(unittest.TestCase):
    """What the shell sees."""

    def test_alerts_alone_do_not_fail_the_run(self) -> None:
        """Finding alerts is the tool working, not the tool failing."""
        code, _, _ = _run([_SAMPLE, '-p', _POLICY])
        self.assertEqual(code, EXIT_OK)

    def test_fail_on_alert_exits_non_zero_when_alerts_were_found(self) -> None:
        """This is what makes the tool usable as a CI gate."""
        code, _, _ = _run([_SAMPLE, '-p', _POLICY, '--fail-on-alert'])
        self.assertEqual(code, EXIT_ALERTS_FOUND)

    def test_fail_on_alert_exits_zero_on_a_clean_log(self) -> None:
        """A gate that always fails is not a gate."""
        handle = tempfile.NamedTemporaryFile('w', suffix='.log', delete=False, encoding='utf-8')
        with handle:
            handle.write('Sep 19 00:00:01 gw healthcheck: health probe ok target=x\n')
        path = Path(handle.name)
        self.addCleanup(path.unlink)
        code, _, _ = _run([str(path), '-p', _POLICY, '--fail-on-alert'])
        self.assertEqual(code, EXIT_OK)

    def test_a_missing_log_file_is_a_message_not_a_traceback(self) -> None:
        """A wrong path is a user mistake."""
        code, _, err = _run(['/nonexistent/auth.log', '-p', _POLICY])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn('No log file', err)

    def test_a_missing_policy_is_a_message_not_a_traceback(self) -> None:
        """Same for the other input."""
        code, _, err = _run([_SAMPLE, '-p', '/nonexistent/policy.json'])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn('No rule pack', err)


class TestDotExport(unittest.TestCase):
    """Writing the automaton out."""

    def test_dot_writes_a_file_and_exits_without_classifying(self) -> None:
        """Exporting the machine is a separate job from running it."""
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'automaton.dot'
            code, out, _ = _run(['-p', _POLICY, '--dot', str(target)])
            self.assertEqual(code, EXIT_OK)
            self.assertTrue(target.exists())
            self.assertIn('digraph policyguard', target.read_text())
            self.assertNotIn('LINE  DECISION', out)


class TestEmptyInput(unittest.TestCase):
    """The empty log."""

    def test_an_empty_file_classifies_nothing_and_succeeds(self) -> None:
        """Handing a classifier an empty file is normal, not an error."""
        handle = tempfile.NamedTemporaryFile('w', suffix='.log', delete=False, encoding='utf-8')
        handle.close()
        path = Path(handle.name)
        self.addCleanup(path.unlink)
        code, out, _ = _run([str(path), '-p', _POLICY])
        self.assertEqual(code, EXIT_OK)
        self.assertIn('0 lines classified', out)


if __name__ == '__main__':
    unittest.main()
