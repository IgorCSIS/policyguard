"""Tests for the Appendix A audit.

A style checker that has been loosened until it passes is worse than no
checker, because it reports success. These tests hold it honest from both
directions: it has to stay silent on this package, and it has to still catch
a file that breaks the conventions on purpose.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from typing import Final

_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'tools'))

from appendix_a_audit import audit_paths, main  # noqa: E402

#: A module that breaks one convention per line, used to prove the checker
#: still has teeth after any change to it.
_BAD_MODULE: Final[str] = '''badConstant = 3
OTHER = 4


class lowercase_class:
    def __init__(self, value):
        self.public = value

    def NotSnake(self, x):
        """One liner."""
        return x

    def raises_without_saying(self):
        """Does something.

        Returns
        -------
        None
        """
        raise ValueError('boom')


def undocumented(a):
    return a
'''


class TestCleanCode(unittest.TestCase):
    """The checker on this repository."""

    def test_the_package_has_no_violations(self) -> None:
        """This is the claim the README makes, so a test should hold it."""
        found = list(audit_paths([_ROOT / 'policyguard']))
        self.assertEqual([str(violation) for violation in found], [])

    def test_the_tests_and_tools_have_no_violations_either(self) -> None:
        """Conventions that only apply to the interesting files are not conventions."""
        found = list(audit_paths([_ROOT / 'tests', _ROOT / 'tools']))
        self.assertEqual([str(violation) for violation in found], [])

    def test_a_clean_run_exits_zero(self) -> None:
        """CI depends on the exit code, not on the text."""
        self.assertEqual(main([str(_ROOT / 'policyguard')]), 0)


class TestItStillCatchesThings(unittest.TestCase):
    """The checker on a file that breaks the rules."""

    def setUp(self) -> None:
        """Write the deliberately bad module to a temporary file."""
        handle = tempfile.NamedTemporaryFile('w', suffix='.py', delete=False, encoding='utf-8')
        with handle:
            handle.write(_BAD_MODULE)
        self._path = Path(handle.name)
        self.addCleanup(self._path.unlink)
        self._rules = {violation.rule for violation in audit_paths([self._path])}

    def test_every_rule_category_still_fires(self) -> None:
        """Loosening the checker must not quietly disable a whole rule."""
        expected = {
            'module-docstring',
            'constant-name',
            'constant-final',
            'class-name',
            'class-docstring',
            'class-str',
            'encapsulation',
            'function-docstring',
            'function-name',
            'docstring-parameters',
            'docstring-returns',
            'docstring-raises',
        }
        self.assertEqual(expected - self._rules, set(), 'a rule stopped firing')

    def test_a_dirty_run_exits_non_zero(self) -> None:
        """Otherwise CI would go green on a file full of violations."""
        self.assertEqual(main([str(self._path)]), 1)


if __name__ == '__main__':
    unittest.main()
