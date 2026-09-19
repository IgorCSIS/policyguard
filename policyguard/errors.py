"""Errors raised on purpose by PolicyGuard.

Having one base class lets the command line tool catch the failures it
expects and print a single readable line, while a genuine bug still escapes
as a traceback rather than being swallowed.

Style follows Appendix A: snake_case names, ALL_CAPS constants marked
``Final``, a leading underscore on anything private, and a docstring on every
module, class, and function.
"""

from __future__ import annotations


class PolicyGuardError(Exception):
    """Base class for every error this package raises deliberately."""


class RulePackError(PolicyGuardError):
    """Raised when a rule pack is missing, malformed, or self-contradictory."""


class LogSourceError(PolicyGuardError):
    """Raised when a log file cannot be read."""


class AutomatonError(PolicyGuardError):
    """Raised when the automaton is used in a way its state does not allow.

    The clearest example is asking a freshly constructed automaton to match
    something before any rule has been compiled into it.
    """
