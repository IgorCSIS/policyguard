"""PolicyGuard: a defensive log policy engine built on a DFA.

PolicyGuard compiles a pack of policy rules into a deterministic finite
automaton, runs log lines through it, and labels each line ``allow``,
``alert``, or ``ignore`` along with the state path that produced the label.

It is a teaching and portfolio project. It reads logs and classifies them.
It has no network code, it never touches a live host, and it contains no
attack tooling of any kind.

The public surface is small on purpose::

    from policyguard import PolicyEngine, RulePack

    engine = PolicyEngine(RulePack.from_file('policies/baseline.json'))
    for verdict in engine.classify_lines(open('samples/auth.log')):
        print(verdict)

Everything here is standard library only, so it runs on a lab machine with
no ``pip install`` step.
"""

from __future__ import annotations

from typing import Final

from policyguard.alert import Alert, Verdict
from policyguard.automaton import Automaton
from policyguard.engine import PolicyEngine
from policyguard.errors import (
    AutomatonError,
    LogSourceError,
    PolicyGuardError,
    RulePackError,
)
from policyguard.event import Event
from policyguard.report import JsonReporter, Reporter, TableReporter
from policyguard.rule import Decision, Rule, RulePack
from policyguard.transition import Transition

#: Package version, reported by ``python -m policyguard --version``.
__version__: Final[str] = '1.0.0'

__all__ = [
    'Alert',
    'Automaton',
    'AutomatonError',
    'Decision',
    'Event',
    'LogSourceError',
    'PolicyEngine',
    'PolicyGuardError',
    'JsonReporter',
    'Reporter',
    'Rule',
    'RulePack',
    'RulePackError',
    'TableReporter',
    'Transition',
    'Verdict',
    '__version__',
]
