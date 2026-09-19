"""Entry point for ``python -m policyguard``.

Kept to one job so the CLI stays testable: :func:`policyguard.cli.main`
returns an exit code rather than calling ``sys.exit`` itself, which is what
lets the tests drive it without catching ``SystemExit``.
"""

from __future__ import annotations

import sys

from policyguard.cli import main

if __name__ == '__main__':
    sys.exit(main())
