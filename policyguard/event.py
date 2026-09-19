"""One log line, parsed into something the automaton can run.

The automaton matches sequences of tokens rather than raw characters. That
choice is the reason the whole engine stays fast and readable: a rule author
writes ``["failed", "password", "for"]`` instead of a regular expression, and
the alphabet of the automaton is the set of words that appear in rules rather
than every byte that can appear in a log.

Normalizing here, once per line, is also what keeps matching case insensitive
and punctuation insensitive without any rule needing to care.
"""

from __future__ import annotations

import re
from typing import Final, Iterator, Sequence

#: Characters that split a log line into tokens. Punctuation that carries no
#: meaning on its own is treated as whitespace, so ``sshd[1234]:`` becomes
#: ``sshd`` and ``1234`` rather than one unmatchable blob.
_TOKEN_SPLIT: Final[re.Pattern[str]] = re.compile(r'[^A-Za-z0-9_.:@/-]+')

#: Trailing punctuation stripped from each token after the split above.
_TRIM: Final[str] = '.:,;'

#: Matches an IPv4 address anywhere in a line, used to group events by source.
_IPV4: Final[re.Pattern[str]] = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

#: Matches the account name in the shapes auth logs actually use:
#: ``user bob``, ``for bob``, ``for user bob``, and ``for invalid user bob``.
#: The two optional groups are why ``for user bob`` yields ``bob`` rather
#: than ``user``, which is what an earlier version of this did.
_USER: Final[re.Pattern[str]] = re.compile(
    r'\b(?:user|for)\s+(?:invalid\s+)?(?:user\s+)?([A-Za-z_][A-Za-z0-9_.-]*)',
    re.IGNORECASE,
)

#: Used when a line has no address in it, so grouping still has a key.
UNKNOWN_SOURCE: Final[str] = '-'


class Event:
    """A single log line and the tokens the automaton will run over.

    An event is immutable once built. Classification has to be repeatable,
    and a line that could be edited between two passes would make the state
    path in a verdict meaningless.
    """

    __slots__ = ('_line_number', '_raw', '_tokens', '_source', '_user')

    def __init__(self, raw: str, line_number: int = 0) -> None:
        """Parse one log line.

        Parameters
        ----------
        raw : str
            The log line exactly as it was read, without its newline.
        line_number : int, optional
            Which line of the file this was, counting from one. Carried
            through to the verdict so a person can find it again.
        """
        self._raw = raw.rstrip('\n')
        self._line_number = line_number
        self._tokens = tuple(self._tokenize(self._raw))
        self._source = self._find_source(self._raw)
        self._user = self._find_user(self._raw)

    @staticmethod
    def _tokenize(raw: str) -> Iterator[str]:
        """Split a line into lower-cased tokens.

        Parameters
        ----------
        raw : str
            The log line.

        Yields
        ------
        str
            Each non-empty token, lower-cased and stripped of trailing
            punctuation.
        """
        for piece in _TOKEN_SPLIT.split(raw.lower()):
            token = piece.strip(_TRIM)
            if token:
                yield token

    @staticmethod
    def _find_source(raw: str) -> str:
        """Pull the source address out of a line.

        Threshold rules count repeats per source, so a line with no address
        still needs a key rather than being dropped.

        Parameters
        ----------
        raw : str
            The log line.

        Returns
        -------
        str
            The first IPv4 address in the line, or :data:`UNKNOWN_SOURCE`.
        """
        found = _IPV4.search(raw)
        return found.group(0) if found else UNKNOWN_SOURCE

    @staticmethod
    def _find_user(raw: str) -> str:
        """Pull the account name out of a line, when the line names one.

        Parameters
        ----------
        raw : str
            The log line.

        Returns
        -------
        str
            The account name, or an empty string when none was found.
        """
        found = _USER.search(raw)
        return found.group(1).lower() if found else ''

    @property
    def raw(self) -> str:
        """str: The original log line."""
        return self._raw

    @property
    def line_number(self) -> int:
        """int: Which line of the source file this was, counting from one."""
        return self._line_number

    @property
    def tokens(self) -> tuple[str, ...]:
        """tuple of str: The normalized tokens the automaton runs over."""
        return self._tokens

    @property
    def source(self) -> str:
        """str: The address the line came from, or ``-`` when it has none."""
        return self._source

    @property
    def user(self) -> str:
        """str: The account named in the line, or an empty string."""
        return self._user

    @property
    def is_blank(self) -> bool:
        """bool: Whether the line has nothing to classify.

        Blank lines and lines of pure punctuation are skipped rather than
        classified, because a verdict on an empty line is noise in a report.
        """
        return not self._tokens

    def __str__(self) -> str:
        """Return the line as it would be shown in a report."""
        prefix = f'{self._line_number}: ' if self._line_number else ''
        return f'{prefix}{self._raw}'

    def __repr__(self) -> str:
        """Return an unambiguous form for debugging."""
        return f'Event(line_number={self._line_number}, tokens={len(self._tokens)})'


def events_from_lines(lines: Sequence[str] | Iterator[str]) -> Iterator[Event]:
    """Turn an iterable of raw lines into events, numbering them from one.

    Parameters
    ----------
    lines : sequence of str or iterator of str
        Raw log lines, with or without trailing newlines.

    Yields
    ------
    Event
        One event per line, including blank ones. The caller decides whether
        to skip them, because a line number that skips gaps is confusing.
    """
    for number, raw in enumerate(lines, start=1):
        yield Event(raw, line_number=number)
