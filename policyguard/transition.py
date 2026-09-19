"""One edge of the automaton's transition function.

The engine itself stores transitions in a dictionary, because that is what
makes a lookup constant time. This class exists for the places where an edge
has to be handled as a value in its own right: printing a state path for a
person to read, and exporting the graph to Graphviz DOT.

Keeping it separate means the hot path stays a plain dict lookup while the
explain path still gets a real object with a name and a docstring.
"""

from __future__ import annotations


class Transition:
    """A single labelled edge from one automaton state to another.

    Immutable, because a transition describes a fact about a compiled
    automaton rather than something a caller should be able to edit.
    """

    __slots__ = ('_source', '_token', '_target')

    def __init__(self, source: int, token: str, target: int) -> None:
        """Build an edge.

        Parameters
        ----------
        source : int
            The state the edge leaves.
        token : str
            The token that has to be read for the edge to be taken.
        target : int
            The state the edge arrives at.
        """
        self._source = source
        self._token = token
        self._target = target

    @property
    def source(self) -> int:
        """int: The state this edge leaves."""
        return self._source

    @property
    def token(self) -> str:
        """str: The token that fires this edge."""
        return self._token

    @property
    def target(self) -> int:
        """int: The state this edge arrives at."""
        return self._target

    def __eq__(self, other: object) -> bool:
        """Compare by value, so transitions can go in a set or be asserted on."""
        if not isinstance(other, Transition):
            return NotImplemented
        return (self._source, self._token, self._target) == (
            other._source,
            other._token,
            other._target,
        )

    def __hash__(self) -> int:
        """Hash by value, to match ``__eq__``."""
        return hash((self._source, self._token, self._target))

    def __str__(self) -> str:
        """Return the edge the way the explain output prints it."""
        return f'q{self._source} --{self._token}--> q{self._target}'

    def __repr__(self) -> str:
        """Return an unambiguous form for debugging."""
        return f'Transition(source={self._source}, token={self._token!r}, target={self._target})'
