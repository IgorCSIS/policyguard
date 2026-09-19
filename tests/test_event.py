"""Tests for log line parsing.

Normalization happens once per line, and everything downstream assumes it
was done right, so these are the cheapest bugs to catch here and the most
expensive to catch later.
"""

from __future__ import annotations

import unittest

from policyguard.event import UNKNOWN_SOURCE, Event, events_from_lines


class TestTokenizing(unittest.TestCase):
    """Turning a line into tokens."""

    def test_case_is_folded_so_rules_do_not_have_to_care(self) -> None:
        """A rule author writes lower case and it just works."""
        event = Event('Failed PASSWORD For Root')
        self.assertEqual(event.tokens, ('failed', 'password', 'for', 'root'))

    def test_log_punctuation_is_split_rather_than_swallowed(self) -> None:
        """``sshd[4001]:`` has to become tokens, not one unmatchable blob."""
        event = Event('Sep 19 01:20:02 vpn-gw sshd[4001]: Failed password')
        self.assertIn('sshd', event.tokens)
        self.assertIn('4001', event.tokens)
        self.assertIn('failed', event.tokens)

    def test_a_blank_line_has_no_tokens_and_knows_it(self) -> None:
        """The engine uses this to skip rather than classify."""
        self.assertTrue(Event('').is_blank)
        self.assertTrue(Event('    ').is_blank)
        self.assertTrue(Event('   ;;;   ').is_blank)
        self.assertFalse(Event('failed password').is_blank)

    def test_the_raw_line_is_kept_exactly_as_read(self) -> None:
        """Reports show the original, not the normalized form."""
        raw = 'Sep 19 01:20:02 vpn-gw sshd[4001]: Failed password for root'
        self.assertEqual(Event(raw + '\n').raw, raw)


class TestExtraction(unittest.TestCase):
    """Pulling structure out of a line."""

    def test_the_source_address_is_found(self) -> None:
        """Threshold rules count per source, so this has to be right."""
        event = Event('sshd: Failed password for root from 203.0.113.42 port 55102')
        self.assertEqual(event.source, '203.0.113.42')

    def test_a_line_with_no_address_still_gets_a_key(self) -> None:
        """Grouping by source must not drop the lines that have none."""
        self.assertEqual(Event('sudo: authentication failure').source, UNKNOWN_SOURCE)

    def test_the_account_name_is_found_in_the_usual_shapes(self) -> None:
        """Auth logs name accounts a few different ways."""
        self.assertEqual(Event('session opened for user backupsvc').user, 'backupsvc')
        self.assertEqual(Event('Failed password for invalid user admin').user, 'admin')
        self.assertEqual(Event('kernel: usb device connected').user, '')


class TestNumbering(unittest.TestCase):
    """Line numbers."""

    def test_lines_are_numbered_from_one_including_blanks(self) -> None:
        """A line number that skips gaps sends people to the wrong line."""
        events = list(events_from_lines(['first', '', 'third']))
        self.assertEqual([event.line_number for event in events], [1, 2, 3])
        self.assertTrue(events[1].is_blank)

    def test_str_shows_the_number_and_the_line(self) -> None:
        """``__str__`` is what a person sees in a report."""
        self.assertEqual(str(Event('failed password', 7)), '7: failed password')


class TestImmutability(unittest.TestCase):
    """Events do not change after parsing."""

    def test_an_event_cannot_be_edited(self) -> None:
        """A line edited between two passes makes its state path meaningless."""
        event = Event('failed password for root', 1)
        with self.assertRaises(AttributeError):
            event.raw = 'something else'  # type: ignore[misc]


if __name__ == '__main__':
    unittest.main()
