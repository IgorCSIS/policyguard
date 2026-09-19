# Design notes

Written for whoever reads this next, including me in six months. The README says
what the project does. This says why it is built the way it is, and works the
automaton by hand so the claims in the README can be checked rather than
believed.

## The model

Every rule is a sequence of tokens. All rules compile into one automaton, built
the Aho-Corasick way.

### Step 1: the trie

Thread each rule's pattern into a prefix tree. Every node is a state, state
`q0` is the start. Patterns sharing a prefix share states, which is what keeps
the machine small when a pack has many similar rules.

Two rules:

```
A: failed password for
B: failed publickey
```

```
q0 --failed--> q1 --password--> q2 --for--> q3  (accept A)
                \--publickey--> q4              (accept B)
```

Five states from five pattern tokens, because `failed` is shared.

### Step 2: failure links

A breadth-first walk gives every state a fallback: the state representing the
longest proper suffix of what has been read that is still a prefix of some
rule. The queue is what makes the walk breadth first, and breadth first is
what makes it correct, because a state's failure link needs its parent's to be
known first.

For the trie above every failure link points at `q0`, since no pattern is a
suffix of another. With a pack containing `user` and `invalid user` the links
are the interesting part: the state after reading `invalid user` falls back to
the state after reading `user`, so a line containing `invalid user` reports
both rules rather than the longer one hiding the shorter.

### Step 3: goto completion

Fold the failure links into the transition table. After this every state has
exactly one entry for every token in the alphabet, so matching reads a token,
does one lookup, and moves. It never backtracks and never follows a link at
run time.

This is the step that makes the thing a genuine DFA rather than an NFA with a
fallback rule, and `test_every_state_answers_every_token` in
`tests/test_automaton.py` asserts it directly.

The start state needed explicit attention. Every other state is completed as
somebody's child during the walk, but `q0` is nobody's child, so tokens it
cannot advance on had no entry at all. Behaviour was already correct because
the lookup default returns `q0`, but the table was not literally total and the
README claims it is. A claim worth making is worth being true, so the start
state is completed explicitly at the end of `_link_failures`.

## Worked example

Pack: `policies/baseline.json`. Line:

```
Sep 19 01:20:02 vpn-gw sshd[4001]: Failed password for invalid user admin from 203.0.113.42
```

Tokenized, lower-cased, punctuation split:

```
sep 19 01:20:02 vpn-gw sshd 4001 failed password for invalid user admin from 203.0.113.42
```

Walking it:

- `sep`, `19`, `01:20:02`, `vpn-gw`, `sshd`, `4001` are not in the alphabet, so
  each is one failed lookup landing back at `q0`.
- `failed` moves to the first state of the brute force pattern.
- `password`, `for` complete it. The rule has `threshold: 5`, so this is
  recorded in the sliding window for `203.0.113.42` and reported only once the
  window holds five.
- `invalid`, `user` complete `invalid_user_probe`, which has threshold 1 and
  fires immediately.

Both matches go to the engine. Precedence picks the winner: below the
threshold the brute force rule is not a candidate at all, so
`invalid_user_probe` wins and the line is an alert with path
`q0 -> q13 -> q14 -> ACCEPT: invalid_user_probe`.

On the fifth such line from that address the brute force rule becomes a
candidate too. Both are priority 50, so the tie breaks by order in the pack,
where `brute_force_ssh` comes first.

## Why the reported path is the rule's own path

A match found through a failure link is reported at a state that is not the
rule's accepting state. The states actually walked would therefore end
somewhere that has nothing to do with the rule being reported, and printing
them next to `ACCEPT: rule_id` would be misleading.

So the automaton records each rule's own path down the trie while threading it
in, and that is what a verdict carries. It is stable, it is the same every
time, and it genuinely spells out the pattern that fired. Where in the line
the match happened is reported separately as `end_index`.

## Precedence

Several rules can match one line. The rule is:

1. Highest priority wins.
2. Equal priorities break the tie by order in the pack.

Both halves are tested. The second half existed as documentation before it
existed as behaviour: the first implementation let whichever rule finished
earliest in the line win, which is not something a rule author can see or
control. `test_equal_priorities_break_the_tie_by_order_in_the_pack` caught it.

### The allow-over-alert decision

Default priorities are allow 100, alert 50, ignore 10, so an explicit allow
beats an alert.

This is the right default for an allow list, and it is also the setting most
capable of hiding a real detection, so it is written down in the README, the
CLI epilog, and the source. The alternative, alert always winning, would mean
an operator could never silence a known-good pattern without deleting the
detection, which is worse: people delete detections.

## Determinism

The compiled machine has to be identical between runs, or the DOT export and
the cross-language parity check are both worthless.

Python randomizes string hashing per process, so iterating the alphabet as a
set produced a correct but differently shaped machine each run. Both the
Python and the TypeScript sort the alphabet before the BFS. Checked with:

```bash
for seed in 0 1 42; do PYTHONHASHSEED=$seed python3 -m policyguard --json | sha256sum; done
```

All three hashes match.

## What was deliberately left out

- **Regular expressions in rules.** They would make patterns more expressive
  and destroy the complexity argument, since a rule would no longer compile
  into shared states. Tokens keep matching linear and keep rules readable.
- **NFA to DFA subset construction.** Aho-Corasick already produces a
  deterministic machine for this rule shape. Building an NFA first and
  determinizing it would be more textbook and strictly more work for the same
  result.
- **Real timestamps in the sliding window.** `window_seconds` currently counts
  events rather than parsing each line's clock. Log timestamp formats vary
  enormously and parsing them badly would be worse than counting events
  honestly. The field name says seconds because that is what it would mean
  once timestamps are parsed, and the README says what it does today.
- **Anything that acts on a host.** Out of scope permanently, not a gap.
