/**
 * The DFA, ported from policyguard/automaton.py.
 *
 * Same three steps: thread every rule pattern into a trie, walk the trie
 * breadth first with a queue to compute failure links, then fold those links
 * into the transition table so every state has exactly one answer for every
 * token. After that, matching is one map lookup per token and never
 * backtracks.
 *
 * The transition table is a Map keyed by "state\ttoken". JavaScript has no
 * tuple keys, and a tab is not a legal character in a token, so the joined
 * string is a safe stand-in for Python's (state, token) tuple.
 */

import type { Rule } from "./rules.ts";

/** The start state. Reading nothing leaves the automaton here. */
export const START_STATE = 0;

/** One rule firing at one position in a line. */
export interface Match {
  rule: Rule;
  endIndex: number;
  path: readonly number[];
}

/** Join a state and a token into a Map key. */
function key(state: number, token: string): string {
  return `${state}\t${token}`;
}

/** A DFA compiled from a set of rule patterns. */
export class Automaton {
  private readonly goto = new Map<string, number>();
  private readonly failure = new Map<number, number>();
  private readonly outputs = new Map<number, Rule[]>();
  private readonly rulePaths = new Map<string, readonly number[]>();
  private readonly alphabet = new Set<string>();
  private states = 1;
  private compiled = false;

  /** How many states the automaton has. */
  get stateCount(): number {
    return this.states;
  }

  /** How many edges the transition table holds. */
  get transitionCount(): number {
    return this.goto.size;
  }

  /** Every token that appears in some rule. */
  get tokenCount(): number {
    return this.alphabet.size;
  }

  /**
   * Build the automaton from a set of rules.
   *
   * @throws if given no rules, since an automaton with no accepting states
   * would quietly call every line clean.
   */
  compile(rules: readonly Rule[]): this {
    if (rules.length === 0) throw new Error("Cannot compile an automaton from zero rules.");
    this.buildTrie(rules);
    this.linkFailures();
    this.compiled = true;
    return this;
  }

  /** Thread every rule pattern into the prefix tree. */
  private buildTrie(rules: readonly Rule[]): void {
    for (const rule of rules) {
      let state = START_STATE;
      const walked: number[] = [START_STATE];
      for (const token of rule.pattern) {
        this.alphabet.add(token);
        const edge = key(state, token);
        if (!this.goto.has(edge)) {
          this.goto.set(edge, this.states);
          this.states += 1;
        }
        state = this.goto.get(edge) as number;
        walked.push(state);
      }
      const existing = this.outputs.get(state);
      if (existing) existing.push(rule);
      else this.outputs.set(state, [rule]);
      // A match found through a failure link is reported at a state that is
      // not the rule's accepting state, so the walked states would be the
      // wrong thing to show. This is the rule's own path.
      this.rulePaths.set(rule.ruleId, walked);
    }
  }

  /** Compute failure links, then fold them into the transition table. */
  private linkFailures(): void {
    // Sorted for the same reason as the Python: a machine that differs
    // between runs would make the parity check and the DOT export useless.
    const ordered = [...this.alphabet].sort();
    const pending: number[] = [];
    let head = 0;

    for (const token of ordered) {
      const edge = key(START_STATE, token);
      const child = this.goto.get(edge);
      if (child !== undefined) {
        this.failure.set(child, START_STATE);
        pending.push(child);
      }
    }

    while (head < pending.length) {
      const state = pending[head] as number;
      head += 1;
      for (const token of ordered) {
        const edge = key(state, token);
        const child = this.goto.get(edge);
        const fallback = this.failure.get(state) ?? START_STATE;
        if (child !== undefined) {
          this.failure.set(child, this.goto.get(key(fallback, token)) ?? START_STATE);
          const inherited = this.outputs.get(this.failure.get(child) as number);
          if (inherited) {
            const own = this.outputs.get(child) ?? [];
            const seen = new Set(own.map((rule) => rule.ruleId));
            own.push(...inherited.filter((rule) => !seen.has(rule.ruleId)));
            this.outputs.set(child, own);
          }
          pending.push(child);
        } else {
          this.goto.set(edge, this.goto.get(key(fallback, token)) ?? START_STATE);
        }
      }
    }

    // Finish the start state, which is never anybody's child.
    for (const token of ordered) {
      const edge = key(START_STATE, token);
      if (!this.goto.has(edge)) this.goto.set(edge, START_STATE);
    }
  }

  /**
   * Run one line's tokens through the automaton.
   *
   * @throws if the automaton has not been compiled.
   */
  match(tokens: readonly string[]): Match[] {
    if (!this.compiled) throw new Error("Compile the automaton before matching against it.");

    const found: Match[] = [];
    let state = START_STATE;

    for (let index = 0; index < tokens.length; index += 1) {
      state = this.goto.get(key(state, tokens[index] as string)) ?? START_STATE;
      for (const rule of this.outputs.get(state) ?? []) {
        found.push({
          rule,
          endIndex: index,
          path: this.rulePaths.get(rule.ruleId) ?? [START_STATE, state],
        });
      }
    }
    return found;
  }

  /** Describe the machine the way the CLI's --stats flag does. */
  describe(): string {
    if (!this.compiled) return "Automaton (not compiled)";
    return `${this.states} states, ${this.goto.size} transitions, ${this.alphabet.size} tokens in the alphabet`;
  }
}
