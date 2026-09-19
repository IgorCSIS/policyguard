/**
 * The policy engine, ported from policyguard/engine.py.
 *
 * Precedence is the part worth reading twice: when several rules match one
 * line, the highest priority wins, and equal priorities break the tie by
 * order in the pack. Getting that wrong is the easiest way for this port to
 * disagree with the Python while still looking right, which is exactly what
 * the parity check exists to catch.
 */

import { Automaton } from "./automaton.ts";
import { parseEvent, type LogEvent } from "./event.ts";
import { isThresholdRule, type Decision, type Rule, type RulePack } from "./rules.ts";

/** How many recent events a threshold rule keeps when it names no window. */
const DEFAULT_WINDOW_EVENTS = 50;

/** The classification of one log line. Mirrors Verdict.to_dict in Python. */
export interface Verdict {
  line: number;
  raw: string;
  decision: Decision;
  ruleId: string;
  ruleLabel: string;
  severity: string;
  path: number[];
  pathText: string;
  reason: string;
  source: string;
}

/** What classifying a whole log produced. */
export interface Report {
  policy: string;
  counts: Record<Decision, number>;
  verdicts: Verdict[];
  automaton: string;
}

/** Recent hits for one threshold rule, grouped by source. */
class SlidingWindow {
  private readonly hits = new Map<string, number[]>();
  private readonly threshold: number;
  private readonly span: number;

  // Written out rather than using constructor parameter properties, which
  // Node's type stripping refuses, and this runs under `node --test`.
  constructor(threshold: number, span: number) {
    this.threshold = threshold;
    this.span = Math.max(span, threshold);
  }

  /** Record a hit and report how many are inside the window now. */
  record(source: string, position: number): number {
    const queue = this.hits.get(source) ?? [];
    queue.push(position);
    // Only the front can ever be stale, so this stays cheap.
    let start = 0;
    while (start < queue.length && position - (queue[start] as number) >= this.span) start += 1;
    const trimmed = start > 0 ? queue.slice(start) : queue;
    this.hits.set(source, trimmed);
    return trimmed.length;
  }

  /** Report whether a hit count is enough to fire the rule. */
  isTripped(count: number): boolean {
    return count >= this.threshold;
  }
}

/** Write the one-line reason shown with a verdict. */
function explain(rule: Rule, hits: number): string {
  const base = rule.description || `Matched ${rule.pattern.join(" ")}.`;
  if (isThresholdRule(rule)) {
    return `${base} Fired after ${hits} matching events from one source.`;
  }
  return base;
}

/** Render the state path the way --explain prints it. */
function describePath(path: readonly number[], rule: Rule | null): string {
  if (path.length === 0 || rule === null) return "q0 (no rule matched, pack default applied)";
  return `${path.map((state) => `q${state}`).join(" -> ")} -> ACCEPT: ${rule.ruleId}`;
}

/** Classifies log lines against a rule pack. */
export class PolicyEngine {
  private readonly pack: RulePack;
  private readonly automaton: Automaton;
  private readonly order = new Map<string, number>();
  private windows = new Map<string, SlidingWindow>();

  constructor(pack: RulePack) {
    this.pack = pack;
    this.automaton = new Automaton().compile(pack.rules);
    pack.rules.forEach((rule, index) => this.order.set(rule.ruleId, index));
    this.reset();
  }

  /** Forget every sliding window. Call this between files. */
  reset(): void {
    this.windows = new Map(
      this.pack.rules
        .filter(isThresholdRule)
        .map((rule) => [
          rule.ruleId,
          new SlidingWindow(rule.threshold, rule.windowSeconds || DEFAULT_WINDOW_EVENTS),
        ]),
    );
  }

  /** Report whether one matching rule should beat another. */
  private outranks(candidate: Rule, holder: Rule): boolean {
    if (candidate.priority !== holder.priority) return candidate.priority > holder.priority;
    return (this.order.get(candidate.ruleId) ?? 0) < (this.order.get(holder.ruleId) ?? 0);
  }

  /** Classify one event. */
  classify(event: LogEvent, position: number): Verdict {
    let winner: Rule | null = null;
    let winningPath: readonly number[] = [];
    let winningHits = 1;

    for (const match of this.automaton.match(event.tokens)) {
      const rule = match.rule;
      let hits = 1;

      if (isThresholdRule(rule)) {
        const window = this.windows.get(rule.ruleId);
        if (!window) continue;
        hits = window.record(event.source, position);
        if (!window.isTripped(hits)) continue;
      }

      if (winner === null || this.outranks(rule, winner)) {
        winner = rule;
        winningPath = match.path;
        winningHits = hits;
      }
    }

    const decision = winner ? winner.decision : this.pack.defaultDecision;
    return {
      line: event.lineNumber,
      raw: event.raw,
      decision,
      ruleId: winner ? winner.ruleId : "default",
      ruleLabel: winner ? winner.label : "",
      severity: winner && decision === "alert" ? winner.severity : "",
      path: [...winningPath],
      pathText: describePath(winningPath, winner),
      reason: winner ? explain(winner, winningHits) : "No rule matched, so the pack default applied.",
      source: event.source,
    };
  }

  /** Classify raw log text, skipping blank lines. */
  classifyText(text: string): Report {
    this.reset();
    const counts: Record<Decision, number> = { allow: 0, alert: 0, ignore: 0 };
    const verdicts: Verdict[] = [];
    let position = 0;

    // Split the way Python's splitlines does for the shapes a log has, and
    // drop a single trailing empty string so a file ending in a newline does
    // not produce one extra blank event.
    const lines = text.split("\n");
    if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();

    lines.forEach((raw, index) => {
      const event = parseEvent(raw, index + 1);
      if (event.isBlank) return;
      position += 1;
      const verdict = this.classify(event, position);
      counts[verdict.decision] += 1;
      verdicts.push(verdict);
    });

    return {
      policy: this.pack.name,
      counts,
      verdicts,
      automaton: this.automaton.describe(),
    };
  }
}
