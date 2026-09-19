/**
 * Rules and rule packs, ported from policyguard/rule.py.
 *
 * Python is the source of truth for rule semantics. This file mirrors it so
 * the browser demo and the Python CLI agree, and scripts/check-parity.mjs
 * fails the build if they ever stop agreeing. When changing behaviour, change
 * the Python first, then port it here, then run the parity check.
 */

/** What a rule says to do with a line. */
export type Decision = "allow" | "alert" | "ignore";

/** The three decisions, in the order reports list them. */
export const DECISIONS: readonly Decision[] = ["allow", "alert", "ignore"];

/**
 * Default priority per decision, mirroring DEFAULT_PRIORITY in rule.py.
 *
 * An explicit allow outranks an alert. That is the allow-list behaviour a
 * policy engine is expected to have, and it is the sharpest edge in the
 * design, so it is written down here as well as in the Python and the README.
 */
const DEFAULT_PRIORITY: Readonly<Record<Decision, number>> = {
  allow: 100,
  alert: 50,
  ignore: 10,
};

const SEVERITIES = ["info", "low", "medium", "high"] as const;
const DEFAULT_SEVERITY = "medium";

/** One policy rule. */
export interface Rule {
  ruleId: string;
  label: string;
  decision: Decision;
  pattern: readonly string[];
  priority: number;
  severity: string;
  description: string;
  threshold: number;
  windowSeconds: number;
}

/** An ordered collection of rules loaded from one pack. */
export interface RulePack {
  name: string;
  rules: readonly Rule[];
  defaultDecision: Decision;
}

/** Raised when a pack is malformed, matching RulePackError in Python. */
export class RulePackError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RulePackError";
  }
}

/** Report whether a rule needs repeats before it fires. */
export function isThresholdRule(rule: Rule): boolean {
  return rule.threshold > 1;
}

/** Turn a string from a pack into a decision, refusing anything else. */
function parseDecision(value: string): Decision {
  const cleaned = value.trim().toLowerCase();
  if (cleaned === "allow" || cleaned === "alert" || cleaned === "ignore") return cleaned;
  throw new RulePackError(`Unknown decision "${value}". Use one of: allow, alert, ignore.`);
}

/** Build one rule from a pack entry, applying the same checks as Python. */
function parseRule(raw: Record<string, unknown>): Rule {
  for (const field of ["id", "decision", "pattern"]) {
    if (!(field in raw)) throw new RulePackError(`Rule is missing the required field "${field}".`);
  }

  const ruleId = String(raw["id"]).trim();
  if (!ruleId) throw new RulePackError("Every rule needs a non-empty id.");

  const rawPattern = raw["pattern"];
  const tokens = (typeof rawPattern === "string" ? rawPattern.split(/\s+/) : rawPattern) as unknown;
  if (!Array.isArray(tokens)) {
    throw new RulePackError(`Rule "${ruleId}" has a pattern that is neither a string nor a list.`);
  }
  const pattern = tokens.map((token) => String(token).trim().toLowerCase()).filter(Boolean);
  if (pattern.length === 0) throw new RulePackError(`Rule "${ruleId}" has an empty pattern.`);

  const decision = parseDecision(String(raw["decision"]));
  const threshold = raw["threshold"] === undefined ? 1 : Number(raw["threshold"]);
  if (!Number.isInteger(threshold) || threshold < 1) {
    throw new RulePackError(`Rule "${ruleId}" has a threshold below one.`);
  }

  const severity = raw["severity"] === undefined ? DEFAULT_SEVERITY : String(raw["severity"]);
  if (!(SEVERITIES as readonly string[]).includes(severity)) {
    throw new RulePackError(
      `Rule "${ruleId}" has severity "${severity}". Use one of: ${SEVERITIES.join(", ")}.`,
    );
  }

  const priority = raw["priority"];
  if (priority !== undefined && !Number.isInteger(priority)) {
    throw new RulePackError(`Rule "${ruleId}" has a non-integer priority.`);
  }

  return {
    ruleId,
    label: String(raw["label"] ?? "").trim() || ruleId,
    decision,
    pattern,
    priority: priority === undefined ? DEFAULT_PRIORITY[decision] : Number(priority),
    severity,
    description: String(raw["description"] ?? "").trim(),
    threshold,
    windowSeconds: Math.max(0, Number(raw["window_seconds"] ?? 0)),
  };
}

/**
 * Parse a rule pack document.
 *
 * @param document The decoded JSON of a pack file.
 * @param name Falls back to the document's own name field.
 */
export function parseRulePack(document: unknown, name = ""): RulePack {
  if (typeof document !== "object" || document === null) {
    throw new RulePackError("A rule pack should be a JSON object.");
  }
  const raw = document as Record<string, unknown>;
  if (!Array.isArray(raw["rules"])) throw new RulePackError('A rule pack needs a "rules" list.');

  const rules = (raw["rules"] as Record<string, unknown>[]).map(parseRule);
  if (rules.length === 0) throw new RulePackError("A rule pack needs at least one rule.");

  const seen = new Set<string>();
  for (const rule of rules) {
    if (seen.has(rule.ruleId)) {
      throw new RulePackError(`Duplicate rule id "${rule.ruleId}" in the pack.`);
    }
    seen.add(rule.ruleId);
  }

  return {
    name: name || String(raw["name"] ?? "rule pack"),
    rules,
    defaultDecision: parseDecision(String(raw["default_decision"] ?? "ignore")),
  };
}
