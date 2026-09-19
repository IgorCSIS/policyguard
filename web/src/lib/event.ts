/**
 * Log line parsing, ported from policyguard/event.py.
 *
 * The regular expressions are the same ones, written in JavaScript syntax.
 * They are the highest parity risk in the whole port, because a difference
 * of one character class silently changes which rules match, so they are
 * covered directly by the parity check rather than trusted.
 */

/** Characters that split a line into tokens. */
const TOKEN_SPLIT = /[^A-Za-z0-9_.:@/-]+/;

/** Trailing and leading punctuation stripped from each token. */
const TRIM = new Set([".", ":", ",", ";"]);

/** Matches an IPv4 address anywhere in a line. */
const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

/** Matches the account name in the shapes auth logs actually use. */
const USER = /\b(?:user|for)\s+(?:invalid\s+)?(?:user\s+)?([A-Za-z_][A-Za-z0-9_.-]*)/i;

/** Used when a line has no address in it, so grouping still has a key. */
export const UNKNOWN_SOURCE = "-";

/** A single log line and the tokens the automaton runs over. */
export interface LogEvent {
  raw: string;
  lineNumber: number;
  tokens: readonly string[];
  source: string;
  user: string;
  isBlank: boolean;
}

/** Strip the characters Python's str.strip(".:,;") removes from both ends. */
function trimPunctuation(token: string): string {
  let start = 0;
  let end = token.length;
  while (start < end && TRIM.has(token[start] as string)) start += 1;
  while (end > start && TRIM.has(token[end - 1] as string)) end -= 1;
  return token.slice(start, end);
}

/** Split a line into lower-cased tokens. */
export function tokenize(raw: string): string[] {
  const out: string[] = [];
  for (const piece of raw.toLowerCase().split(TOKEN_SPLIT)) {
    const token = trimPunctuation(piece);
    if (token) out.push(token);
  }
  return out;
}

/**
 * Parse one log line.
 *
 * @param raw The line as read, with or without a trailing newline.
 * @param lineNumber Which line of the file this was, counting from one.
 */
export function parseEvent(raw: string, lineNumber = 0): LogEvent {
  const line = raw.replace(/\n$/, "");
  const tokens = tokenize(line);
  const address = IPV4.exec(line);
  const account = USER.exec(line);
  return {
    raw: line,
    lineNumber,
    tokens,
    source: address ? address[0] : UNKNOWN_SOURCE,
    user: account?.[1] ? account[1].toLowerCase() : "",
    isBlank: tokens.length === 0,
  };
}

/** Turn raw lines into events, numbering them from one including blanks. */
export function eventsFromLines(lines: readonly string[]): LogEvent[] {
  return lines.map((raw, index) => parseEvent(raw, index + 1));
}
