/**
 * Tests for the TypeScript port.
 *
 * The parity check already proves this agrees with Python on the shipped
 * sample. These cover the edges parity cannot reach, because they are cases
 * the sample does not contain.
 */

import test from "node:test";
import assert from "node:assert/strict";

import { PolicyEngine } from "../src/lib/engine.ts";
import { parseEvent, tokenize } from "../src/lib/event.ts";
import { parseRulePack, RulePackError } from "../src/lib/rules.ts";

const PACK = {
  name: "test pack",
  default_decision: "ignore",
  rules: [
    { id: "probe", decision: "alert", pattern: ["invalid", "user"], severity: "medium" },
    { id: "good", decision: "allow", pattern: ["accepted", "publickey"] },
    { id: "noise", decision: "ignore", pattern: ["health", "probe", "ok"] },
    {
      id: "brute",
      decision: "alert",
      pattern: ["failed", "password", "for"],
      threshold: 5,
      window_seconds: 20,
      severity: "high",
    },
  ],
};

function engine() {
  return new PolicyEngine(parseRulePack(PACK));
}

test("tokenizing folds case and splits log punctuation", () => {
  assert.deepEqual(tokenize("Failed PASSWORD For Root"), ["failed", "password", "for", "root"]);
  const tokens = tokenize("Sep 19 01:20:02 vpn-gw sshd[4001]: Failed password");
  assert.ok(tokens.includes("sshd"));
  assert.ok(tokens.includes("4001"));
});

test("an account name is pulled out of the shapes auth logs use", () => {
  assert.equal(parseEvent("session opened for user backupsvc").user, "backupsvc");
  assert.equal(parseEvent("Failed password for invalid user admin").user, "admin");
  assert.equal(parseEvent("kernel: usb device connected").user, "");
});

test("a line with no address still gets a grouping key", () => {
  assert.equal(parseEvent("sudo: authentication failure").source, "-");
  assert.equal(parseEvent("sshd: from 203.0.113.42 port 1").source, "203.0.113.42");
});

test("each decision comes back for a line that earns it", () => {
  const report = engine().classifyText(
    [
      "sshd: Failed password for invalid user admin from 10.0.0.1",
      "sshd: Accepted publickey for itadmin from 10.0.0.2",
      "healthcheck: health probe ok target=x",
      "kernel: usb 2-1 new device",
    ].join("\n"),
  );
  assert.deepEqual(
    report.verdicts.map((verdict) => verdict.decision),
    ["alert", "allow", "ignore", "ignore"],
  );
  assert.equal(report.verdicts[3]?.ruleId, "default");
});

test("blank lines are skipped but never renumber the ones that follow", () => {
  const report = engine().classifyText("\n\ninvalid user bob\n\n");
  assert.equal(report.verdicts.length, 1);
  assert.equal(report.verdicts[0]?.line, 3);
});

test("empty input classifies nothing and does not throw", () => {
  const report = engine().classifyText("");
  assert.equal(report.verdicts.length, 0);
  assert.deepEqual(report.counts, { allow: 0, alert: 0, ignore: 0 });
});

test("a threshold rule fires on the event that reaches the threshold", () => {
  const line = "sshd: Failed password for root from 10.0.0.9";
  const report = engine().classifyText(Array.from({ length: 6 }, () => line).join("\n"));
  const decisions = report.verdicts.map((verdict) => verdict.decision);
  assert.deepEqual(decisions.slice(0, 4), ["ignore", "ignore", "ignore", "ignore"]);
  assert.equal(decisions[4], "alert");
});

test("threshold hits are counted per source", () => {
  const lines: string[] = [];
  for (let i = 0; i < 4; i += 1) {
    lines.push("sshd: Failed password for root from 10.0.0.1");
    lines.push("sshd: Failed password for root from 10.0.0.2");
  }
  const report = engine().classifyText(lines.join("\n"));
  assert.equal(report.counts.alert, 0);
});

test("classifying twice gives the same answers", () => {
  const text = "sshd: Failed password for invalid user admin from 10.0.0.1";
  const shared = engine();
  assert.deepEqual(shared.classifyText(text).verdicts, shared.classifyText(text).verdicts);
});

test("the path starts at q0 and names the rule that accepted", () => {
  const report = engine().classifyText("noise noise invalid user bob");
  const verdict = report.verdicts[0];
  assert.ok(verdict);
  assert.ok(verdict.pathText.startsWith("q0 -> "));
  assert.ok(verdict.pathText.endsWith("ACCEPT: probe"));
  assert.equal(verdict.path.length, 3);
});

test("an unmatched line says so instead of faking a path", () => {
  const report = engine().classifyText("kernel: nothing interesting here");
  assert.match(report.verdicts[0]?.pathText ?? "", /no rule matched/);
});

test("a malformed pack is refused with the field named", () => {
  assert.throws(
    () => parseRulePack({ rules: [{ id: "x", decision: "alert" }] }),
    (error: unknown) => {
      assert.ok(error instanceof RulePackError);
      assert.match((error as Error).message, /pattern/);
      return true;
    },
  );
  assert.throws(() => parseRulePack({ rules: [] }), /at least one rule/);
  assert.throws(
    () => parseRulePack({ rules: [{ id: "x", decision: "block", pattern: ["y"] }] }),
    /Unknown decision/,
  );
});

test("duplicate rule ids are refused", () => {
  assert.throws(
    () =>
      parseRulePack({
        rules: [
          { id: "same", decision: "alert", pattern: ["a"] },
          { id: "same", decision: "ignore", pattern: ["b"] },
        ],
      }),
    /Duplicate rule id/,
  );
});
