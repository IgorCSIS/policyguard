/**
 * PolicyGuard: the browser demo.
 *
 * One screen. Paste log lines or load the sample, and every line comes back
 * labelled with the rule that decided and the automaton path that fired.
 *
 * The engine under this is a port of the Python package, and
 * scripts/check-parity.mjs proves the two agree on the shipped sample. What
 * the page shows is what the Python CLI would say about the same log.
 *
 * Nothing is uploaded. The rule pack and the sample log are fetched from this
 * site's own folder on load, and after that the page makes no requests at all.
 */

import "./style.css";
import { PolicyEngine, type Report, type Verdict } from "./lib/engine.ts";
import { parseRulePack, RulePackError, type Decision, type RulePack } from "./lib/rules.ts";

const PORTFOLIO_URL = "https://igorcsis.github.io/niftyai-portfolio/";
const REPO_URL = "https://github.com/IgorCSIS/policyguard";
const POLICY_URL = `${import.meta.env.BASE_URL}baseline.json`;
const SAMPLE_URL = `${import.meta.env.BASE_URL}office-auth.log`;

type Filter = Decision | "all";

interface State {
  pack: RulePack | null;
  engine: PolicyEngine | null;
  report: Report | null;
  filter: Filter;
  text: string;
  notice: { kind: "info" | "error"; text: string } | null;
  /** True while the rule pack is still being fetched and compiled. */
  busy: boolean;
  /** True for the frame between pressing a button and the verdicts existing. */
  classifying: boolean;
}

const state: State = {
  pack: null,
  engine: null,
  report: null,
  filter: "all",
  text: "",
  notice: null,
  busy: true,
  classifying: false,
};

const app = document.querySelector<HTMLDivElement>("#app");
if (!app) throw new Error("#app not found");

/* ------------------------------------------------------------------ view */

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function header(): string {
  return `
    <header class="border-b border-slate-700">
      <div class="mx-auto flex max-w-5xl items-center justify-between gap-4 px-5 py-4">
        <div class="flex items-center gap-2.5">
          <svg viewBox="0 0 32 32" class="h-7 w-7" aria-hidden="true">
            <rect width="32" height="32" rx="7" fill="#0D141E"/>
            <path d="M16 5.5 25 9v7.2c0 5.2-3.6 9.4-9 11.3-5.4-1.9-9-6.1-9-11.3V9z" fill="none" stroke="#2DD4BF" stroke-width="2.2" stroke-linejoin="round"/>
            <circle cx="12.4" cy="15.4" r="1.9" fill="#2DD4BF"/>
            <circle cx="19.6" cy="15.4" r="1.9" fill="#5EEAD4"/>
            <path d="M14.3 15.4h3.4" stroke="#5EEAD4" stroke-width="1.6" stroke-linecap="round"/>
          </svg>
          <span class="font-semibold text-mist-50">PolicyGuard</span>
        </div>
        <a href="${REPO_URL}" target="_blank" rel="noopener noreferrer"
           class="text-sm text-mist-400 hover:text-teal-300">Source and CLI</a>
      </div>
    </header>`;
}

function hero(): string {
  return `
    <section class="mx-auto max-w-5xl px-5 pt-6 sm:pt-10">
      <h1 class="text-2xl font-bold leading-tight tracking-tight text-mist-50 sm:text-3xl">
        Paste a log. See allow, alert, or ignore with the rule that fired.
      </h1>
      <p class="mt-4 max-w-2xl leading-relaxed">
        Paste log lines. Each one comes back labelled allow, alert, or ignore, with the rule and
        the state path behind the decision.
      </p>
      <p class="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-mist-400">
        <span class="badge badge-trust">Stays on this device</span>
        <span>Educational demo. It classifies logs. It does not block, scan, or contact anything.</span>
      </p>
    </section>`;
}

function inputPanel(): string {
  const packLine = state.pack
    ? `${escapeHtml(state.pack.name)}, ${state.pack.rules.length} rules`
    : "Loading rules\u2026";

  // While the pack is loading there is nothing useful either button can do,
  // so they say so rather than looking live and swallowing a click.
  const classifyLabel = state.busy
    ? "Loading rules\u2026"
    : state.classifying
      ? "Classifying\u2026"
      : "Classify these lines";
  const sampleLabel = state.busy ? "Loading rules\u2026" : "Load sample and classify";

  const waiting = state.busy || state.classifying;
  const hasText = state.text.trim() !== "";

  // Whichever action is actually useful right now is the filled one. With an
  // empty box that is loading the sample; with text in it, classifying what
  // is there. Nothing moves, only the emphasis changes.
  const classifyTone = hasText ? "btn-primary" : "btn-ghost";
  const sampleTone = hasText ? "btn-ghost" : "btn-primary";

  return `
    <section class="mx-auto mt-5 max-w-5xl px-5 sm:mt-8">
      <div class="card p-4 sm:p-5" aria-busy="${waiting}">
        <div class="flex flex-wrap items-baseline justify-between gap-2">
          <h2 class="text-sm font-semibold text-mist-50">Log lines</h2>
          <span class="font-mono text-xs text-mist-400">${packLine}</span>
        </div>
        <label class="sr-only" for="log-input">Log lines to classify</label>
        <textarea id="log-input" rows="7" spellcheck="false"
          class="mt-3 h-24 w-full rounded-lg border border-slate-600 bg-slate-950 p-3 font-mono
                 text-xs leading-relaxed text-mist-200 placeholder:text-mist-400/60
                 focus:border-teal-400 sm:h-auto"
          placeholder="Sep 19 01:20:02 vpn-gw sshd[4001]: Failed password for invalid user admin from 203.0.113.42 port 55102 ssh2">${escapeHtml(state.text)}</textarea>
        <div class="mt-4 flex flex-wrap gap-2">
          <button id="load-sample" type="button" class="btn ${sampleTone}" ${waiting ? "disabled" : ""}>
            ${sampleLabel}
          </button>
          <button id="classify" type="button" class="btn ${classifyTone}"
                  ${waiting || !hasText ? "disabled" : ""}>
            ${classifyLabel}
          </button>
          <button id="clear" type="button" class="btn btn-ghost" ${hasText ? "" : "disabled"}>Clear</button>
        </div>
      </div>
    </section>`;
}

function noticeBlock(): string {
  if (!state.notice) return "";
  const tone =
    state.notice.kind === "error"
      ? "border-verdict-alert/40 bg-verdict-alert-bg text-verdict-alert"
      : "border-slate-600 bg-slate-900 text-mist-200";
  return `
    <section class="mx-auto mt-5 max-w-5xl px-5">
      <p role="status" class="rounded-card border px-4 py-3 text-sm ${tone}">${escapeHtml(state.notice.text)}</p>
    </section>`;
}

function summary(): string {
  const report = state.report;
  if (!report) return "";
  const order: Decision[] = ["alert", "allow", "ignore"];
  const tabs = (["all", ...order] as Filter[])
    .map((filter) => {
      const count = filter === "all" ? report.verdicts.length : report.counts[filter];
      const text = filter === "all" ? `All ${count}` : `${filter} ${count}`;
      return `<button type="button" class="filter-tab" data-filter="${filter}"
                aria-pressed="${state.filter === filter}">${text}</button>`;
    })
    .join("");

  // Sticky, because the filter is what somebody reaches for after scrolling
  // half of sixty six verdicts, and scrolling back up to find it is friction
  // for no reason.
  return `
    <section class="sticky top-0 z-20 mx-auto mt-8 max-w-5xl px-5">
      <div class="summary-bar rounded-card border border-slate-700 bg-slate-950/95 p-3 backdrop-blur"
           data-active-filter="${state.filter}">
        <div class="flex flex-wrap items-center justify-between gap-3">
          <h2 class="text-sm font-semibold text-mist-50">${report.verdicts.length} lines classified</h2>
          <div class="flex flex-wrap rounded-lg border border-slate-700 p-0.5">${tabs}</div>
        </div>
        ${
          state.filter === "all"
            ? ""
            : `<p class="mt-2 text-xs text-mist-400">Showing ${escapeHtml(state.filter)} only.
                 <button id="clear-filter" type="button"
                   class="underline underline-offset-2 hover:text-teal-300">Show all</button></p>`
        }
      </div>
    </section>`;
}

/**
 * The automaton's size, and what the model actually is.
 *
 * Both are interesting and neither belongs in front of somebody who has not
 * classified anything yet, so they sit behind a toggle underneath the
 * results where a curious reader will find them and nobody else has to.
 */
function howItWorks(): string {
  const report = state.report;
  if (!report) return "";
  return `
    <section class="mx-auto mt-2 max-w-5xl px-5 pb-16">
      <details class="detail-toggle card p-4">
        <summary>How it works</summary>
        <div class="mt-3 space-y-3 text-sm leading-relaxed text-mist-400">
          <p>
            Every rule is a sequence of tokens. All of them are compiled once into a single
            deterministic finite automaton, so matching a line costs one table lookup per word
            and does not get slower as rules are added.
          </p>
          <p>
            This pack compiled to
            <span class="font-mono text-xs text-teal-300">${escapeHtml(report.automaton)}</span>.
          </p>
          <p>
            The same rules run as a Python command line tool, and a parity check proves both
            give identical answers on the sample.
            <a href="${REPO_URL}" target="_blank" rel="noopener noreferrer"
               class="text-teal-300 underline underline-offset-2">Source and CLI</a>.
          </p>
        </div>
      </details>
    </section>`;
}

function verdictRow(verdict: Verdict): string {
  const severity =
    verdict.severity && verdict.decision === "alert"
      ? `<span class="font-mono text-[0.7rem] text-mist-400">${escapeHtml(verdict.severity)}</span>`
      : "";

  // The human sentence sits in the summary row, so a reader gets the reason
  // without opening anything. The state path is the detail, one tap away,
  // which is what keeps eight verdicts readable on a phone.
  return `
    <li class="card verdict-${verdict.decision}-edge p-4">
      <div class="flex flex-wrap items-center gap-2">
        <span class="font-mono text-xs text-mist-400">line ${verdict.line}</span>
        <span class="badge badge-${verdict.decision}">${verdict.decision}</span>
        <span class="text-sm font-semibold text-mist-50">${escapeHtml(verdict.ruleLabel || "no rule matched")}</span>
        ${severity}
        <span class="font-mono text-[0.7rem] text-mist-400">${escapeHtml(verdict.ruleId)}</span>
      </div>
      <pre class="mt-2.5 overflow-x-auto whitespace-pre-wrap break-words rounded border border-slate-700 bg-slate-950 p-2.5 font-mono text-xs leading-relaxed text-mist-200">${escapeHtml(verdict.raw)}</pre>
      <details class="detail-toggle mt-2.5">
        <summary>${escapeHtml(verdict.reason)}</summary>
        <p class="mt-2 overflow-x-auto font-mono text-xs text-teal-300">${escapeHtml(verdict.pathText)}</p>
      </details>
    </li>`;
}

function results(): string {
  const report = state.report;
  if (!report) return "";

  const shown =
    state.filter === "all"
      ? report.verdicts
      : report.verdicts.filter((verdict) => verdict.decision === state.filter);

  if (shown.length === 0) {
    return `
      <section class="mx-auto mt-5 max-w-5xl px-5">
        <p class="card p-8 text-center text-mist-400">
          No ${escapeHtml(state.filter)} lines in this log. Switch back to All to see the rest.
        </p>
      </section>`;
  }

  return `
    <section id="results" class="mx-auto mt-5 max-w-5xl px-5">
      <ul class="grid gap-3">${shown.map(verdictRow).join("")}</ul>
    </section>`;
}

/**
 * What the page shows before anything has been classified.
 *
 * The three chips are the point. A stranger sees the verdict vocabulary and
 * its colours before pressing anything, so the first screen of results is
 * already familiar rather than a wall of new labels. They are plain spans:
 * nothing here is clickable, because nothing here should invite a click.
 */
function emptyState(): string {
  if (state.report || state.busy) return "";
  const chips: [Decision, string][] = [
    ["alert", "worth a person looking"],
    ["allow", "known good, on purpose"],
    ["ignore", "real, and not interesting"],
  ];
  return `
    <section class="mx-auto mt-5 max-w-5xl px-5 pb-16">
      <div class="card p-8 text-center">
        <p class="text-mist-200">Nothing classified yet.</p>
        <p class="mt-2 text-sm text-mist-400">
          Load the sample to see all three verdicts, or paste your own lines above.
          Syslog and auth.log shapes work best, because that is what the shipped rules describe.
        </p>
        <ul class="mt-6 flex flex-wrap items-center justify-center gap-3">
          ${chips
            .map(
              ([decision, meaning]) => `
            <li class="flex items-center gap-2">
              <span class="badge badge-sample badge-${decision}">${decision}</span>
              <span class="text-xs text-mist-400">${meaning}</span>
            </li>`,
            )
            .join("")}
        </ul>
      </div>
    </section>`;
}

function footer(): string {
  return `
    <footer class="border-t border-slate-700">
      <div class="mx-auto flex max-w-5xl flex-col gap-3 px-5 py-8 text-sm text-mist-400 sm:flex-row sm:items-center sm:justify-between">
        <p>Classifies logs. Never blocks, scans, or contacts anything.</p>
        <div class="flex flex-wrap gap-4">
          <span>Educational demo. Defensive classification only.</span>
          <a href="${PORTFOLIO_URL}" target="_blank" rel="noopener noreferrer" class="hover:text-teal-300">
            Built by Igor Lima
          </a>
        </div>
      </div>
    </footer>`;
}

function render(): void {
  if (!app) return;
  app.innerHTML = [
    header(),
    hero(),
    inputPanel(),
    noticeBlock(),
    summary(),
    results(),
    howItWorks(),
    emptyState(),
    footer(),
  ].join("");
  bind();
}

/* --------------------------------------------------------------- behavior */

function classifyCurrentText(): void {
  if (!state.engine) {
    state.notice = {
      kind: "error",
      text: "The rule pack has not loaded yet. Give it a moment and try again.",
    };
    render();
    return;
  }

  const field = document.querySelector<HTMLTextAreaElement>("#log-input");
  state.text = field?.value ?? state.text;

  // Only a genuinely empty box is an error. A box holding whitespace or a
  // line nothing matches is a perfectly good thing to classify, and saying
  // otherwise would be lying about the tool.
  if (state.text.trim() === "") {
    state.report = null;
    state.notice = { kind: "error", text: "Paste some log lines first, or load the sample." };
    render();
    return;
  }

  state.classifying = true;
  state.notice = { kind: "info", text: "Classifying..." };
  render();

  // One frame of real feedback before the work. Classification is fast
  // enough that the label would otherwise never paint, and a button that
  // flashes nothing looks broken on a slow machine rather than instant.
  window.requestAnimationFrame(() => {
    const engine = state.engine;
    if (!engine) return;

    state.report = engine.classifyText(state.text);
    // Back to All on every run, so a filter left on from last time cannot
    // make a fresh log look empty.
    state.filter = "all";
    state.classifying = false;

    const counts = state.report.counts;
    state.notice = {
      kind: "info",
      text:
        `${state.report.verdicts.length} lines classified: ` +
        `${counts.alert} alert, ${counts.allow} allow, ${counts.ignore} ignore.`,
    };
    render();

    document.getElementById("results")?.scrollIntoView({
      behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
      block: "start",
    });
  });
}

async function loadSample(): Promise<void> {
  try {
    const response = await fetch(SAMPLE_URL);
    if (!response.ok) throw new Error(String(response.status));
    state.text = await response.text();
    state.notice = null;
    render();
    classifyCurrentText();
  } catch {
    state.notice = {
      kind: "error",
      text: "The sample log could not be loaded. Paste your own lines instead.",
    };
    render();
  }
}

/**
 * Enable or disable the controls that only make sense with text present.
 *
 * Called on every keystroke, so it edits the two buttons in place instead of
 * re-rendering. Classify with an empty box would do nothing but show an
 * error, and a control that can only fail should not look ready.
 */
function syncTextDependentButtons(): void {
  const hasText = state.text.trim() !== "";
  const classify = document.querySelector<HTMLButtonElement>("#classify");
  const clear = document.querySelector<HTMLButtonElement>("#clear");
  if (classify) {
    classify.disabled = !hasText || state.busy || state.classifying;
    classify.classList.toggle("btn-primary", hasText);
    classify.classList.toggle("btn-ghost", !hasText);
  }
  const sample = document.querySelector<HTMLButtonElement>("#load-sample");
  if (sample) {
    sample.classList.toggle("btn-primary", !hasText);
    sample.classList.toggle("btn-ghost", hasText);
  }
  if (clear) clear.disabled = !hasText;
}

function bind(): void {
  if (!app) return;

  app.querySelector<HTMLButtonElement>("#classify")?.addEventListener("click", classifyCurrentText);
  app.querySelector<HTMLButtonElement>("#load-sample")?.addEventListener("click", () => void loadSample());

  app.querySelector<HTMLButtonElement>("#clear")?.addEventListener("click", () => {
    state.text = "";
    state.report = null;
    state.notice = null;
    render();
    document.getElementById("log-input")?.focus();
  });

  const field = app.querySelector<HTMLTextAreaElement>("#log-input");
  field?.addEventListener("input", () => {
    // Kept in state so a re-render does not throw away what was typed.
    state.text = field.value;
    // Toggled directly rather than by re-rendering, because re-rendering the
    // panel while somebody is typing in it would take the caret with it.
    syncTextDependentButtons();
  });

  app.querySelector<HTMLButtonElement>("#clear-filter")?.addEventListener("click", () => {
    state.filter = "all";
    render();
  });

  // button[data-filter], not [data-filter]. The summary container used to
  // carry the same attribute to describe the active filter, which meant this
  // bound the container too and every click bubbled into a no-op reset.
  app.querySelectorAll<HTMLButtonElement>("button[data-filter]").forEach((button) => {
    button.addEventListener("click", () => {
      state.filter = (button.dataset.filter as Filter | undefined) ?? "all";
      render();
    });
  });
}

/**
 * How long the loading state stays up even when there is nothing to wait for.
 *
 * The rule pack is a small file served from the same origin, so on a warm
 * cache it arrives in a few milliseconds and the busy state would flicker
 * past unseen. A state nobody can see is a state nobody can trust, and the
 * flicker itself reads as a glitch. This holds it just long enough to
 * register as deliberate.
 */
const MINIMUM_BOOT_PAINT_MS = 180;

/** Resolve after a delay, so the boot state is visible rather than implied. */
function pause(milliseconds: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

/** Fetch the rule pack this demo enforces, then let the buttons work. */
async function boot(): Promise<void> {
  const started = performance.now();
  try {
    const response = await fetch(POLICY_URL);
    if (!response.ok) throw new Error(String(response.status));
    state.pack = parseRulePack(await response.json());
    state.engine = new PolicyEngine(state.pack);
  } catch (error) {
    state.notice = {
      kind: "error",
      text:
        error instanceof RulePackError
          ? `The rule pack is not valid: ${error.message}`
          : "The rule pack could not be loaded, so nothing can be classified right now.",
    };
  } finally {
    const elapsed = performance.now() - started;
    if (elapsed < MINIMUM_BOOT_PAINT_MS) await pause(MINIMUM_BOOT_PAINT_MS - elapsed);
    state.busy = false;
    render();
  }
}

render();
void boot();
