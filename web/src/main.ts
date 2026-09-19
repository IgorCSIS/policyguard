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
  busy: boolean;
}

const state: State = {
  pack: null,
  engine: null,
  report: null,
  filter: "all",
  text: "",
  notice: null,
  busy: true,
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
    <section class="mx-auto max-w-5xl px-5 pt-10">
      <h1 class="text-3xl font-bold tracking-tight text-mist-50">Defensive log policy as a DFA</h1>
      <p class="mt-4 max-w-2xl leading-relaxed">
        Paste log lines. Every one comes back labelled allow, alert, or ignore, with the rule that
        decided and the automaton path that fired. The policy is compiled once into a
        deterministic finite automaton, so adding rules does not slow the matching down.
      </p>
      <p class="mt-3 text-sm text-mist-400">
        Educational demo. It reads logs and classifies them. It does not block, scan, or contact
        anything.
      </p>
      <p class="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-mist-400">
        <span class="badge badge-allow">In your browser</span>
        <span>Whatever you paste stays on this device. Nothing is uploaded.</span>
      </p>
    </section>`;
}

function inputPanel(): string {
  const packLine = state.pack
    ? `${escapeHtml(state.pack.name)}, ${state.pack.rules.length} rules`
    : "loading the rule pack";
  return `
    <section class="mx-auto mt-8 max-w-5xl px-5">
      <div class="card p-5">
        <div class="flex flex-wrap items-baseline justify-between gap-2">
          <h2 class="text-sm font-semibold text-mist-50">Log lines</h2>
          <span class="font-mono text-xs text-mist-400">${packLine}</span>
        </div>
        <label class="sr-only" for="log-input">Log lines to classify</label>
        <textarea id="log-input" rows="7" spellcheck="false"
          class="mt-3 w-full rounded-lg border border-slate-600 bg-slate-950 p-3 font-mono text-xs
                 leading-relaxed text-mist-200 placeholder:text-mist-400/60 focus:border-teal-400 focus:outline-none"
          placeholder="Sep 19 01:20:02 vpn-gw sshd[4001]: Failed password for invalid user admin from 203.0.113.42 port 55102 ssh2">${escapeHtml(state.text)}</textarea>
        <div class="mt-4 flex flex-wrap gap-2">
          <button id="classify" type="button" class="btn btn-primary" ${state.busy ? "disabled" : ""}>
            Classify these lines
          </button>
          <button id="load-sample" type="button" class="btn btn-ghost" ${state.busy ? "disabled" : ""}>
            Load the sample log
          </button>
          <button id="clear" type="button" class="btn btn-ghost">Clear</button>
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
      const count =
        filter === "all"
          ? report.verdicts.length
          : report.counts[filter];
      const text = filter === "all" ? `All ${count}` : `${filter} ${count}`;
      return `<button type="button" class="filter-tab" data-filter="${filter}"
                aria-pressed="${state.filter === filter}">${text}</button>`;
    })
    .join("");

  return `
    <section class="mx-auto mt-8 max-w-5xl px-5">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div class="flex flex-wrap items-center gap-2">
          <h2 class="text-sm font-semibold text-mist-50">${report.verdicts.length} lines classified</h2>
          <span class="font-mono text-xs text-mist-400">${escapeHtml(report.automaton)}</span>
        </div>
        <div class="flex flex-wrap rounded-lg border border-slate-700 p-0.5">${tabs}</div>
      </div>
    </section>`;
}

function verdictRow(verdict: Verdict): string {
  const badge = `badge badge-${verdict.decision}`;
  const severity =
    verdict.severity && verdict.decision === "alert"
      ? `<span class="font-mono text-[0.7rem] text-mist-400">${escapeHtml(verdict.severity)}</span>`
      : "";
  return `
    <li class="card p-4">
      <div class="flex flex-wrap items-center gap-2">
        <span class="font-mono text-xs text-mist-400">line ${verdict.line}</span>
        <span class="${badge}">${verdict.decision}</span>
        <span class="text-sm font-semibold text-mist-50">${escapeHtml(verdict.ruleLabel || "no rule matched")}</span>
        ${severity}
        <span class="font-mono text-[0.7rem] text-mist-400">${escapeHtml(verdict.ruleId)}</span>
      </div>
      <pre class="mt-2.5 overflow-x-auto whitespace-pre-wrap break-words rounded border border-slate-700 bg-slate-950 p-2.5 font-mono text-xs leading-relaxed text-mist-200">${escapeHtml(verdict.raw)}</pre>
      <p class="mt-2.5 overflow-x-auto font-mono text-xs text-teal-300">${escapeHtml(verdict.pathText)}</p>
      <p class="mt-1.5 text-sm text-mist-400">${escapeHtml(verdict.reason)}</p>
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
      <section class="mx-auto mt-5 max-w-5xl px-5 pb-16">
        <p class="card p-8 text-center text-mist-400">
          Nothing in this log was called ${escapeHtml(state.filter)}. Switch back to All to see the rest.
        </p>
      </section>`;
  }

  return `
    <section id="results" class="mx-auto mt-5 max-w-5xl px-5 pb-16">
      <ul class="grid gap-3">${shown.map(verdictRow).join("")}</ul>
    </section>`;
}

function emptyState(): string {
  if (state.report || state.busy) return "";
  return `
    <section class="mx-auto mt-5 max-w-5xl px-5 pb-16">
      <div class="card p-8 text-center">
        <p class="text-mist-200">Nothing classified yet.</p>
        <p class="mt-2 text-sm text-mist-400">
          Load the sample log to see all three decisions, or paste your own lines above.
          Syslog and auth.log shapes work best, because that is what the shipped rules describe.
        </p>
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
    emptyState(),
    footer(),
  ].join("");
  bind();
}

/* --------------------------------------------------------------- behavior */

function classifyCurrentText(): void {
  if (!state.engine) {
    state.notice = { kind: "error", text: "The rule pack has not loaded yet. Give it a moment and try again." };
    render();
    return;
  }
  const field = document.querySelector<HTMLTextAreaElement>("#log-input");
  state.text = field?.value ?? state.text;

  if (!state.text.trim()) {
    state.report = null;
    state.notice = { kind: "error", text: "Paste some log lines first, or load the sample." };
    render();
    return;
  }

  state.report = state.engine.classifyText(state.text);
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

  app.querySelector<HTMLTextAreaElement>("#log-input")?.addEventListener("input", (event) => {
    // Kept in state so a re-render does not throw away what was typed.
    state.text = (event.target as HTMLTextAreaElement).value;
  });

  app.querySelectorAll<HTMLButtonElement>("[data-filter]").forEach((button) => {
    button.addEventListener("click", () => {
      state.filter = (button.dataset.filter as Filter | undefined) ?? "all";
      render();
    });
  });
}

/** Fetch the rule pack this demo enforces, then let the buttons work. */
async function boot(): Promise<void> {
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
    state.busy = false;
    render();
  }
}

render();
void boot();
