const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function response(data) {
  return { ok: true, status: 200, json: async () => data, text: async () => JSON.stringify(data) };
}

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

function harness() {
  const timers = new Map();
  let timerId = 0;
  const element = () => ({
    disabled: false, textContent: "", innerHTML: "", title: "", dataset: {},
    listeners: {}, addEventListener(name, callback) { this.listeners[name] = callback; },
  });
  const elements = Object.fromEntries(
    ["runBtn", "stopBtn", "manualBtn", "healthLine", "activityDiagnostic", "runStatus", "currentRun", "runsList"]
      .map((id) => [id, element()]),
  );
  const h = { timers, elements, calls: [], runs: [{ id: 134, status: "canceled" }] };
  h.fetch = async (url, options) => {
    if (options.method === "POST") return response({ status: "canceled", run_id: 134, run_ids: [134], force: true });
    if (url.startsWith("/api/runs?")) return response({ runs: h.runs });
    if (url.startsWith("/api/runs/")) return response({ run: h.runs[0], logs: [], findings: [] });
    if (url.startsWith("/api/cases")) return response({ cases: [] });
    throw new Error(`Unexpected request ${url}`);
  };
  const context = vm.createContext({
    document: {
      body: { dataset: { page: "monitor" } },
      getElementById: (id) => elements[id] || null,
      querySelectorAll: () => [], addEventListener: () => {},
    },
    window: { addEventListener: () => {} },
    localStorage: { getItem: () => "", setItem: () => {}, removeItem: () => {} },
    URLSearchParams, AbortController, DOMException,
    console: { error: () => {}, log: () => {} }, alert: () => {},
    setTimeout(callback, delay) { const id = ++timerId; timers.set(id, { callback, delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
    fetch: (url, options) => { h.calls.push({ url, options }); return h.fetch(url, options); },
  });
  const source = fs.readFileSync(path.join(__dirname, "../app/static/app.js"), "utf8");
  // Import the page's actual functions without issuing its automatic startup requests.
  const withoutStartup = source.replace(/bootstrap\(\)\.catch\(console\.error\);\s*$/, "");
  assert.notEqual(source, withoutStartup);
  vm.runInContext(`${withoutStartup}\n globalThis.frontend = {
    state, api, stopRun, syncStopButton, syncActionButtons, loadRuns, loadRun,
    hardStopAll: typeof hardStopAll === "function" ? hardStopAll : null,
  };`, context);
  h.ui = context.frontend;
  h.prime = (status = "canceling") => {
    h.ui.state.runs = [{ id: 134, status }];
    h.ui.state.selectedRunId = 134;
    h.ui.state.runStatuses.set(134, status);
    h.ui.syncStopButton(); h.ui.syncActionButtons();
  };
  h.fireDeadlines = () => {
    for (const [id, timer] of [...timers]) {
      timers.delete(id); timer.callback();
    }
  };
  return h;
}

const flush = () => new Promise((resolve) => setImmediate(resolve));

test("a canceling run keeps the main hard-stop control available after page load", () => {
  const h = harness(); h.prime();
  assert.equal(h.elements.stopBtn.disabled, false);
  assert.equal(h.elements.stopBtn.textContent, "Жёсткий стоп");
  assert.equal(h.elements.runBtn.disabled, true);
});

test("main hard stop calls cancel-all and only fresh terminal DB state enables Start", async () => {
  const h = harness(); h.prime("running");
  assert.equal(typeof h.ui.hardStopAll, "function");
  const pendingPost = deferred();
  const normalFetch = h.fetch;
  h.fetch = (url, options) => options.method === "POST" ? pendingPost.promise : normalFetch(url, options);
  const stopping = h.ui.hardStopAll();
  await flush();
  assert.equal(h.elements.stopBtn.textContent, "Прерываю");
  assert.equal(h.elements.runBtn.disabled, true);
  assert.equal(h.calls[0].url, "/api/runs/cancel-all");
  assert.equal(h.ui.state.runs[0].status, "running", "No optimistic terminal status");
  pendingPost.resolve(response({ status: "canceled", run_ids: [134], force: true }));
  await stopping;
  assert.equal(h.elements.stopBtn.disabled, false);
  assert.equal(h.elements.runBtn.disabled, false);
  assert.equal(h.ui.state.runStatuses.get(134), "canceled");
});

test("a failed refresh never unlocks Start from the cancel POST alone", async () => {
  const h = harness(); h.prime("running");
  assert.equal(typeof h.ui.hardStopAll, "function");
  h.fetch = async (url, options) => {
    if (options.method === "POST") return response({ status: "canceled", run_ids: [134], force: true });
    throw new Error("Database read unavailable");
  };
  await assert.rejects(h.ui.hardStopAll());
  assert.equal(h.elements.stopBtn.disabled, false);
  assert.equal(h.elements.stopBtn.textContent, "Жёсткий стоп");
  assert.equal(h.elements.runBtn.disabled, true);
});

test("a failed stop can be retried and a later terminal read clears the Start lock", async () => {
  const h = harness(); h.prime("running");
  assert.equal(typeof h.ui.hardStopAll, "function");
  const normalFetch = h.fetch;
  h.fetch = async () => { throw new Error("Network offline"); };
  await assert.rejects(h.ui.hardStopAll());
  assert.equal(h.elements.stopBtn.disabled, false);
  assert.equal(h.elements.runBtn.disabled, true);
  h.fetch = normalFetch;
  await h.ui.loadRuns();
  assert.equal(h.elements.runBtn.disabled, false);
});

test("late reads from before hard stop cannot resurrect a running status or polling lock", async () => {
  const h = harness(); h.prime("running");
  assert.equal(typeof h.ui.hardStopAll, "function");
  const oldRead = deferred();
  const normalFetch = h.fetch;
  let firstRead = true;
  h.fetch = (url, options) => {
    if (url.startsWith("/api/runs/134?") && firstRead) { firstRead = false; return oldRead.promise; }
    return normalFetch(url, options);
  };
  const stale = h.ui.loadRun(134, { force: true }).catch(() => {});
  h.ui.state.pollInFlight = true;
  await h.ui.hardStopAll();
  oldRead.resolve(response({ run: { id: 134, status: "running" }, logs: [], findings: [] }));
  await stale; await flush();
  assert.equal(h.ui.state.runStatuses.get(134), "canceled");
  assert.equal(h.elements.runBtn.disabled, false);
  assert.equal(h.ui.state.pollInFlight, false);
});

test("a stalled stop response body times out and releases the busy control", async () => {
  const h = harness(); h.prime("running");
  assert.equal(typeof h.ui.hardStopAll, "function");
  h.fetch = async () => ({ ok: true, status: 200, json: () => new Promise(() => {}) });
  const stopping = h.ui.hardStopAll();
  const rejected = assert.rejects(stopping, /врем|таймаут|timeout/i);
  await flush();
  assert.ok(h.timers.size, "The stop request must have a deadline");
  h.fireDeadlines();
  await rejected;
  assert.equal(h.elements.stopBtn.disabled, false);
  assert.equal(h.elements.runBtn.disabled, true);
});

test("per-run stop retains the existing id endpoint and also bounds stalled requests", async () => {
  const h = harness(); h.prime("running");
  h.fetch = () => new Promise(() => {});
  const stopping = h.ui.stopRun(134);
  stopping.catch(() => {});
  await flush();
  assert.equal(h.calls[0].url, "/api/runs/134/cancel");
  assert.ok(h.timers.size, "The per-run stop must have a deadline");
  h.fireDeadlines();
  await assert.rejects(stopping, /врем|таймаут|timeout/i);
  assert.equal(h.ui.state.stoppingRunIds.size, 0);
  assert.equal(h.elements.stopBtn.disabled, false);
});

test("stopping one run succeeds while another run remains active", async () => {
  const h = harness(); h.prime("running");
  h.runs = [{ id: 134, status: "canceled" }, { id: 135, status: "running" }];
  await h.ui.stopRun(134);
  assert.equal(h.ui.state.runStatuses.get(134), "canceled");
  assert.equal(h.ui.state.runStatuses.get(135), "running");
  assert.equal(h.ui.state.stopConfirmationPending, false);
  assert.equal(h.elements.runBtn.disabled, true);
});

test("the actual main button handler uses the global endpoint", async () => {
  const h = harness(); h.prime();
  h.elements.stopBtn.listeners.click();
  await flush();
  assert.equal(h.calls.find((call) => call.options.method === "POST").url, "/api/runs/cancel-all");
});

test("a fresh canceling DB status keeps Start locked and hard stop retryable", async () => {
  const h = harness(); h.prime("running");
  h.runs = [{ id: 134, status: "canceling" }];
  await assert.rejects(h.ui.hardStopAll(), /не подтвердил/);
  assert.equal(h.elements.runBtn.disabled, true);
  assert.equal(h.elements.stopBtn.disabled, false);
});

test("hard stop does not abort the independent health request", async () => {
  const h = harness(); h.prime("running");
  const pendingHealth = deferred();
  const normalFetch = h.fetch;
  h.fetch = (url, options) => url === "/api/health" ? pendingHealth.promise : normalFetch(url, options);
  const health = h.ui.api("/api/health");
  await h.ui.hardStopAll();
  const healthRequest = h.calls.find((call) => call.url === "/api/health");
  assert.equal(healthRequest.options.signal.aborted, false);
  pendingHealth.resolve(response({ status: "ok" }));
  assert.equal((await health).status, "ok");
});
