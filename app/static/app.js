const state = {
  selectedRunId: null,
  pollTimer: null,
  pollInFlight: false,
  pollRunsCounter: 0,
  cases: [],
  filteredCases: [],
  runs: [],
  activityRunId: null,
  apiToken: localStorage.getItem("argus_api_token") || "",
  authRequired: true,
  authConfigured: false,
  caseDetails: new Map(),
  runDetails: new Map(),
  runStatuses: new Map(),
  runFindingsExpanded: false,
  lastLiveFindingCount: 0,
  visibleCasesLimit: 8,
  chartPoints: [],
  chartHoverIndex: null,
};

const DEFAULT_RUN_CANDIDATES = 100;
const MAX_RUN_CANDIDATES = 500;
const CASES_INITIAL_LIMIT = 8;
const CASES_PAGE_SIZE = 20;
const POLL_INTERVAL_MS = 3000;

const els = {
  scanForm: document.getElementById("scanForm"),
  healthLine: document.getElementById("healthLine"),
  healthToggle: document.getElementById("healthToggle"),
  healthDetails: document.getElementById("healthDetails"),
  geminiPill: document.getElementById("geminiPill"),
  kzAccessPill: document.getElementById("kzAccessPill"),
  runBtn: document.getElementById("runBtn"),
  stopBtn: document.getElementById("stopBtn"),
  seedQuery: document.getElementById("seedQuery"),
  searchMode: document.getElementById("searchMode"),
  runSize: document.getElementById("runSize"),
  takeScreenshots: document.getElementById("takeScreenshots"),
  manualTarget: document.getElementById("manualTarget"),
  manualBtn: document.getElementById("manualBtn"),
  activityPanel: document.getElementById("activityPanel"),
  activityHeadline: document.getElementById("activityHeadline"),
  activitySteps: document.getElementById("activitySteps"),
  activityText: document.getElementById("activityText"),
  currentRun: document.getElementById("currentRun"),
  runStatus: document.getElementById("runStatus"),
  activeCaseCount: document.getElementById("activeCaseCount"),
  highRiskCount: document.getElementById("highRiskCount"),
  evidenceCount: document.getElementById("evidenceCount"),
  trendChart: document.getElementById("trendChart"),
  chartTooltip: document.getElementById("chartTooltip"),
  caseSearch: document.getElementById("caseSearch"),
  categoryFilter: document.getElementById("categoryFilter"),
  caseMinRisk: document.getElementById("caseMinRisk"),
  caseFilterBtn: document.getElementById("caseFilterBtn"),
  exportCasesCsvBtn: document.getElementById("exportCasesCsvBtn"),
  exportCasesXlsxBtn: document.getElementById("exportCasesXlsxBtn"),
  exportRunCsvBtn: document.getElementById("exportRunCsvBtn"),
  exportRunXlsxBtn: document.getElementById("exportRunXlsxBtn"),
  toggleRunFindingsBtn: document.getElementById("toggleRunFindingsBtn"),
  casesList: document.getElementById("casesList"),
  runFindingsList: document.getElementById("runFindingsList"),
  runFindingsCount: document.getElementById("runFindingsCount"),
  runsList: document.getElementById("runsList"),
  methodologyList: document.getElementById("methodologyList"),
  logsList: document.getElementById("logsList"),
  warningCount: document.getElementById("warningCount"),
  drawerOverlay: document.getElementById("drawerOverlay"),
  drawerClose: document.getElementById("drawerClose"),
  drawerTitle: document.getElementById("drawerTitle"),
  caseDetailContent: document.getElementById("caseDetailContent"),
  authOverlay: document.getElementById("authOverlay"),
  authForm: document.getElementById("authForm"),
  authHint: document.getElementById("authHint"),
  apiTokenInput: document.getElementById("apiTokenInput"),
  clearTokenBtn: document.getElementById("clearTokenBtn"),
};

const statusLabels = {
  queued: "в очереди",
  running: "идет поиск",
  canceling: "останавливается",
  canceled: "остановлено",
  interrupted: "прервано",
  completed: "готово",
  failed: "ошибка",
};

const categoryLabels = {
  legit: "Низкий риск",
  casino: "Казино",
  online_casino: "Онлайн-казино",
  betting: "Букмекер",
  sports_betting_review: "Букмекер/проверка",
  phishing: "Фишинг",
  pyramid: "Пирамиды",
  investment_pyramid: "Пирамиды",
  empty_or_parked: "Пустой сайт",
  suspicious: "Подозрительный",
};

const categoryColors = {
  legit: "#10b981",
  casino: "#f59e0b",
  online_casino: "#f59e0b",
  betting: "#38bdf8",
  sports_betting_review: "#38bdf8",
  phishing: "#ef4444",
  pyramid: "#8b5cf6",
  investment_pyramid: "#8b5cf6",
  empty_or_parked: "#64748b",
  suspicious: "#3b82f6",
};

const modelLabelLabels = {
  legit: "похож на обычный сайт",
  casino: "похож на казино",
  online_casino: "похож на онлайн-казино",
  betting: "похож на букмекер/ставки",
  sports_betting_review: "похож на букмекера, нужна проверка лицензии",
  phishing: "похож на фишинг",
  pyramid: "похож на финансовую пирамиду",
  investment_pyramid: "похож на финансовую пирамиду",
  empty_or_parked: "пустой или parking-сайт",
  suspicious: "требует проверки",
};

const levelLabels = {
  info: "инфо",
  warning: "внимание",
  error: "ошибка",
};

const featureLabels = {
  phishing_keyword_count: "слова входа, пароля или кошелька",
  casino_keyword_count: "слова казино, ставок или бонусов",
  pyramid_keyword_count: "обещания дохода или инвестиций",
  subdomain_count: "много уровней в домене",
  path_length: "длинный путь страницы",
  digit_count: "цифры в адресе",
  suspicious_tld: "рискованная доменная зона",
  domain_age_days: "возраст домена",
  ssl_valid: "состояние SSL",
  password_form_count: "форма ввода пароля",
  num_password_forms: "форма ввода пароля",
  num_suspicious_patterns: "подозрительный JavaScript",
  num_hidden_elements: "скрытые элементы страницы",
  casino_confidence_score: "уверенность по казино-маркерам",
  betting_confidence_score: "уверенность по betting-маркерам",
  betting_keywords_count: "слова букмекера или ставок",
  trusted_domain: "доверенный домен",
  site_quality_score: "качество страницы",
  has_brand_impersonation: "упоминание чужого бренда",
  has_casino_in_url: "казино/ставки в адресе",
  has_betting_in_url: "букмекер/ставки в адресе",
  num_external_links: "много внешних ссылок",
  num_iframes: "встроенные чужие блоки",
};

const activityStages = [
  { key: "search", label: "Поиск", detail: "AI ищет кандидатов" },
  { key: "open", label: "Открытие", detail: "Проверка доступности" },
  { key: "evidence", label: "Доказательства", detail: "DNS, SSL, HTML" },
  { key: "report", label: "Отчет", detail: "Запись в реестр" },
];

async function api(path, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };
  if (state.apiToken) {
    headers.Authorization = `Bearer ${state.apiToken}`;
  }
  const response = await fetch(path, {
    ...options,
    headers,
  });
  if (!response.ok) {
    const text = await response.text();
    if (response.status === 401) {
      showAuth(text || response.statusText);
    }
    throw new Error(text || response.statusText);
  }
  return response.json();
}

async function downloadFile(path) {
  const headers = {};
  if (state.apiToken) {
    headers.Authorization = `Bearer ${state.apiToken}`;
  }
  const response = await fetch(path, { headers });
  if (response.status === 401) {
    const text = await response.text();
    showAuth(text || response.statusText);
    throw new Error(text || response.statusText);
  }
  if (!response.ok) {
    throw new Error(await response.text() || response.statusText);
  }
  const blob = await response.blob();
  const disposition = response.headers.get("content-disposition") || "";
  const match = disposition.match(/filename="?([^"]+)"?/i);
  const filename = match?.[1] || path.split("/").pop()?.split("?")[0] || "argus-export";
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function normalizeAuthMessage(message) {
  try {
    const parsed = JSON.parse(message);
    if (parsed.detail) return parsed.detail;
  } catch {
    // Response is already plain text.
  }
  return String(message);
}

function showAuth(message = "") {
  if (!els.authOverlay) return;
  els.authOverlay.hidden = false;
  if (els.authHint) {
    els.authHint.textContent = message
      ? normalizeAuthMessage(message)
      : "Введите ADMIN_TOKEN, который задан в Render Environment.";
  }
  if (els.apiTokenInput) {
    els.apiTokenInput.value = state.apiToken;
    setTimeout(() => els.apiTokenInput.focus(), 30);
  }
}

function hideAuth() {
  if (els.authOverlay) els.authOverlay.hidden = true;
}

function setActionLock(locked, reason = "") {
  [els.runBtn, els.manualBtn].forEach((button) => {
    if (!button) return;
    button.disabled = locked;
    button.title = reason || "";
  });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function relPath(path) {
  if (!path) return null;
  return String(path).replaceAll("\\", "/").replace(/^\/+/, "");
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleDateString("ru-RU");
}

function formatDateTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("ru-RU", { dateStyle: "short", timeStyle: "short" });
}

function formatBytes(bytes) {
  const value = Number(bytes || 0);
  if (!value) return "N/A";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

function formatResponseTime(ms) {
  const value = Number(ms || 0);
  if (!value) return "N/A";
  if (value < 1000) return `${value} мс`;
  return `${(value / 1000).toFixed(2)} сек`;
}

function formatPercent(value) {
  const number = Number(value || 0);
  if (!number) return "N/A";
  return `${Math.round(number * 100)}%`;
}

function normalizeCategory(value) {
  const text = String(value || "").toLowerCase();
  if (/(legit|benign|trusted|low_signal)/.test(text)) return "legit";
  if (/(betting|bookmaker|sports_betting)/.test(text)) return "betting";
  if (/(casino|gambling)/.test(text)) return "casino";
  if (/(phishing|scam|malware)/.test(text)) return "phishing";
  if (/(pyramid|investment)/.test(text)) return "pyramid";
  return "suspicious";
}

function categoryLabel(value) {
  return categoryLabels[normalizeCategory(value)] || "Подозрительный";
}

function modelLabel(value) {
  const key = String(value || "").toLowerCase();
  return modelLabelLabels[key] || value || "нет вывода";
}

function riskClass(score) {
  const value = Number(score || 0);
  if (value >= 80) return "high";
  if (value >= 55) return "mid";
  return "low";
}

function runningStatus(status) {
  return ["queued", "running", "canceling"].includes(status);
}

function terminalStatus(status) {
  return ["completed", "failed", "canceled", "interrupted"].includes(status);
}

function hasRunningRuns() {
  return state.runs.some((run) => runningStatus(run.status))
    || Array.from(state.runStatuses.values()).some((status) => runningStatus(status));
}

function latestLog(logs = []) {
  return logs.length ? logs[logs.length - 1] : null;
}

function activityStageIndex(run = {}, logs = []) {
  if (terminalStatus(run.status)) {
    return activityStages.length - 1;
  }
  const last = latestLog(logs) || {};
  const meta = last.meta || {};
  if (Number(run.finding_count || 0) > 0 || meta.risk_score !== undefined) return 3;
  if (meta.path || meta.html_sha256) return 2;
  if (meta.url || meta.domain) return 1;
  const text = logs.map((log) => `${log.message || ""} ${JSON.stringify(log.meta || {})}`).join(" ").toLowerCase();
  if (/добавлен|отчет|заверш|report|complete/.test(text)) return 3;
  if (/скрин|html|sha|dns|tls|ssl|доказ|screenshot|evidence/.test(text)) return 2;
  if (/открываю|ручного анализа|кандидат|доступ|candidate|opening|url/.test(text)) return 1;
  return 0;
}

function showActivity(run = {}, logs = []) {
  if (!els.activityPanel) return;
  const active = runningStatus(run.status);
  const done = terminalStatus(run.status);
  if (active && run.id) state.activityRunId = run.id;
  if (done && run.id && state.activityRunId !== run.id) {
    els.activityPanel.hidden = true;
    return;
  }
  if (!active && !done && !logs.length) {
    els.activityPanel.hidden = true;
    return;
  }

  const stageIndex = activityStageIndex(run, logs);
  const last = latestLog(logs);
  els.activityPanel.hidden = false;
  els.activityPanel.classList.toggle("done", done && run.status === "completed");
  els.activityPanel.classList.toggle("failed", done && run.status === "failed");
  els.activityPanel.classList.toggle("interrupted", done && ["canceled", "interrupted"].includes(run.status));
  els.activityHeadline.textContent = run.id
    ? `Запуск #${run.id}: ${runStatusLabel(run)}`
    : "Запуск создан";
  els.activityText.textContent = last
    ? `${formatDateTime(last.timestamp)} · ${last.message}${formatMeta(last.meta)}`
    : "Задача поставлена в очередь, ожидаю первые события анализа.";
  els.activitySteps.innerHTML = activityStages.map((stage, index) => {
    const cls = index < stageIndex ? "done" : index === stageIndex ? "active" : "";
    return `
      <div class="activity-step ${cls}">
        <span>${index + 1}</span>
        <strong>${escapeHtml(stage.label)}</strong>
        <small>${escapeHtml(stage.detail)}</small>
      </div>`;
  }).join("");
}

function primeActivity(runId, mode = "auto") {
  state.activityRunId = runId;
  showActivity(
    { id: runId, status: "queued", finding_count: 0, candidate_count: 0 },
    [
      {
        timestamp: new Date().toISOString(),
        level: "info",
        message: mode === "manual" ? "Ручная проверка поставлена в очередь" : "Поиск поставлен в очередь",
        meta: {},
      },
    ],
  );
}

function certDate(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function certDaysLeft(tls = {}) {
  if (Number.isFinite(Number(tls.expires_in_days))) return Number(tls.expires_in_days);
  const date = certDate(tls.not_after);
  if (!date) return null;
  return Math.floor((date.getTime() - Date.now()) / 86400000);
}

function statusLabel(status) {
  return statusLabels[status] || status || "-";
}

function runStatusLabel(run) {
  if (!run) return "-";
  const error = String(run.error || "");
  if (run.status === "failed" && /сервер|render|остановлен/i.test(error)) {
    return "прервано";
  }
  return statusLabel(run.status);
}

function renderPill(el, text, cls) {
  el.textContent = text;
  el.className = `health-pill ${cls}`;
}

function setHealthDetailsOpen(open) {
  if (!els.healthToggle || !els.healthDetails) return;
  els.healthToggle.setAttribute("aria-expanded", String(open));
  els.healthDetails.hidden = !open;
}

async function loadHealth() {
  try {
    const health = await api("/api/health");
    state.authRequired = Boolean(health.auth_required);
    state.authConfigured = Boolean(health.auth_configured);
    const geminiWarnings = Array.isArray(health.gemini_key_warnings) ? health.gemini_key_warnings : [];
    const geminiOk = Boolean(health.gemini_configured && health.gemini_key_format_ok);
    const geminiText = !health.gemini_configured
      ? "AI: нет ключа"
      : geminiWarnings.length
        ? "AI: проверь формат"
        : "AI: ключи загружены";
    renderPill(els.geminiPill, geminiText, geminiOk ? "ok" : "warn");
    const kzReady = Boolean(health.kz_proxy_ready);
    const kzRequired = Boolean(health.kz_proxy_required);
    const kzText = health.kz_proxy_configured ? "KZ: proxy" : kzRequired ? "KZ: нет proxy" : "KZ: direct";
    renderPill(els.kzAccessPill, kzText, health.kz_proxy_configured ? "ok" : kzRequired ? "bad" : "warn");
    const keyCount = health.gemini_key_count ?? health.gemini_keys?.length ?? 0;
    const keyHashes = Array.isArray(health.gemini_key_hashes) ? health.gemini_key_hashes : [];
    const hashHint = keyHashes.length ? `, hash ${keyHashes.join(", ")}` : "";
    const authMissing = state.authRequired && !state.authConfigured;
    const geminiModels = Array.isArray(health.gemini_models) && health.gemini_models.length
      ? health.gemini_models.join(" → ")
      : health.gemini_model;
    const geminiHint = health.gemini_configured
      ? `${keyCount} ключ(а), модели ${geminiModels}${hashHint}`
      : "добавьте GEMINI_API_KEYS";
    const mlClasses = Array.isArray(health.ml_classes) && health.ml_classes.length ? ` (${health.ml_classes.join(", ")})` : "";
    const mlHint = health.ml_available
      ? `ML: CatBoost готов${mlClasses}`
      : health.ml_enabled
        ? "ML: модель недоступна"
        : "ML: выключен";
    const cyberHint = health.cyberscan_ml_available
      ? `CyberScan: ${health.cyberscan_feature_count || 34} признака`
      : health.cyberscan_ml_enabled
        ? "CyberScan: модель недоступна"
        : "CyberScan: выключен";
    const kzHint = health.kz_proxy_configured
      ? `${health.kz_access_label}${health.kz_proxy_source ? ` (${health.kz_proxy_source})` : ""}`
      : kzRequired
        ? "KZ proxy обязателен и не настроен, запуск заблокирован"
        : "KZ proxy не задан: запуск разрешен, но доступность из Казахстана не подтверждена";
    const concurrency = health.scan_concurrency || 3;
    const timeout = health.candidate_timeout_seconds || 15;
    const maxRun = Math.min(Number(health.max_candidates_per_run || MAX_RUN_CANDIDATES), MAX_RUN_CANDIDATES);
    els.healthLine.textContent = `${geminiHint}. ${mlHint}. ${cyberHint}. ${kzHint}. Цель запуска: до ${maxRun} находок, потоков: ${concurrency}, таймаут сайта: ${timeout} сек.`;
    const actionBlocked = authMissing || !kzReady;
    const actionReason = authMissing
      ? "На сервере не настроен ADMIN_TOKEN"
      : !kzReady
        ? "Настройте KZ_PROXY_URL, KZ_HTTP_PROXY, KZ_HTTPS_PROXY или KZ_PROXY"
        : "";
    setActionLock(actionBlocked, actionReason);
    if (authMissing) {
      els.healthLine.textContent = `${els.healthLine.textContent} ADMIN_TOKEN не настроен, запуски защищенного API недоступны.`;
      hideAuth();
    } else if (state.authRequired && !state.apiToken) {
      showAuth("Введите ADMIN_TOKEN для доступа к API.");
    }
  } catch (error) {
    renderPill(els.geminiPill, "AI: ошибка", "bad");
    renderPill(els.kzAccessPill, "KZ: ошибка", "bad");
    els.healthLine.textContent = error.message;
  }
}

async function startRun(event) {
  event?.preventDefault();
  els.runBtn.disabled = true;
  els.runBtn.textContent = "Запускаю";
  showActivity(
    { status: "queued" },
    [{ timestamp: new Date().toISOString(), level: "info", message: "Отправляю задачу автоматического поиска", meta: {} }],
  );
  try {
    const requestedCandidates = Number(els.runSize?.value || DEFAULT_RUN_CANDIDATES);
    const payload = {
      seed_query: els.seedQuery.value.trim() || null,
      search_mode: els.searchMode?.value || "casino",
      max_candidates: Math.max(1, Math.min(requestedCandidates, MAX_RUN_CANDIDATES)),
      take_screenshots: els.takeScreenshots.checked,
    };
    const result = await api("/api/runs", { method: "POST", body: JSON.stringify(payload) });
    state.selectedRunId = result.run_id;
    state.runFindingsExpanded = false;
    state.lastLiveFindingCount = 0;
    state.runDetails.delete(result.run_id);
    primeActivity(result.run_id, "auto");
    await loadRuns();
    await loadRun(result.run_id, { force: true });
    startPolling();
  } catch (error) {
    alert(`Не удалось запустить проверку: ${error.message}`);
  } finally {
    els.runBtn.disabled = false;
    els.runBtn.textContent = "Запустить";
  }
}

async function startManualCheck() {
  const target = els.manualTarget?.value.trim() || "";
  if (!target) {
    alert("Укажите домен или URL для ручной проверки.");
    els.manualTarget?.focus();
    return;
  }
  els.manualBtn.disabled = true;
  els.manualBtn.textContent = "Проверяю";
  showActivity(
    { status: "queued" },
    [{ timestamp: new Date().toISOString(), level: "info", message: "Отправляю задачу ручной проверки", meta: { url: target } }],
  );
  try {
    const payload = {
      target,
      take_screenshots: els.takeScreenshots.checked,
    };
    const result = await api("/api/manual-check", { method: "POST", body: JSON.stringify(payload) });
    state.selectedRunId = result.run_id;
    state.runFindingsExpanded = false;
    state.lastLiveFindingCount = 0;
    state.runDetails.delete(result.run_id);
    primeActivity(result.run_id, "manual");
    await loadRuns();
    await loadRun(result.run_id, { force: true });
    startPolling();
  } catch (error) {
    alert(`Не удалось запустить ручную проверку: ${error.message}`);
  } finally {
    els.manualBtn.disabled = false;
    els.manualBtn.textContent = "Проверить сайт";
  }
}

async function stopRun(runId = state.selectedRunId) {
  if (!runId) return;
  if (runId === state.selectedRunId) els.stopBtn.disabled = true;
  const runIndex = state.runs.findIndex((item) => item.id === runId);
  if (runIndex >= 0) {
    state.runs[runIndex] = { ...state.runs[runIndex], status: "canceling" };
    renderRuns();
  }
  await api(`/api/runs/${runId}/cancel`, { method: "POST" });
  state.runDetails.delete(runId);
  await loadRun(runId, { force: true });
  await loadRuns();
}

async function loadRuns() {
  const data = await api("/api/runs?limit=40");
  state.runs = data.runs || [];
  const runIds = new Set(state.runs.map((run) => run.id));
  Array.from(state.runStatuses.keys()).forEach((runId) => {
    if (!runIds.has(runId) && runId !== state.selectedRunId) state.runStatuses.delete(runId);
  });
  state.runs.forEach((run) => state.runStatuses.set(run.id, run.status));
  if (!state.selectedRunId && state.runs.length) state.selectedRunId = state.runs[0].id;
  renderRuns();
}

async function loadRun(runId, options = {}) {
  if (!runId) return;
  const cached = state.runDetails.get(runId);
  const canUseCache = cached && !options.force && !runningStatus(cached.run?.status);
  const includeFindings = Boolean(options.includeFindings || state.runFindingsExpanded);
  const suffix = includeFindings ? "?include_findings=true" : "";
  const data = canUseCache && (!includeFindings || cached.findings)
    ? cached
    : await api(`/api/runs/${runId}${suffix}`);
  if (!data.findings && cached?.findings) data.findings = cached.findings;
  if (!canUseCache || includeFindings) state.runDetails.set(runId, data);
  const run = data.run;
  const previousStatus = state.runStatuses.get(run.id);
  state.selectedRunId = run.id;
  state.runStatuses.set(run.id, run.status);
  const runIndex = state.runs.findIndex((item) => item.id === run.id);
  if (runIndex >= 0) {
    state.runs[runIndex] = { ...state.runs[runIndex], ...run };
  } else {
    state.runs.unshift(run);
  }

  els.currentRun.textContent = `#${run.id}`;
  const liveFindingCount = Number(run.finding_count || 0);
  els.runStatus.textContent = `${runStatusLabel(run)} · ${liveFindingCount}/${run.candidate_count || 0}`;
  els.stopBtn.disabled = !runningStatus(run.status);

  showActivity(run, data.logs || []);
  renderMethodology(run.methodology || []);
  renderLogs(data.logs || []);
  renderRunFindings(data.findings || [], run, state.runFindingsExpanded);
  renderRuns();

  if (runningStatus(run.status) && liveFindingCount !== state.lastLiveFindingCount) {
    state.lastLiveFindingCount = liveFindingCount;
    await loadCases({ preserveLimit: true });
  }

  if (runningStatus(run.status)) {
    if (!state.pollTimer) startPolling();
  }
  else {
    if (!hasRunningRuns()) stopPolling();
    if (previousStatus && runningStatus(previousStatus)) {
      await loadRuns();
      await loadCases();
    }
    if (hasRunningRuns() && !state.pollTimer) startPolling();
  }
}

function renderRuns() {
  if (!state.runs.length) {
    els.runsList.innerHTML = '<div class="empty-state">Запусков пока нет.</div>';
    return;
  }
  els.runsList.innerHTML = state.runs.map((run) => {
    const active = run.id === state.selectedRunId ? "active" : "";
    const running = runningStatus(run.status);
    const runningClass = running ? "running" : "";
    const signal = runningStatus(run.status) ? "live" : run.status === "failed" ? "bad" : run.status === "interrupted" ? "warn" : "done";
    const hint = ["failed", "interrupted"].includes(run.status) && run.error ? run.error : `${run.finding_count || 0} находок`;
    const stopControl = running
      ? `<button class="run-stop-btn" data-stop-run-id="${run.id}" type="button">Остановить запуск</button>`
      : "";
    return `
      <div class="run-item ${active} ${runningClass}" data-run-id="${run.id}" role="button" tabindex="0">
        <span class="run-signal ${signal}"></span>
        <span>
          <strong>#${run.id}</strong>
          <small>${escapeHtml(formatDateTime(run.started_at))}</small>
        </span>
        <span class="run-state">
          <span>
            <strong>${escapeHtml(runStatusLabel(run))}</strong>
            ${stopControl}
          </span>
          <small>${escapeHtml(hint)}</small>
        </span>
      </div>`;
  }).join("");
  document.querySelectorAll("[data-run-id]").forEach((button) => {
    button.addEventListener("click", () => {
      state.runFindingsExpanded = false;
      loadRun(Number(button.dataset.runId), { force: true }).catch(console.error);
    });
    button.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      state.runFindingsExpanded = false;
      loadRun(Number(button.dataset.runId), { force: true }).catch(console.error);
    });
  });
  document.querySelectorAll("[data-stop-run-id]").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      stopRun(Number(button.dataset.stopRunId)).catch((error) => alert(`Не удалось остановить запуск: ${error.message}`));
    });
  });
}

function renderMethodology(items) {
  if (!els.methodologyList || els.methodologyList.hidden) return;
  if (!items.length) {
    els.methodologyList.innerHTML = '<div class="empty-state">Методика появится после запуска.</div>';
    return;
  }
  els.methodologyList.innerHTML = items.map((item, index) => `
    <div class="method-step">
      <span>${index + 1}</span>
      <p>${escapeHtml(item)}</p>
    </div>
  `).join("");
}

function formatMeta(meta) {
  const parts = formatMetaParts(meta);
  return parts.length ? ` · ${parts.join(" · ")}` : "";
}

function formatMetaParts(meta) {
  if (!meta || !Object.keys(meta).length) return [];
  const parts = [];
  if (meta.name) parts.push(`источник: ${meta.name}`);
  if (meta.category) parts.push(`категория: ${meta.category}`);
  if (meta.domain) parts.push(`домен: ${meta.domain}`);
  if (meta.url) parts.push(`url: ${meta.url}`);
  if (meta.reason) parts.push(`причина: ${meta.reason}`);
  if (meta.access_origin) parts.push(`сеть: ${meta.access_origin}`);
  if (meta.count !== undefined) parts.push(`кол-во: ${meta.count}`);
  if (meta.added !== undefined) parts.push(`добавлено: ${meta.added}`);
  if (meta.skipped !== undefined) parts.push(`пропущено: ${meta.skipped}`);
  if (meta.raw !== undefined) parts.push(`raw: ${meta.raw}`);
  if (meta.deduped !== undefined) parts.push(`после дедупликации: ${meta.deduped}`);
  if (meta.known_rechecked !== undefined) parts.push(`уже известные: ${meta.known_rechecked}`);
  if (meta.skipped_known !== undefined) parts.push(`пропущено повторов: ${meta.skipped_known}`);
  if (meta.ready !== undefined) parts.push(`готово к проверке: ${meta.ready}`);
  if (meta.items !== undefined) parts.push(`items: ${meta.items}`);
  if (meta.sources !== undefined) parts.push(`sources: ${meta.sources}`);
  if (meta.limit !== undefined) parts.push(`лимит: ${meta.limit}`);
  if (meta.index !== undefined) parts.push(`#${meta.index}`);
  if (meta.findings !== undefined) parts.push(`в отчете: ${meta.findings}`);
  if (meta.risk_score !== undefined) parts.push(`риск: ${meta.risk_score}`);
  if (meta.status_code !== undefined && meta.status_code !== null) parts.push(`HTTP: ${meta.status_code}`);
  if (meta.error) parts.push(`ошибка: ${meta.error}`);
  return parts;
}

function renderLogs(logs) {
  const warnings = logs.filter((log) => ["warning", "error"].includes(log.level)).length;
  els.warningCount.textContent = `${warnings} предупреждений`;
  if (!logs.length) {
    els.logsList.innerHTML = '<div class="empty-state">Журнал появится после запуска.</div>';
    return;
  }
  const recentLogs = logs.slice(-45);
  const last = recentLogs[recentLogs.length - 1];
  const summary = `
    <div class="log-live-summary">
      <div>
        <span>Live журнал</span>
        <strong>${escapeHtml(last?.message || "Ожидаю событие")}</strong>
      </div>
      <div>
        <span>${recentLogs.length}/${logs.length} строк</span>
        <strong>${warnings} предупреждений</strong>
      </div>
    </div>`;
  els.logsList.innerHTML = summary + recentLogs.map((log) => {
    const cls = log.level === "error" ? "error" : log.level === "warning" ? "warning" : "";
    const meta = formatMetaParts(log.meta);
    return `
      <div class="log-line ${cls}">
        <span class="log-time">${escapeHtml(formatDateTime(log.timestamp))}</span>
        <strong class="log-level">${escapeHtml(levelLabels[log.level] || log.level)}</strong>
        <div class="log-body">
          <p>${escapeHtml(log.message)}</p>
          ${meta.length ? `<div class="log-meta">${meta.map((item) => `<span>${escapeHtml(item)}</span>`).join("")}</div>` : ""}
        </div>
      </div>`;
  }).join("");
  els.logsList.scrollTop = els.logsList.scrollHeight;
}

async function loadCases(options = {}) {
  const params = new URLSearchParams({ archived: "false", limit: "250" });
  if (els.caseSearch.value.trim()) params.set("q", els.caseSearch.value.trim());
  if (els.caseMinRisk.value) params.set("min_risk", els.caseMinRisk.value);
  const data = await api(`/api/cases?${params.toString()}`);
  if (!options.preserveLimit) state.visibleCasesLimit = CASES_INITIAL_LIMIT;
  state.cases = data.cases || [];
  const category = els.categoryFilter.value;
  state.filteredCases = category
    ? state.cases.filter((item) => normalizeCategory(item.category) === category)
    : state.cases;
  renderCaseStats(state.cases);
  renderCases(state.filteredCases);
  drawTrend(state.cases);
}

async function exportCurrentCases(format) {
  const ids = state.filteredCases.map((item) => item.id).filter(Boolean);
  if (!ids.length) {
    alert("В текущем реестре нет доменов для экспорта.");
    return;
  }
  await downloadFile(`/api/cases/export.${format}?ids=${encodeURIComponent(ids.join(","))}`);
}

async function exportSelectedRun(format) {
  if (!state.selectedRunId) {
    alert("Выберите запуск в истории для экспорта.");
    return;
  }
  await downloadFile(`/api/runs/${state.selectedRunId}/export.${format}`);
}

function renderCaseStats(cases) {
  els.activeCaseCount.textContent = cases.length;
  els.highRiskCount.textContent = cases.filter((item) => Number(item.best_risk_score || 0) >= 70).length;
  els.evidenceCount.textContent = cases.filter((item) => item.html_path || item.screenshot_path).length;
}

function renderCases(cases) {
  if (!cases.length) {
    els.casesList.innerHTML = '<div class="empty-state">В выбранном фильтре нет рабочих доменов.</div>';
    return;
  }
  const visibleLimit = Math.max(CASES_INITIAL_LIMIT, state.visibleCasesLimit);
  const visibleCases = cases.slice(0, visibleLimit);
  const hiddenCount = Math.max(0, cases.length - visibleCases.length);
  const controls = hiddenCount || visibleCases.length > CASES_INITIAL_LIMIT
    ? `
      <div class="case-list-controls">
        <span>Показано ${visibleCases.length} из ${cases.length}</span>
        <div>
          ${hiddenCount ? `<button class="secondary-btn" data-cases-show-more type="button">Показать ещё ${Math.min(CASES_PAGE_SIZE, hiddenCount)}</button>` : ""}
          ${visibleCases.length > CASES_INITIAL_LIMIT ? '<button class="ghost-btn" data-cases-collapse type="button">Свернуть</button>' : ""}
        </div>
      </div>`
    : "";
  els.casesList.innerHTML = visibleCases.map(domainRow).join("") + controls;
  bindCaseOpenButtons(els.casesList);
  els.casesList.querySelector("[data-cases-show-more]")?.addEventListener("click", () => {
    state.visibleCasesLimit += CASES_PAGE_SIZE;
    renderCases(state.filteredCases);
  });
  els.casesList.querySelector("[data-cases-collapse]")?.addEventListener("click", () => {
    state.visibleCasesLimit = CASES_INITIAL_LIMIT;
    renderCases(state.filteredCases);
    document.getElementById("domainsPanel")?.scrollIntoView({ block: "start", behavior: "smooth" });
  });
}

function renderRunFindings(findings, run, expanded = false) {
  if (!els.runFindingsList) return;
  const count = findings.length || Number(run?.finding_count || 0);
  if (els.runFindingsCount) {
    const label = count === 1 ? "1 находка" : `${count} находок`;
    els.runFindingsCount.textContent = run ? `#${run.id} · ${label}` : label;
  }
  if (els.toggleRunFindingsBtn) {
    els.toggleRunFindingsBtn.textContent = expanded ? "Скрыть список" : "Показать список";
    els.toggleRunFindingsBtn.disabled = !run;
  }
  if (!expanded) {
    const status = run ? statusLabel(run.status) : "ожидание";
    const progress = run ? `${run.finding_count || 0}/${run.max_candidates || DEFAULT_RUN_CANDIDATES}` : "0/0";
    els.runFindingsList.innerHTML = `
      <div class="collapsed-results">
        <div>
          <span>Список результатов скрыт</span>
          <strong>${escapeHtml(count)} найдено · ${escapeHtml(status)} · ${escapeHtml(progress)}</strong>
          <p>Полные карточки доменов, SSL/DNS/HTTP и причины риска загружаются только по запросу, чтобы старые запуски открывались быстро.</p>
        </div>
        <button class="secondary-btn" data-expand-run-findings type="button">Открыть список</button>
      </div>`;
    els.runFindingsList.querySelector("[data-expand-run-findings]")?.addEventListener("click", () => {
      toggleRunFindings().catch(console.error);
    });
    return;
  }
  if (!findings.length) {
    const status = run ? statusLabel(run.status) : "ожидание";
    els.runFindingsList.innerHTML = `
      <div class="empty-state">
        В выбранном запуске пока нет доменов в отчете. Статус: ${escapeHtml(status)}.
      </div>`;
    return;
  }
  els.runFindingsList.innerHTML = findings.map(runFindingRow).join("");
  els.runFindingsList.querySelectorAll("[data-run-finding-domain]").forEach((button) => {
    button.addEventListener("click", () => openCaseForFinding(
      button.dataset.runFindingDomain,
      Number(button.dataset.runFindingCase || 0),
    ).catch(console.error));
  });
}

async function toggleRunFindings() {
  state.runFindingsExpanded = !state.runFindingsExpanded;
  const cached = state.selectedRunId ? state.runDetails.get(state.selectedRunId) : null;
  renderRunFindings(cached?.findings || [], cached?.run || null, state.runFindingsExpanded);
  if (state.runFindingsExpanded && state.selectedRunId) {
    await loadRun(state.selectedRunId, { force: true, includeFindings: true });
  }
}

function runFindingRow(item) {
  const risk = Number(item.risk_score || item.best_risk_score || 0);
  const category = normalizeCategory(item.category);
  const evidence = item.evidence || {};
  const reason = (item.reasons || [])[0] || item.verdict || "Зафиксированы технические признаки риска.";
  const source = formatSource((item.sources || [])[0]) || evidence.search_source || evidence.access_origin || "OSINT/ML";
  const domain = item.domain || item.normalized_domain || item.url || "-";
  return `
    <article class="run-finding-row">
      <div class="run-finding-main">
        <button data-run-finding-domain="${escapeHtml(item.normalized_domain || domain)}" data-run-finding-case="${Number(item.case_id || 0)}" type="button">${escapeHtml(domain)}</button>
        <small>${escapeHtml(item.final_url || item.url || item.title || "URL не указан")}</small>
      </div>
      <div class="run-finding-meta">
        <span class="category-badge ${category}">${escapeHtml(categoryLabel(item.category))}</span>
        <span class="risk-badge ${riskClass(risk)}">${risk}%</span>
        ${item.status_code ? `<span class="mini-pill">HTTP ${escapeHtml(item.status_code)}</span>` : ""}
        ${evidence.response_time_ms ? `<span class="mini-pill">${escapeHtml(formatResponseTime(evidence.response_time_ms))}</span>` : ""}
      </div>
      <p>${escapeHtml(reason)}</p>
      <small class="run-finding-source">${escapeHtml(String(source))}</small>
    </article>`;
}

function formatSource(source) {
  if (!source) return "";
  if (typeof source === "string") return source;
  if (typeof source === "object") return source.title || source.url || source.name || "";
  return String(source);
}

async function openCaseForFinding(domain, caseId = 0) {
  if (caseId) {
    await openCase(caseId);
    return;
  }
  const normalized = String(domain || "").toLowerCase();
  let match = state.cases.find((item) => (
    String(item.normalized_domain || item.domain || "").toLowerCase() === normalized
    || String(item.domain || "").toLowerCase() === normalized
  ));
  if (!match) {
    await loadCases();
    match = state.cases.find((item) => (
      String(item.normalized_domain || item.domain || "").toLowerCase() === normalized
      || String(item.domain || "").toLowerCase() === normalized
    ));
  }
  if (match) {
    await openCase(match.id);
  }
}

function bindCaseOpenButtons(root = document) {
  root.querySelectorAll("[data-case-open]").forEach((button) => {
    button.addEventListener("click", () => openCase(Number(button.dataset.caseOpen)).catch(console.error));
  });
}

function domainRow(item) {
  const category = normalizeCategory(item.category);
  const risk = Number(item.best_risk_score || 0);
  return `
    <article class="domain-row" role="row">
      <div class="domain-cell domain-name" role="cell">
        <button data-case-open="${item.id}" type="button">${escapeHtml(item.domain)}</button>
        ${item.title ? `<small>${escapeHtml(item.title)}</small>` : ""}
      </div>
      <div role="cell">
        <span class="category-badge ${category}">${escapeHtml(categoryLabel(item.category))}</span>
      </div>
      <div role="cell">
        <span class="risk-badge ${riskClass(risk)}">${risk}%</span>
      </div>
      <div class="date-cell" role="cell">${escapeHtml(formatDate(item.first_seen || item.finding_created_at))}</div>
      <div class="date-cell" role="cell">${escapeHtml(formatDate(item.last_seen || item.finding_created_at))}</div>
      <div class="action-cell" role="cell">
        <button class="analysis-btn" data-case-open="${item.id}" type="button">Анализ</button>
      </div>
    </article>`;
}

function renderEvidenceCards(cases) {
  if (!els.evidenceCards) return;
  if (!cases.length) {
    els.evidenceCards.innerHTML = '<div class="empty-state">Карточки появятся после первой найденной рабочей страницы.</div>';
    return;
  }
  els.evidenceCards.innerHTML = cases.map(siteEvidenceCard).join("");
  bindCaseOpenButtons(els.evidenceCards);
}

function shortList(values, limit = 2) {
  const list = Array.isArray(values) ? values.filter(Boolean) : [];
  if (!list.length) return "None";
  const shown = list.slice(0, limit).join(", ");
  return list.length > limit ? `${shown} +${list.length - limit}` : shown;
}

function siteEvidenceCard(item) {
  const evidence = item.evidence || {};
  const dns = item.dns || {};
  const tls = item.tls || {};
  const domainInfo = evidence.domain || {};
  const risk = Number(item.best_risk_score || 0);
  const daysLeft = certDaysLeft(tls);
  const sslText = tls.valid ? "Действителен" : "Недействителен";
  const sslClass = tls.valid ? "neutral" : "bad";
  const mxCount = (dns.mx_records || []).length;
  return `
    <article class="site-evidence-card">
      <div class="site-evidence-head">
        <div>
          <button data-case-open="${item.id}" type="button">${escapeHtml(item.domain)}</button>
          <small>${escapeHtml(item.final_url || item.url || item.title || "Последняя рабочая проверка")}</small>
        </div>
        <span class="risk-badge ${riskClass(risk)}">${risk}%</span>
      </div>
      <div class="mini-tech-grid">
        <div class="mini-tech-box">
          <h3>SSL сертификат</h3>
          ${techRow("Статус", sslText, sslClass)}
          ${techRow("Издатель", tls.issuer || "None")}
          ${techRow("Дней до истечения", daysLeft ?? "None", daysLeft !== null && daysLeft < 14 ? "bad" : "neutral")}
        </div>
        <div class="mini-tech-box">
          <h3>DNS</h3>
          ${techRow("IP адресов", (dns.records || []).length)}
          ${techRow("IP", shortList(dns.records, 2))}
          ${techRow("MX записи", mxCount ? "Есть" : "Нет", mxCount ? "good" : "bad")}
        </div>
        <div class="mini-tech-box">
          <h3>Домен</h3>
          ${techRow("Возраст", domainInfo.age_days === null || domainInfo.age_days === undefined ? "None" : `${domainInfo.age_days} дн.`)}
          ${techRow("Регистратор", domainInfo.registrar || "None")}
          ${techRow("Категория", categoryLabel(item.category))}
        </div>
        <div class="mini-tech-box">
          <h3>Производительность</h3>
          ${techRow("Время ответа", formatResponseTime(evidence.response_time_ms))}
          ${techRow("Размер страницы", formatBytes(evidence.page_size_bytes))}
          ${techRow("Редиректов", evidence.redirect_count ?? 0)}
        </div>
      </div>
      <div class="evidence-reasons">
        ${(item.reasons || []).slice(0, 3).map((reason) => `<span>${escapeHtml(reason)}</span>`).join("") || "<span>Причины появятся после анализа страницы.</span>"}
      </div>
    </article>`;
}

function dayKey(date) {
  return date.toISOString().slice(0, 10);
}

function drawTrend(cases) {
  const canvas = els.trendChart;
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  if (!rect.width) return;

  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.floor(rect.width * dpr);
  canvas.height = Math.floor(320 * dpr);
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  const width = rect.width;
  const height = 320;
  ctx.clearRect(0, 0, width, height);

  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const days = [];
  for (let offset = 21; offset >= 0; offset -= 1) {
    const date = new Date(today);
    date.setDate(today.getDate() - offset);
    days.push(date);
  }

  const buckets = Object.fromEntries(days.map((date) => [dayKey(date), { casino: 0, phishing: 0, pyramid: 0 }]));
  cases.forEach((item) => {
    const raw = item.first_seen || item.finding_created_at || item.last_seen;
    const date = raw ? new Date(raw) : null;
    if (!date || Number.isNaN(date.getTime())) return;
    date.setHours(0, 0, 0, 0);
    const key = dayKey(date);
    if (!buckets[key]) return;
    const category = normalizeCategory(item.category);
    if (category in buckets[key]) buckets[key][category] += 1;
  });

  const series = ["casino", "phishing", "pyramid"].map((category) => ({
    category,
    values: days.map((date) => buckets[dayKey(date)][category]),
  }));
  const maxValue = Math.max(1, ...series.flatMap((item) => item.values));
  const tickStep = Math.max(1, Math.ceil(maxValue / 5));
  const axisMax = tickStep * 5;
  const plot = { left: 54, right: 18, top: 18, bottom: 54 };
  const plotWidth = width - plot.left - plot.right;
  const plotHeight = height - plot.top - plot.bottom;
  state.chartPoints = days.map((date, index) => {
    const values = Object.fromEntries(series.map((item) => [item.category, item.values[index]]));
    const x = plot.left + (plotWidth * index) / Math.max(1, days.length - 1);
    const maxAtPoint = Math.max(...Object.values(values));
    const y = plot.top + plotHeight - (plotHeight * maxAtPoint) / axisMax;
    return { date, index, x, y, values };
  });

  ctx.lineWidth = 1;
  ctx.strokeStyle = "rgba(148, 163, 184, 0.16)";
  ctx.fillStyle = "#94a3b8";
  ctx.font = "12px Inter, Segoe UI, sans-serif";
  for (let i = 0; i <= 5; i += 1) {
    const value = tickStep * i;
    const y = plot.top + plotHeight - (plotHeight * i) / 5;
    ctx.beginPath();
    ctx.moveTo(plot.left, y);
    ctx.lineTo(width - plot.right, y);
    ctx.stroke();
    ctx.fillText(String(value), 18, y + 4);
  }

  days.forEach((date, index) => {
    if (index % 3 !== 0 && index !== days.length - 1) return;
    const x = plot.left + (plotWidth * index) / Math.max(1, days.length - 1);
    const label = date.toLocaleDateString("ru-RU", { day: "2-digit", month: "2-digit" });
    ctx.save();
    ctx.translate(x, height - 26);
    ctx.rotate(-0.65);
    ctx.fillText(label, 0, 0);
    ctx.restore();
  });

  series.forEach(({ category, values }) => {
    ctx.strokeStyle = categoryColors[category];
    ctx.fillStyle = categoryColors[category];
    ctx.lineWidth = 3;
    ctx.beginPath();
    values.forEach((value, index) => {
      const x = plot.left + (plotWidth * index) / Math.max(1, values.length - 1);
      const y = plot.top + plotHeight - (plotHeight * value) / axisMax;
      if (index === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();
    values.forEach((value, index) => {
      const x = plot.left + (plotWidth * index) / Math.max(1, values.length - 1);
      const y = plot.top + plotHeight - (plotHeight * value) / axisMax;
      ctx.beginPath();
      ctx.arc(x, y, 4, 0, Math.PI * 2);
      ctx.fill();
    });
  });

  drawChartHover(ctx, plot, plotHeight, axisMax);
}

function drawChartHover(ctx, plot, plotHeight, axisMax) {
  const hover = state.chartHoverIndex === null ? null : state.chartPoints[state.chartHoverIndex];
  if (!hover) {
    if (els.chartTooltip) els.chartTooltip.hidden = true;
    return;
  }
  const canvas = els.trendChart;
  const height = 320;
  ctx.save();
  ctx.strokeStyle = "rgba(226, 232, 240, 0.28)";
  ctx.lineWidth = 1;
  ctx.setLineDash([4, 5]);
  ctx.beginPath();
  ctx.moveTo(hover.x, plot.top);
  ctx.lineTo(hover.x, height - plot.bottom);
  ctx.stroke();
  ctx.setLineDash([]);

  Object.entries(hover.values).forEach(([category, value]) => {
    const y = plot.top + plotHeight - (plotHeight * Number(value || 0)) / axisMax;
    ctx.fillStyle = categoryColors[category];
    ctx.beginPath();
    ctx.arc(hover.x, y, 6, 0, Math.PI * 2);
    ctx.fill();
    ctx.strokeStyle = "#0b0f15";
    ctx.lineWidth = 2;
    ctx.stroke();
  });
  ctx.restore();

  if (!els.chartTooltip || !canvas) return;
  const title = hover.date.toLocaleDateString("ru-RU", { day: "2-digit", month: "2-digit", year: "numeric" });
  els.chartTooltip.innerHTML = `
    <strong>${escapeHtml(title)}</strong>
    <span><i class="casino"></i>${escapeHtml(categoryLabel("casino"))}: ${hover.values.casino}</span>
    <span><i class="phishing"></i>${escapeHtml(categoryLabel("phishing"))}: ${hover.values.phishing}</span>
    <span><i class="pyramid"></i>${escapeHtml(categoryLabel("pyramid"))}: ${hover.values.pyramid}</span>
  `;
  els.chartTooltip.hidden = false;
  const left = Math.min(Math.max(12, hover.x + 12), canvas.getBoundingClientRect().width - 180);
  const top = Math.max(12, hover.y - 8);
  els.chartTooltip.style.left = `${left}px`;
  els.chartTooltip.style.top = `${top}px`;
}

function handleChartMove(event) {
  if (!state.chartPoints.length || !els.trendChart) return;
  const rect = els.trendChart.getBoundingClientRect();
  const x = event.clientX - rect.left;
  let nearest = 0;
  let distance = Number.POSITIVE_INFINITY;
  state.chartPoints.forEach((point, index) => {
    const nextDistance = Math.abs(point.x - x);
    if (nextDistance < distance) {
      nearest = index;
      distance = nextDistance;
    }
  });
  state.chartHoverIndex = nearest;
  drawTrend(state.cases);
}

function clearChartHover() {
  state.chartHoverIndex = null;
  if (els.chartTooltip) els.chartTooltip.hidden = true;
  drawTrend(state.cases);
}

async function openCase(caseId) {
  els.drawerOverlay.hidden = false;
  els.drawerTitle.textContent = "Загрузка анализа";
  const cached = state.caseDetails.get(caseId);
  if (cached) {
    renderCaseDetail(cached.case, cached.findings || []);
    return;
  }
  els.caseDetailContent.innerHTML = '<div class="empty-state">Загружаю доказательства...</div>';
  const data = await api(`/api/cases/${caseId}`);
  state.caseDetails.set(caseId, data);
  renderCaseDetail(data.case, data.findings || []);
}

function latestFinding(item, findings) {
  return findings[0] || item || {};
}

function compactSignals(items, limit = 12) {
  const seen = new Set();
  const result = [];
  (items || []).forEach((item) => {
    const text = String(item || "").trim();
    const key = text.toLowerCase().replace(/\s+/g, " ");
    if (!text || seen.has(key)) return;
    seen.add(key);
    result.push(text);
  });
  return result.slice(0, limit);
}

function positiveSignals(finding) {
  const evidence = finding.evidence || {};
  const ml = evidence.ml || {};
  const cyber = evidence.cyberscan_ml || {};
  const tls = finding.tls || {};
  const dns = finding.dns || {};
  const signals = [];
  if (finding.status_code >= 200 && finding.status_code < 400) signals.push(`Сайт отвечает HTTP ${finding.status_code}`);
  if (tls.issuer || tls.not_after || tls.expires_in_days !== undefined) {
    signals.push(`TLS зафиксирован как метаданные${tls.issuer ? `: ${tls.issuer}` : ""}`);
  }
  if ((dns.records || []).length) signals.push(`DNS возвращает ${(dns.records || []).length} IP адрес(ов)`);
  if (finding.html_sha256) signals.push("HTML сохранен с SHA-256 отпечатком");
  if (finding.screenshot_path) signals.push("Скриншот страницы сохранен");
  if (evidence.response_time_ms && evidence.response_time_ms < 1500) signals.push(`Быстрый ответ: ${formatResponseTime(evidence.response_time_ms)}`);
  if (evidence.access_origin) signals.push(`Проверено через: ${evidence.access_origin}`);
  if (ml.available && ml.label === "legit") signals.push(`ML CatBoost считает сайт легитимным: ${formatPercent(ml.confidence)}`);
  if (cyber.available && cyber.label === "legit") signals.push(`CyberScan ML не видит сильных подозрительных признаков: ${formatPercent(cyber.confidence)}`);
  return signals.length ? compactSignals(signals, 8) : ["Положительные технические признаки не выделены"];
}

function negativeSignals(finding) {
  const evidence = finding.evidence || {};
  const ml = evidence.ml || {};
  const cyber = evidence.cyberscan_ml || {};
  const contentAi = evidence.content_ai || {};
  const domainInfo = evidence.domain || {};
  const dns = finding.dns || {};
  const tls = finding.tls || {};
  const signals = [...(finding.reasons || [])];
  if (evidence.keyword_hits?.length) signals.push(`Ключевые маркеры на странице: ${evidence.keyword_hits.slice(0, 8).join(", ")}`);
  if (domainInfo.age_days !== null && domainInfo.age_days !== undefined && domainInfo.age_days < 60) {
    signals.push(`Очень молодой домен: ${domainInfo.age_days} дн.`);
  }
  if (!tls.valid) signals.push("SSL сертификат не подтвержден или недоступен");
  if (!(dns.mx_records || []).length) signals.push("MX записи не найдены");
  if (Number(evidence.redirect_count || 0) > 2) signals.push(`Много редиректов: ${evidence.redirect_count}`);
  if (evidence.blocked_by_policy) signals.push("Страница похожа на блокировку доступа");
  if (ml.available && ml.label && ml.label !== "legit") signals.push(`ML CatBoost: ${ml.label}, уверенность ${formatPercent(ml.confidence)}`);
  if (cyber.available && cyber.label === "suspicious") signals.push(`CyberScan ML: подозрительность ${formatPercent(cyber.suspicious_probability)}`);
  if (Array.isArray(contentAi.signals)) signals.push(...contentAi.signals.slice(0, 6));
  return signals.length ? compactSignals(signals, 12) : ["Явные негативные признаки не найдены"];
}

function renderSignalList(items, type) {
  return `
    <div class="signal-box ${type}">
      <h3>${type === "positive" ? "Подтвержденные факты" : "Подозрительные признаки"}</h3>
      <ul>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
    </div>`;
}

function techRow(label, value, cls = "") {
  return `<div class="tech-row"><span>${escapeHtml(label)}</span><strong class="${cls}">${escapeHtml(value ?? "N/A")}</strong></div>`;
}

function techCard(title, rows) {
  return `<article class="tech-card"><h3>${escapeHtml(title)}</h3>${rows.join("")}</article>`;
}

function mlFeatureText(ml) {
  const features = Array.isArray(ml?.top_features) ? ml.top_features : [];
  return features.slice(0, 4)
    .map((item) => item.label || featureLabels[item.feature] || item.feature)
    .filter(Boolean)
    .join(", ") || "Нет";
}

function renderCaseDetail(item, findings) {
  const finding = latestFinding(item, findings);
  const evidence = finding.evidence || {};
  const ml = evidence.ml || {};
  const cyber = evidence.cyberscan_ml || {};
  const contentAi = evidence.content_ai || {};
  const dns = finding.dns || {};
  const tls = finding.tls || {};
  const domainInfo = evidence.domain || {};
  const category = normalizeCategory(finding.category || item.category);
  const risk = Number(finding.risk_score || item.best_risk_score || 0);
  const screenshot = relPath(finding.screenshot_path || item.screenshot_path);
  const html = relPath(finding.html_path || item.html_path);
  const firstSource = finding.sources?.[0]?.url || item.sources?.[0]?.url;
  const daysLeft = certDaysLeft(tls);

  els.drawerTitle.textContent = item.domain;
  els.caseDetailContent.innerHTML = `
    <div class="detail-summary">
      <div class="risk-panel ${riskClass(risk)}">
        <span>Риск</span>
        <strong>${risk}%</strong>
        <small>${escapeHtml(categoryLabel(category))}</small>
      </div>
      <div class="summary-text">
        <h3>${escapeHtml(finding.title || item.title || item.domain)}</h3>
        <p>${escapeHtml((finding.reasons || [])[0] || "Домен добавлен в мониторинг по результатам OSINT-поиска.")}</p>
        <div class="detail-actions">
          <a class="primary-btn" href="${escapeHtml(finding.final_url || item.final_url || item.url || "#")}" target="_blank" rel="noreferrer">Открыть сайт</a>
          ${screenshot ? `<a class="secondary-btn" href="/${escapeHtml(screenshot)}" target="_blank" rel="noreferrer">Скриншот</a>` : ""}
          ${html ? `<a class="secondary-btn" href="/${escapeHtml(html)}" target="_blank" rel="noreferrer">HTML</a>` : ""}
          ${firstSource ? `<a class="secondary-btn" href="${escapeHtml(firstSource)}" target="_blank" rel="noreferrer">Источник</a>` : ""}
        </div>
      </div>
    </div>

    <div class="signals-grid">
      ${renderSignalList(positiveSignals(finding), "positive")}
      ${renderSignalList(negativeSignals(finding), "negative")}
    </div>

    <div class="tabbar">
      <button class="tab-btn active" data-tab="technical" type="button">Технические</button>
      <button class="tab-btn" data-tab="search" type="button">Как найден</button>
      <button class="tab-btn" data-tab="evidence" type="button">Доказательства</button>
      <button class="tab-btn" data-tab="history" type="button">История</button>
    </div>

    <section class="tab-panel active" data-panel="technical">
      <div class="tech-grid">
        ${techCard("SSL сертификат", [
          techRow("Статус", tls.valid ? "Действителен" : "Недействителен", tls.valid ? "neutral" : "bad"),
          techRow("Издатель", tls.issuer || "None"),
          techRow("Истекает", tls.not_after || "None"),
          techRow("Дней до истечения", daysLeft ?? "None", daysLeft !== null && daysLeft >= 14 ? "good" : "bad"),
        ])}
        ${techCard("DNS", [
          techRow("IP адресов", (dns.records || []).length),
          techRow("IP", (dns.records || []).slice(0, 3).join(", ") || "None"),
          techRow("MX записи", (dns.mx_records || []).length ? "Есть" : "Нет", (dns.mx_records || []).length ? "good" : "bad"),
          techRow("MX", (dns.mx_records || []).slice(0, 2).join(", ") || "None"),
        ])}
        ${techCard("Домен", [
          techRow("Возраст", domainInfo.age_days === null || domainInfo.age_days === undefined ? "None" : `${domainInfo.age_days} дн.`),
          techRow("Регистратор", domainInfo.registrar || "None"),
          techRow("Создан", domainInfo.created_at || "None"),
          techRow("Истекает", domainInfo.expires_at || "None"),
        ])}
        ${techCard("Производительность", [
          techRow("Время ответа", formatResponseTime(evidence.response_time_ms)),
          techRow("Размер страницы", formatBytes(evidence.page_size_bytes)),
          techRow("Редиректов", evidence.redirect_count ?? 0),
          techRow("Сеть проверки", evidence.access_origin || "server direct network"),
        ])}
        ${techCard("ML модель", [
          techRow("Статус", ml.available ? "CatBoost готов" : (ml.error || "Недоступна"), ml.available ? "good" : "bad"),
          techRow("Класс", modelLabel(ml.label)),
          techRow("Уверенность", formatPercent(ml.confidence), ml.label && ml.label !== "legit" ? "bad" : "good"),
          techRow("Топ признаки", mlFeatureText(ml)),
        ])}
        ${techCard("CyberScan ML", [
          techRow("Статус", cyber.available ? "RandomForest готов" : (cyber.error || "Недоступна"), cyber.available ? "good" : "bad"),
          techRow("Вердикт", modelLabel(cyber.label)),
          techRow("Подозрительность", formatPercent(cyber.suspicious_probability), cyber.label === "suspicious" ? "bad" : "good"),
          techRow("Признаки", mlFeatureText(cyber)),
        ])}
        ${techCard("Контентный анализ", [
          techRow("Категория", contentAi.category_hint || "None", contentAi.category_hint ? "bad" : ""),
          techRow("Casino слов", (contentAi.casino_keywords || []).length),
          techRow("Password форм", contentAi.forms?.num_password_forms ?? 0),
          techRow("iframe / hidden", `${contentAi.num_iframes || 0} / ${contentAi.num_hidden_elements || 0}`),
        ])}
      </div>
    </section>

    <section class="tab-panel" data-panel="search">
      <div class="explain-grid">
        <div>
          <h3>Поисковый след</h3>
          ${techRow("Запрос", evidence.search_query || "Автоматический Gemini Search")}
          ${techRow("Бренд", evidence.brand || "None")}
          ${techRow("Зеркальная группа", finding.mirror_group || "None")}
          ${techRow("Подсказки зеркал", (evidence.mirror_hints || []).join(", ") || "None")}
        </div>
        <div>
          <h3>Почему подозрительный</h3>
          <ul class="reason-list">${(finding.reasons || []).map((reason) => `<li>${escapeHtml(reason)}</li>`).join("") || "<li>Причины не сохранены</li>"}</ul>
        </div>
      </div>
    </section>

    <section class="tab-panel" data-panel="evidence">
      ${screenshot ? `<a class="screenshot-preview" href="/${escapeHtml(screenshot)}" target="_blank" rel="noreferrer"><img src="/${escapeHtml(screenshot)}" alt="Скриншот ${escapeHtml(item.domain)}" loading="lazy"></a>` : ""}
      <div class="evidence-grid">
        ${screenshot ? `<a class="evidence-link" href="/${escapeHtml(screenshot)}" target="_blank" rel="noreferrer"><span>Скриншот</span><strong>${escapeHtml(screenshot)}</strong></a>` : ""}
        ${html ? `<a class="evidence-link" href="/${escapeHtml(html)}" target="_blank" rel="noreferrer"><span>HTML</span><strong>${escapeHtml(html)}</strong></a>` : ""}
        <div class="evidence-link"><span>SHA-256 HTML</span><strong>${escapeHtml(finding.html_sha256 || "None")}</strong></div>
        <div class="evidence-link"><span>Финальный URL</span><strong>${escapeHtml(finding.final_url || finding.url || "None")}</strong></div>
      </div>
      <h3 class="subhead">Источники</h3>
      <div class="source-list">${(finding.sources || []).map((source) => `<a href="${escapeHtml(source.url || source)}" target="_blank" rel="noreferrer">${escapeHtml(source.url || source)}</a>`).join("") || '<span class="muted">Источники не сохранены</span>'}</div>
    </section>

    <section class="tab-panel" data-panel="history">
      <div class="timeline">${findings.map(findingTimelineItem).join("") || '<div class="empty-state">История пуста.</div>'}</div>
    </section>
  `;

  bindTabs();
}

function findingTimelineItem(finding) {
  return `
    <article class="timeline-item">
      <div>
        <strong>Запуск #${finding.run_id}</strong>
        <span>${escapeHtml(formatDateTime(finding.created_at))}</span>
      </div>
      <span class="risk-badge ${riskClass(finding.risk_score)}">${finding.risk_score}%</span>
      <p>${escapeHtml((finding.reasons || [])[0] || finding.verdict || "Зафиксировано")}</p>
    </article>`;
}

function bindTabs() {
  document.querySelectorAll(".tab-btn").forEach((button) => {
    button.addEventListener("click", () => {
      const tab = button.dataset.tab;
      document.querySelectorAll(".tab-btn").forEach((item) => item.classList.toggle("active", item === button));
      document.querySelectorAll(".tab-panel").forEach((panel) => panel.classList.toggle("active", panel.dataset.panel === tab));
    });
  });
}

function closeDrawer() {
  els.drawerOverlay.hidden = true;
}

function startPolling() {
  if (state.pollTimer) return;
  state.pollTimer = setTimeout(pollSelectedRun, POLL_INTERVAL_MS);
}

function stopPolling() {
  if (state.pollTimer) {
    clearTimeout(state.pollTimer);
    state.pollTimer = null;
  }
}

async function pollSelectedRun() {
  state.pollTimer = null;
  if (state.pollInFlight) {
    startPolling();
    return;
  }
  state.pollInFlight = true;
  try {
    state.pollRunsCounter += 1;
    if (state.pollRunsCounter % 2 === 0) {
      await loadRuns();
    }
    if (state.selectedRunId) {
      await loadRun(state.selectedRunId, { force: true });
    }
  } catch (error) {
    console.error(error);
  } finally {
    state.pollInFlight = false;
    if (hasRunningRuns()) startPolling();
  }
}

els.scanForm.addEventListener("submit", startRun);
els.healthToggle?.addEventListener("click", () => {
  const open = els.healthToggle.getAttribute("aria-expanded") !== "true";
  setHealthDetailsOpen(open);
});
document.addEventListener("click", (event) => {
  if (!event.target.closest(".health")) setHealthDetailsOpen(false);
});
els.manualBtn?.addEventListener("click", startManualCheck);
els.manualTarget?.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    startManualCheck();
  }
});
els.stopBtn.addEventListener("click", stopRun);
els.caseFilterBtn.addEventListener("click", loadCases);
els.categoryFilter.addEventListener("change", loadCases);
els.caseSearch.addEventListener("keydown", (event) => {
  if (event.key === "Enter") loadCases();
});
els.exportCasesCsvBtn?.addEventListener("click", () => exportCurrentCases("csv").catch((error) => alert(`Не удалось скачать CSV: ${error.message}`)));
els.exportCasesXlsxBtn?.addEventListener("click", () => exportCurrentCases("xlsx").catch((error) => alert(`Не удалось скачать Excel: ${error.message}`)));
els.exportRunCsvBtn?.addEventListener("click", () => exportSelectedRun("csv").catch((error) => alert(`Не удалось скачать CSV запуска: ${error.message}`)));
els.exportRunXlsxBtn?.addEventListener("click", () => exportSelectedRun("xlsx").catch((error) => alert(`Не удалось скачать Excel запуска: ${error.message}`)));
els.toggleRunFindingsBtn?.addEventListener("click", () => toggleRunFindings().catch(console.error));
els.drawerClose.addEventListener("click", closeDrawer);
els.drawerOverlay.addEventListener("click", (event) => {
  if (event.target === els.drawerOverlay) closeDrawer();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    closeDrawer();
    setHealthDetailsOpen(false);
  }
});
window.addEventListener("resize", () => drawTrend(state.cases));
els.trendChart?.addEventListener("mousemove", handleChartMove);
els.trendChart?.addEventListener("mouseleave", clearChartHover);

els.authForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  state.apiToken = els.apiTokenInput.value.trim();
  if (!state.apiToken) {
    showAuth("Введите ADMIN_TOKEN.");
    return;
  }
  localStorage.setItem("argus_api_token", state.apiToken);
  hideAuth();
  await bootstrap();
});

els.clearTokenBtn?.addEventListener("click", () => {
  state.apiToken = "";
  localStorage.removeItem("argus_api_token");
  showAuth("Токен сброшен. Введите ADMIN_TOKEN заново.");
});

async function bootstrap() {
  await loadHealth();
  if (state.authRequired && state.authConfigured && !state.apiToken) {
    drawTrend([]);
    return;
  }
  if (!(state.authRequired && !state.authConfigured)) {
    await loadRuns();
    if (state.selectedRunId) await loadRun(state.selectedRunId);
    await loadCases();
  }
}

bootstrap().catch(console.error);
