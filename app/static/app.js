const PAGE = document.body.dataset.page || "monitor";
const PAGE_USES_CASES = PAGE === "monitor" || PAGE === "registry" || PAGE === "dynamics";
const TREND_CHART_HEIGHT = 300;

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
  registryExpanded: PAGE === "registry",
  expandedRunFolderId: null,
  runFolderLoadingId: null,
  runFolderErrors: new Map(),
  lastLiveFindingCount: 0,
  lastCasesRefreshAt: 0,
  chartPoints: [],
  chartHoverIndex: null,
  logFilter: "all",
  visibleLogs: [],
  visibleRunStatus: "",
  runHistoryExpanded: false,
  stoppingRunIds: new Set(),
  healthActionBlocked: false,
  healthActionReason: "",
  kzProxyConfigured: false,
  groqConfigured: false,
};

const DEFAULT_RUN_CANDIDATES = 100;
const MAX_RUN_CANDIDATES = 500;
const POLL_INTERVAL_MS = 3000;
const CASE_REFRESH_INTERVAL_MS = 15000;
const MAX_CACHED_LOGS = 500;

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
  runSize: document.getElementById("runSize"),
  takeScreenshots: document.getElementById("takeScreenshots"),
  manualTarget: document.getElementById("manualTarget"),
  manualBtn: document.getElementById("manualBtn"),
  activityPanel: document.getElementById("activityPanel"),
  activityHeadline: document.getElementById("activityHeadline"),
  activitySteps: document.getElementById("activitySteps"),
  activityText: document.getElementById("activityText"),
  activityFound: document.getElementById("activityFound"),
  activityChecked: document.getElementById("activityChecked"),
  activityUnreachable: document.getElementById("activityUnreachable"),
  activityFiltered: document.getElementById("activityFiltered"),
  activityProgressBar: document.getElementById("activityProgressBar"),
  activityDiagnostic: document.getElementById("activityDiagnostic"),
  activityFindings: document.getElementById("activityFindings"),
  activityFindingsCount: document.getElementById("activityFindingsCount"),
  activityFindingsList: document.getElementById("activityFindingsList"),
  journalRunContext: document.getElementById("journalRunContext"),
  journalRunLabel: document.getElementById("journalRunLabel"),
  journalRunDiagnostic: document.getElementById("journalRunDiagnostic"),
  journalRunFound: document.getElementById("journalRunFound"),
  journalRunChecked: document.getElementById("journalRunChecked"),
  journalRunFindings: document.getElementById("journalRunFindings"),
  currentRun: document.getElementById("currentRun"),
  runStatus: document.getElementById("runStatus"),
  activeCaseCount: document.getElementById("activeCaseCount"),
  highRiskCount: document.getElementById("highRiskCount"),
  evidenceCount: document.getElementById("evidenceCount"),
  trendChart: document.getElementById("trendChart"),
  chartTooltip: document.getElementById("chartTooltip"),
  trendEmptyState: document.getElementById("trendEmptyState"),
  trendTotal: document.getElementById("trendTotal"),
  trendCasinoCount: document.getElementById("trendCasinoCount"),
  trendPhishingCount: document.getElementById("trendPhishingCount"),
  trendPyramidCount: document.getElementById("trendPyramidCount"),
  caseSearch: document.getElementById("caseSearch"),
  categoryFilter: document.getElementById("categoryFilter"),
  caseMinRisk: document.getElementById("caseMinRisk"),
  caseFilterBtn: document.getElementById("caseFilterBtn"),
  exportCasesCsvBtn: document.getElementById("exportCasesCsvBtn"),
  exportCasesXlsxBtn: document.getElementById("exportCasesXlsxBtn"),
  registrySummary: document.getElementById("registrySummary"),
  toggleRegistryBtn: document.getElementById("toggleRegistryBtn"),
  registryDetails: document.getElementById("registryDetails"),
  casesList: document.getElementById("casesList"),
  runFoldersList: document.getElementById("runFoldersList"),
  runFoldersCount: document.getElementById("runFoldersCount"),
  runsList: document.getElementById("runsList"),
  runHistoryToggle: document.getElementById("runHistoryToggle"),
  runHistoryContent: document.getElementById("runHistoryContent"),
  runHistorySummary: document.getElementById("runHistorySummary"),
  runHistoryAction: document.getElementById("runHistoryAction"),
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

const categoryFillColors = {
  casino: "rgba(245, 158, 11, 0.18)",
  phishing: "rgba(239, 68, 68, 0.14)",
  pyramid: "rgba(139, 92, 246, 0.14)",
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
  state.healthActionBlocked = Boolean(locked);
  state.healthActionReason = reason || "";
  syncActionButtons();
}

function syncActionButtons() {
  const activeRun = hasRunningRuns();
  if (els.runBtn) {
    els.runBtn.disabled = state.healthActionBlocked || activeRun;
    els.runBtn.title = state.healthActionBlocked
      ? state.healthActionReason
      : activeRun
        ? "Сначала остановите или дождитесь завершения текущего запуска"
        : "";
    els.runBtn.textContent = activeRun ? "Запуск идет" : "Запустить";
  }
  if (els.manualBtn) {
    els.manualBtn.disabled = state.healthActionBlocked;
    els.manualBtn.title = state.healthActionReason;
  }
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

function runStatusForId(runId) {
  if (!runId) return "";
  return state.runs.find((run) => Number(run.id) === Number(runId))?.status
    || state.runStatuses.get(Number(runId))
    || state.runDetails.get(Number(runId))?.run?.status
    || "";
}

function activeRunIdForStop() {
  const preferredIds = [state.activityRunId, state.selectedRunId];
  for (const runId of preferredIds) {
    if (runId && runningStatus(runStatusForId(runId))) return Number(runId);
  }
  const activeRun = state.runs.find((run) => runningStatus(run.status));
  return activeRun ? Number(activeRun.id) : null;
}

function syncStopButton() {
  if (!els.stopBtn) return;
  const runId = activeRunIdForStop();
  const stopping = Boolean(runId && state.stoppingRunIds.has(runId));
  els.stopBtn.disabled = !runId || stopping;
  els.stopBtn.dataset.activeRunId = runId ? String(runId) : "";
  els.stopBtn.textContent = stopping ? "Останавливаю" : "Стоп";
}

function latestLog(logs = []) {
  return logs.length ? logs[logs.length - 1] : null;
}

function summarizeRunLogs(logs = []) {
  const stats = { unreachable: 0, filtered: 0, timeouts: 0, searchIssues: 0 };
  logs.forEach((log) => {
    const message = String(log.message || "").toLowerCase();
    const reason = String(log.meta?.reason || log.meta?.error || "").toLowerCase();
    const text = `${message} ${reason}`;
    if (/search pages (?:unavailable|degraded)|поисков.*недоступ/.test(text)) stats.searchIssues += 1;
    if (!/сайт пропущен|пропущен после контентной проверки/.test(message)) return;
    if (/таймаут|timeout/.test(text)) {
      stats.timeouts += 1;
      stats.unreachable += 1;
      return;
    }
    if (/http 2xx\/3xx|не открыл|dns|connection|connect|ssl|tls/.test(text)) {
      stats.unreachable += 1;
      return;
    }
    stats.filtered += 1;
  });
  return stats;
}

function runDiagnostic(run = {}, stats = {}) {
  const found = Number(run.finding_count || 0);
  const checked = Number(run.candidate_count || 0);
  const activeCount = state.runs.filter((item) => runningStatus(item.status)).length;
  if (activeCount > 1 && runningStatus(run.status)) {
    return `Одновременно работают ${activeCount} запуска: они делят сетевые и браузерные ресурсы. Остановите лишний запуск для максимальной скорости.`;
  }
  if (run.status === "queued") return "Запуск поставлен в очередь. Формируется первая партия реальных доменов.";
  if (runningStatus(run.status) && checked === 0) {
    const source = state.groqConfigured ? "Groq Compound, поисковые страницы, форумы и OSINT" : "поисковые страницы, форумы и OSINT";
    return `Идет сбор через ${source}. Новые проходы будут продолжаться до выбранного количества находок.`;
  }
  if (runningStatus(run.status) && found === 0 && stats.unreachable > 0) {
    return `Поиск не завис: проверка продолжается, но ${stats.unreachable} последних кандидатов не открылись или превысили таймаут.`;
  }
  if (runningStatus(run.status) && found > 0) {
    return `Рабочие домены уже поступают в реестр. Проверено или поставлено в текущие пакеты: ${checked}.`;
  }
  if (run.status === "completed" && found < Number(run.max_candidates || DEFAULT_RUN_CANDIDATES)) {
    return "Этот запуск завершился ниже цели. Новые запуски продолжают поиск до цели либо ручной остановки.";
  }
  if (run.status === "completed") return "Цель запуска набрана; находки сохранены в реестре и папке запуска.";
  if (["canceled", "interrupted"].includes(run.status)) return "Запуск остановлен. Уже подтвержденные находки сохранены.";
  if (run.status === "failed") return run.error || "Запуск завершился ошибкой; подробности доступны в журнале.";
  return "Система собирает и проверяет очередную партию доменов.";
}

function renderLiveFindingButtons(container, findings = [], limit = 8) {
  if (!container) return;
  const rows = findings.slice(0, limit);
  container.innerHTML = rows.map((item) => {
    const domain = item.domain || item.normalized_domain || item.url || "-";
    return `
      <button class="live-finding" data-live-finding-domain="${escapeHtml(item.normalized_domain || domain)}" data-live-finding-case="${Number(item.case_id || 0)}" type="button">
        <span>${escapeHtml(domain)}</span>
        <small>${escapeHtml(categoryLabel(item.category))} · ${Number(item.risk_score || 0)}%</small>
      </button>`;
  }).join("");
  container.querySelectorAll("[data-live-finding-domain]").forEach((button) => {
    button.addEventListener("click", () => {
      openCaseForFinding(button.dataset.liveFindingDomain, Number(button.dataset.liveFindingCase || 0)).catch(console.error);
    });
  });
}

function renderRunObserver(run = {}, logs = [], findings = []) {
  if (!run.id) return;
  const found = Number(run.finding_count || 0);
  const target = Math.max(1, Number(run.max_candidates || DEFAULT_RUN_CANDIDATES));
  const checked = Number(run.candidate_count || 0);
  const stats = summarizeRunLogs(logs);
  const diagnostic = runDiagnostic(run, stats);
  const progress = Math.max(0, Math.min(100, (found / target) * 100));

  if (els.activityFound) els.activityFound.textContent = `${found} / ${target}`;
  if (els.activityChecked) els.activityChecked.textContent = String(checked);
  if (els.activityUnreachable) els.activityUnreachable.textContent = String(stats.unreachable);
  if (els.activityFiltered) els.activityFiltered.textContent = String(stats.filtered);
  if (els.activityProgressBar) els.activityProgressBar.style.width = `${progress}%`;
  if (els.activityDiagnostic) els.activityDiagnostic.textContent = diagnostic;
  if (els.activityFindings) els.activityFindings.hidden = findings.length === 0;
  if (els.activityFindingsCount) els.activityFindingsCount.textContent = `${found} доменов`;
  renderLiveFindingButtons(els.activityFindingsList, findings, 8);

  if (els.journalRunContext) els.journalRunContext.hidden = false;
  if (els.journalRunLabel) els.journalRunLabel.textContent = `Запуск #${run.id} · ${runStatusLabel(run)}`;
  if (els.journalRunDiagnostic) els.journalRunDiagnostic.textContent = diagnostic;
  if (els.journalRunFound) els.journalRunFound.textContent = `${found} / ${target}`;
  if (els.journalRunChecked) els.journalRunChecked.textContent = String(checked);
  renderLiveFindingButtons(els.journalRunFindings, findings, 6);
}

function activityStageIndex(run = {}, logs = []) {
  if (terminalStatus(run.status)) {
    return activityStages.length - 1;
  }
  const last = latestLog(logs) || {};
  const meta = last.meta || {};
  const lastText = `${last.message || ""} ${JSON.stringify(meta)}`.toLowerCase();
  if (/добавлен|отчет|заверш|report|complete/.test(lastText)) return 3;
  if (meta.path || meta.html_sha256) return 2;
  if (/скрин|html|sha|dns|tls|ssl|доказ|screenshot|evidence/.test(lastText)) return 2;
  if (/открываю|ручного анализа|кандидат|доступ|candidate|opening|url/.test(lastText)) return 1;
  if (meta.url || meta.domain) return 1;
  if (Number(run.finding_count || 0) > 0 || meta.risk_score !== undefined) return 3;
  return 0;
}

function showActivity(run = {}, logs = [], findings = []) {
  if (!els.activityPanel) return;
  const active = runningStatus(run.status);
  const done = terminalStatus(run.status);
  if (active && run.id) state.activityRunId = run.id;
  if (!active && !done && !logs.length) {
    els.activityPanel.hidden = true;
    return;
  }

  const stageIndex = activityStageIndex(run, logs);
  const last = latestLog(logs);
  els.activityPanel.hidden = false;
  els.activityPanel.style.setProperty("--activity-progress", `${((stageIndex + 1) / activityStages.length) * 100}%`);
  els.activityPanel.setAttribute("aria-busy", String(active));
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
  renderRunObserver(run, logs, findings);
}

function primeActivity(runId, mode = "auto") {
  state.activityRunId = runId;
  state.runStatuses.set(Number(runId), "queued");
  syncStopButton();
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
  if (!el) return;
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
    state.kzProxyConfigured = Boolean(health.kz_proxy_configured);
    state.groqConfigured = Boolean(health.groq_configured);
    const discoveryText = health.groq_configured ? "Discovery: Groq + OSINT" : "Discovery: OSINT";
    renderPill(els.geminiPill, discoveryText, health.groq_configured ? "ok" : "warn");
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
      ? `Gemini настроен (${keyCount} ключ(а), ${geminiModels}${hashHint}), но в автоматическом поиске не используется`
      : "Gemini в автоматическом поиске не используется";
    const groqHint = health.groq_configured
      ? `Groq Compound: до ${health.groq_requests_per_discovery || 1} поисковых пакетов (${health.groq_model || "groq/compound"})`
      : "Groq Compound не настроен: поиск продолжает работать через поисковые страницы и OSINT";
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
    els.healthLine.textContent = `${groqHint}. ${geminiHint}. ${mlHint}. ${cyberHint}. ${kzHint}. Цель запуска: до ${maxRun} находок, потоков: ${concurrency}, таймаут сайта: ${timeout} сек.`;
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
  if (!els.runBtn || !els.seedQuery || !els.takeScreenshots) return;
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
      search_mode: "auto",
      max_candidates: Math.max(1, Math.min(requestedCandidates, MAX_RUN_CANDIDATES)),
      take_screenshots: els.takeScreenshots.checked,
    };
    const result = await api("/api/runs", { method: "POST", body: JSON.stringify(payload) });
    state.selectedRunId = result.run_id;
    state.lastLiveFindingCount = 0;
    state.runDetails.delete(result.run_id);
    primeActivity(result.run_id, "auto");
    await loadRuns();
    await loadRun(result.run_id, { force: true });
    startPolling();
  } catch (error) {
    alert(`Не удалось запустить проверку: ${error.message}`);
  } finally {
    syncActionButtons();
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
    state.lastLiveFindingCount = 0;
    state.runDetails.delete(result.run_id);
    primeActivity(result.run_id, "manual");
    await loadRuns();
    await loadRun(result.run_id, { force: true });
    startPolling();
  } catch (error) {
    alert(`Не удалось запустить ручную проверку: ${error.message}`);
  } finally {
    els.manualBtn.disabled = state.healthActionBlocked;
    els.manualBtn.textContent = "Проверить сайт";
  }
}

async function stopRun(runId = activeRunIdForStop()) {
  const normalizedRunId = Number(runId);
  if (!Number.isInteger(normalizedRunId) || normalizedRunId <= 0) return;
  const previousStatus = runStatusForId(normalizedRunId);
  state.stoppingRunIds.add(normalizedRunId);
  const runIndex = state.runs.findIndex((item) => Number(item.id) === normalizedRunId);
  if (runIndex >= 0) {
    state.runs[runIndex] = { ...state.runs[runIndex], status: "canceling" };
  }
  state.runStatuses.set(normalizedRunId, "canceling");
  syncStopButton();
  renderRuns();
  renderRunFolders();
  try {
    await api(`/api/runs/${normalizedRunId}/cancel`, { method: "POST" });
    state.runDetails.delete(normalizedRunId);
    await loadRun(normalizedRunId, { force: true });
    await loadRuns();
  } catch (error) {
    if (runIndex >= 0 && previousStatus) {
      state.runs[runIndex] = { ...state.runs[runIndex], status: previousStatus };
    }
    if (previousStatus) state.runStatuses.set(normalizedRunId, previousStatus);
    throw error;
  } finally {
    state.stoppingRunIds.delete(normalizedRunId);
    syncStopButton();
    syncActionButtons();
    renderRuns();
  }
}

async function loadRuns() {
  const limit = PAGE === "monitor" ? 20 : 100;
  const data = await api(`/api/runs?limit=${limit}`);
  state.runs = data.runs || [];
  const runIds = new Set(state.runs.map((run) => run.id));
  if (state.expandedRunFolderId && !runIds.has(state.expandedRunFolderId)) {
    state.expandedRunFolderId = null;
  }
  Array.from(state.runStatuses.keys()).forEach((runId) => {
    if (!runIds.has(runId) && runId !== state.selectedRunId) state.runStatuses.delete(runId);
  });
  state.runs.forEach((run) => state.runStatuses.set(run.id, run.status));
  if (!state.selectedRunId && state.runs.length) state.selectedRunId = state.runs[0].id;
  syncStopButton();
  syncActionButtons();
  renderRuns();
  renderRunFolders();
}

async function loadRun(runId, options = {}) {
  if (!runId) return;
  const cached = state.runDetails.get(runId);
  const canUseCache = cached && !options.force && !runningStatus(cached.run?.status);
  const includeFindings = Boolean(options.includeFindings || PAGE === "monitor");
  const compactFindings = Boolean(options.compactFindings || PAGE === "monitor");
  const incremental = Boolean(options.incremental && cached?.logs?.length);
  const params = new URLSearchParams();
  if (includeFindings) {
    params.set("include_findings", "true");
    params.set("finding_limit", String(options.findingLimit || (compactFindings ? 8 : 500)));
  }
  if (compactFindings) params.set("compact_findings", "true");
  if (incremental) {
    const lastLogId = Number(cached.logs[cached.logs.length - 1]?.id || 0);
    if (lastLogId) params.set("after_log_id", String(lastLogId));
    params.set("log_limit", "1000");
  }
  const query = params.toString();
  const suffix = query ? `?${query}` : "";
  const data = canUseCache && (!includeFindings || cached.findings)
    ? cached
    : await api(`/api/runs/${runId}${suffix}`);
  if (incremental) {
    const logsById = new Map();
    [...(cached.logs || []), ...(data.logs || [])].forEach((log) => logsById.set(log.id, log));
    data.logs = Array.from(logsById.values()).slice(-MAX_CACHED_LOGS);
  }
  if (!data.findings && cached?.findings) data.findings = cached.findings;
  if (!canUseCache || includeFindings || incremental) state.runDetails.set(runId, data);
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

  if (els.currentRun) els.currentRun.textContent = `#${run.id}`;
  const liveFindingCount = Number(run.finding_count || 0);
  if (els.runStatus) els.runStatus.textContent = `${runStatusLabel(run)} · ${liveFindingCount}/${run.candidate_count || 0}`;
  syncStopButton();
  syncActionButtons();

  showActivity(run, data.logs || [], data.findings || []);
  renderMethodology(run.methodology || []);
  renderLogs(data.logs || [], run.status);
  renderRuns();
  renderRunFolders();

  if (
    runningStatus(run.status)
    && liveFindingCount !== state.lastLiveFindingCount
    && Date.now() - state.lastCasesRefreshAt >= CASE_REFRESH_INTERVAL_MS
  ) {
    if (PAGE_USES_CASES) await loadCases({ preserveLimit: true });
    state.lastLiveFindingCount = liveFindingCount;
  }

  if (runningStatus(run.status)) {
    if (!state.pollTimer) startPolling();
  }
  else {
    if (!hasRunningRuns()) stopPolling();
    if (previousStatus && runningStatus(previousStatus)) {
      await loadRuns();
      if (PAGE_USES_CASES) await loadCases();
    }
    if (hasRunningRuns() && !state.pollTimer) startPolling();
  }
}

function setRunHistoryExpanded(expanded) {
  state.runHistoryExpanded = Boolean(expanded);
  if (els.runHistoryToggle) els.runHistoryToggle.setAttribute("aria-expanded", String(state.runHistoryExpanded));
  if (els.runHistoryContent) els.runHistoryContent.hidden = !state.runHistoryExpanded;
  if (els.runHistoryAction) els.runHistoryAction.textContent = state.runHistoryExpanded ? "Скрыть" : "Показать";
}

function updateRunHistorySummary() {
  if (!els.runHistorySummary) return;
  const activeCount = state.runs.filter((run) => runningStatus(run.status)).length;
  const total = state.runs.length;
  els.runHistorySummary.textContent = activeCount
    ? `${total} запусков · ${activeCount} активных`
    : `${total} запусков`;
}

function renderRuns() {
  updateRunHistorySummary();
  if (!els.runsList) return;
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
    const stopping = state.stoppingRunIds.has(Number(run.id));
    const stopControl = running
      ? `<button class="run-stop-btn" data-stop-run-id="${run.id}" type="button" ${stopping ? "disabled" : ""}>${stopping ? "Останавливаю" : "Остановить запуск"}</button>`
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
      loadRun(Number(button.dataset.runId), { force: true }).catch(console.error);
    });
    button.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
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

function runFolderBody(run) {
  const runId = Number(run.id);
  if (state.runFolderLoadingId === runId) {
    return '<div class="run-folder-message">Загружаю домены запуска...</div>';
  }
  const error = state.runFolderErrors.get(runId);
  if (error) {
    return `
      <div class="run-folder-message error">
        <span>${escapeHtml(error)}</span>
        <button class="secondary-btn" data-run-folder-retry="${runId}" type="button">Повторить</button>
      </div>`;
  }
  const details = state.runDetails.get(runId);
  const findings = Array.isArray(details?.findings) ? details.findings : [];
  if (!findings.length) {
    return `<div class="run-folder-message">В запуске #${runId} пока нет доменов.</div>`;
  }
  return `
    <div class="run-folder-toolbar">
      <span>${findings.length} доменов</span>
      <div>
        <button class="ghost-btn" data-run-folder-export="${runId}" data-run-folder-format="csv" type="button">CSV</button>
        <button class="ghost-btn" data-run-folder-export="${runId}" data-run-folder-format="xlsx" type="button">Excel</button>
      </div>
    </div>
    <div class="run-folder-findings">
      ${findings.map(runFindingRow).join("")}
    </div>`;
}

function renderRunFolders() {
  if (!els.runFoldersList) return;
  if (els.runFoldersCount) {
    els.runFoldersCount.textContent = `${state.runs.length} запусков`;
  }
  if (!state.runs.length) {
    els.runFoldersList.innerHTML = '<div class="empty-state">Запусков пока нет.</div>';
    return;
  }
  els.runFoldersList.innerHTML = state.runs.map((run) => {
    const runId = Number(run.id);
    const expanded = state.expandedRunFolderId === runId;
    const running = runningStatus(run.status);
    const signal = running ? "live" : run.status === "failed" ? "bad" : run.status === "interrupted" ? "warn" : "done";
    const count = Number(run.finding_count || 0);
    return `
      <article class="run-folder ${expanded ? "expanded" : ""} ${running ? "running" : ""}">
        <button class="run-folder-toggle" data-run-folder-id="${runId}" type="button" aria-expanded="${expanded}" aria-controls="run-folder-body-${runId}">
          <span class="folder-icon ${signal}" aria-hidden="true"><i></i></span>
          <span class="run-folder-title">
            <strong>Запуск #${runId}</strong>
            <small>${escapeHtml(formatDateTime(run.started_at))}</small>
          </span>
          <span class="run-folder-stats">
            <strong>${count} доменов</strong>
            <small>${escapeHtml(runStatusLabel(run))}</small>
          </span>
          <span class="folder-chevron" aria-hidden="true"></span>
        </button>
        ${expanded ? `<div id="run-folder-body-${runId}" class="run-folder-body">${runFolderBody(run)}</div>` : ""}
      </article>`;
  }).join("");

  els.runFoldersList.querySelectorAll("[data-run-folder-id]").forEach((button) => {
    button.addEventListener("click", () => toggleRunFolder(Number(button.dataset.runFolderId)).catch(console.error));
  });
  els.runFoldersList.querySelectorAll("[data-run-folder-retry]").forEach((button) => {
    button.addEventListener("click", () => loadRunFolder(Number(button.dataset.runFolderRetry), true).catch(console.error));
  });
  els.runFoldersList.querySelectorAll("[data-run-folder-export]").forEach((button) => {
    button.addEventListener("click", () => {
      const runId = Number(button.dataset.runFolderExport);
      const format = button.dataset.runFolderFormat;
      downloadFile(`/api/runs/${runId}/export.${format}`).catch((error) => {
        alert(`Не удалось скачать отчет запуска #${runId}: ${error.message}`);
      });
    });
  });
  els.runFoldersList.querySelectorAll("[data-run-finding-domain]").forEach((button) => {
    button.addEventListener("click", () => openCaseForFinding(
      button.dataset.runFindingDomain,
      Number(button.dataset.runFindingCase || 0),
    ).catch(console.error));
  });
}

async function loadRunFolder(runId, force = false) {
  const cached = state.runDetails.get(runId);
  const run = state.runs.find((item) => Number(item.id) === runId);
  const cachedCount = Array.isArray(cached?.findings) ? cached.findings.length : -1;
  const expectedCount = Number(run?.finding_count || 0);
  if (!force && cachedCount >= expectedCount && !runningStatus(run?.status)) {
    renderRunFolders();
    return;
  }
  state.runFolderLoadingId = runId;
  state.runFolderErrors.delete(runId);
  renderRunFolders();
  try {
    const data = await api(`/api/runs/${runId}?include_findings=true`);
    const previous = state.runDetails.get(runId) || {};
    state.runDetails.set(runId, { ...previous, ...data, findings: data.findings || [] });
    const runIndex = state.runs.findIndex((item) => Number(item.id) === runId);
    if (runIndex >= 0 && data.run) {
      state.runs[runIndex] = { ...state.runs[runIndex], ...data.run };
    }
  } catch (error) {
    state.runFolderErrors.set(runId, error.message || "Не удалось загрузить запуск.");
  } finally {
    if (state.runFolderLoadingId === runId) state.runFolderLoadingId = null;
    renderRunFolders();
  }
}

async function toggleRunFolder(runId) {
  if (state.expandedRunFolderId === runId) {
    state.expandedRunFolderId = null;
    renderRunFolders();
    return;
  }
  state.expandedRunFolderId = runId;
  renderRunFolders();
  await loadRunFolder(runId);
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
  if (meta.page !== undefined) parts.push(`страница: ${meta.page}`);
  if (meta.batch !== undefined) parts.push(`пакет: ${meta.batch}`);
  if (meta.checking !== undefined) parts.push(`в пакете: ${meta.checking}`);
  if (meta.checked_total !== undefined) parts.push(`проверяется: ${meta.checked_total}`);
  if (meta.candidate_total !== undefined) parts.push(`кандидатов: ${meta.candidate_total}`);
  if (meta.target_findings !== undefined) parts.push(`цель: ${meta.target_findings}`);
  if (meta.skipped !== undefined) parts.push(`пропущено: ${meta.skipped}`);
  if (meta.raw !== undefined) parts.push(`raw: ${meta.raw}`);
  if (meta.deduped !== undefined) parts.push(`после дедупликации: ${meta.deduped}`);
  if (meta.known_rechecked !== undefined) parts.push(`уже известные: ${meta.known_rechecked}`);
  if (meta.skipped_known !== undefined) parts.push(`пропущено повторов: ${meta.skipped_known}`);
  if (meta.skipped_attempted !== undefined) parts.push(`уже проверено: ${meta.skipped_attempted}`);
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

function compactLogRows(logs) {
  const rows = [];
  logs.forEach((log) => {
    const previous = rows[rows.length - 1];
    const groupable = log.level === "info" && /^Search page processed$/i.test(String(log.message || ""));
    if (groupable && previous?._groupable && previous.message === log.message) {
      const previousAdded = Number(previous.meta?.added);
      const nextAdded = Number(log.meta?.added);
      previous.timestamp = log.timestamp;
      previous._repeat += 1;
      previous.meta = { ...(log.meta || {}) };
      if (Number.isFinite(previousAdded) && Number.isFinite(nextAdded)) {
        previous.meta.added = previousAdded + nextAdded;
      }
      return;
    }
    rows.push({ ...log, meta: { ...(log.meta || {}) }, _repeat: 1, _groupable: groupable });
  });
  return rows;
}

function renderLogs(logs, runStatus = "") {
  if (!els.logsList || !els.warningCount) return;
  state.visibleLogs = logs;
  state.visibleRunStatus = runStatus;
  const warnings = logs.filter((log) => ["warning", "error"].includes(log.level)).length;
  els.warningCount.textContent = `${warnings} предупреждений`;
  const filteredLogs = state.logFilter === "all"
    ? logs
    : logs.filter((log) => log.level === state.logFilter);
  if (!filteredLogs.length) {
    const message = runningStatus(runStatus)
      ? state.logFilter === "all" ? "Ожидаю новое событие запуска." : "Событий этого уровня пока нет."
      : state.logFilter === "all" ? "Live-журнал завершен. Сохраненных ошибок нет." : "Событий этого уровня нет.";
    els.logsList.innerHTML = `<div class="empty-state">${message}</div>`;
    return;
  }
  const recentLogs = compactLogRows(filteredLogs.slice(-160)).slice(-60);
  const last = recentLogs[recentLogs.length - 1];
  const summary = `
    <div class="log-live-summary">
      <div>
        <span>Live журнал</span>
        <strong>${escapeHtml(last?.message || "Ожидаю событие")}</strong>
      </div>
      <div>
        <span>${recentLogs.length}/${filteredLogs.length} строк</span>
        <strong>${warnings} предупреждений</strong>
      </div>
    </div>
    <div class="log-table-head" aria-hidden="true">
      <span>Время</span><span>Уровень</span><span>Событие и детали</span>
    </div>`;
  els.logsList.innerHTML = summary + recentLogs.map((log) => {
    const cls = log.level === "error" ? "error" : log.level === "warning" ? "warning" : "";
    const meta = formatMetaParts(log.meta);
    return `
      <div class="log-line ${cls}">
        <span class="log-time">${escapeHtml(formatDateTime(log.timestamp))}</span>
        <strong class="log-level">${escapeHtml(levelLabels[log.level] || log.level)}</strong>
        <div class="log-body">
          <p>${escapeHtml(log.message)}${log._repeat > 1 ? `<span class="log-repeat">×${log._repeat}</span>` : ""}</p>
          ${meta.length ? `<div class="log-meta">${meta.map((item) => `<span>${escapeHtml(item)}</span>`).join("")}</div>` : ""}
        </div>
      </div>`;
  }).join("");
  els.logsList.scrollTop = els.logsList.scrollHeight;
}

async function loadCases(options = {}) {
  const params = new URLSearchParams({ archived: "false", limit: "250" });
  if (els.caseSearch?.value.trim()) params.set("q", els.caseSearch.value.trim());
  if (els.caseMinRisk?.value) params.set("min_risk", els.caseMinRisk.value);
  const data = await api(`/api/cases?${params.toString()}`);
  state.lastCasesRefreshAt = Date.now();
  state.cases = data.cases || [];
  const category = els.categoryFilter?.value || "";
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

function renderCaseStats(cases) {
  if (els.activeCaseCount) els.activeCaseCount.textContent = cases.length;
  if (els.highRiskCount) els.highRiskCount.textContent = cases.filter((item) => Number(item.best_risk_score || 0) >= 70).length;
  if (els.evidenceCount) els.evidenceCount.textContent = cases.filter((item) => item.html_path || item.screenshot_path).length;
}

function renderCases(cases) {
  if (els.registrySummary) {
    const filtered = cases.length !== state.cases.length;
    els.registrySummary.textContent = filtered ? `${cases.length} из ${state.cases.length} доменов` : `${cases.length} доменов`;
  }
  if (!els.casesList) return;
  if (!state.registryExpanded) {
    els.casesList.innerHTML = "";
    return;
  }
  if (!cases.length) {
    els.casesList.innerHTML = '<div class="empty-state">В выбранном фильтре нет рабочих доменов.</div>';
    return;
  }
  els.casesList.innerHTML = cases.map(domainRow).join("");
  bindCaseOpenButtons(els.casesList);
}

function setRegistryExpanded(open) {
  state.registryExpanded = Boolean(open);
  if (els.toggleRegistryBtn) {
    els.toggleRegistryBtn.setAttribute("aria-expanded", String(state.registryExpanded));
    els.toggleRegistryBtn.textContent = state.registryExpanded ? "Скрыть реестр" : "Открыть реестр";
  }
  if (els.registryDetails) els.registryDetails.hidden = !state.registryExpanded;
  renderCases(state.filteredCases);
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
  canvas.height = Math.floor(TREND_CHART_HEIGHT * dpr);
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  const width = rect.width;
  const height = TREND_CHART_HEIGHT;
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
  const totals = Object.fromEntries(series.map((item) => [item.category, item.values.reduce((sum, value) => sum + value, 0)]));
  const total = Object.values(totals).reduce((sum, value) => sum + value, 0);
  if (els.trendTotal) els.trendTotal.textContent = String(total);
  if (els.trendCasinoCount) els.trendCasinoCount.textContent = String(totals.casino || 0);
  if (els.trendPhishingCount) els.trendPhishingCount.textContent = String(totals.phishing || 0);
  if (els.trendPyramidCount) els.trendPyramidCount.textContent = String(totals.pyramid || 0);
  if (els.trendEmptyState) els.trendEmptyState.hidden = total > 0;
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

  const labelStep = width < 640 ? 5 : 3;
  const lastDayIndex = days.length - 1;
  ctx.textAlign = "center";
  days.forEach((date, index) => {
    if (index !== lastDayIndex && (index % labelStep !== 0 || lastDayIndex - index < Math.ceil(labelStep / 2))) return;
    const x = plot.left + (plotWidth * index) / Math.max(1, days.length - 1);
    const label = date.toLocaleDateString("ru-RU", { day: "2-digit", month: "2-digit" });
    ctx.fillText(label, x, height - 20);
  });
  ctx.textAlign = "start";

  series.forEach(({ category, values }) => {
    if (!values.some((value) => value > 0)) return;
    const points = values.map((value, index) => ({
      value,
      x: plot.left + (plotWidth * index) / Math.max(1, values.length - 1),
      y: plot.top + plotHeight - (plotHeight * value) / axisMax,
    }));
    const fill = ctx.createLinearGradient(0, plot.top, 0, plot.top + plotHeight);
    fill.addColorStop(0, categoryFillColors[category]);
    fill.addColorStop(1, "rgba(8, 13, 20, 0)");
    ctx.beginPath();
    points.forEach((point, index) => {
      if (index === 0) ctx.moveTo(point.x, point.y);
      else ctx.lineTo(point.x, point.y);
    });
    ctx.lineTo(points[points.length - 1].x, plot.top + plotHeight);
    ctx.lineTo(points[0].x, plot.top + plotHeight);
    ctx.closePath();
    ctx.fillStyle = fill;
    ctx.fill();

    ctx.strokeStyle = categoryColors[category];
    ctx.fillStyle = categoryColors[category];
    ctx.lineWidth = 3;
    ctx.beginPath();
    points.forEach((point, index) => {
      if (index === 0) ctx.moveTo(point.x, point.y);
      else ctx.lineTo(point.x, point.y);
    });
    ctx.stroke();
    points.forEach((point) => {
      if (point.value <= 0) return;
      ctx.beginPath();
      ctx.arc(point.x, point.y, 4, 0, Math.PI * 2);
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
  const height = TREND_CHART_HEIGHT;
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
  if (!els.drawerOverlay || !els.drawerTitle || !els.caseDetailContent) return;
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
  if (!els.drawerTitle || !els.caseDetailContent) return;
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
  if (els.drawerOverlay) els.drawerOverlay.hidden = true;
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
      await loadRun(state.selectedRunId, { force: true, incremental: true });
    }
  } catch (error) {
    console.error(error);
  } finally {
    state.pollInFlight = false;
    if (hasRunningRuns()) startPolling();
  }
}

els.scanForm?.addEventListener("submit", startRun);
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
els.stopBtn?.addEventListener("click", () => {
  stopRun().catch((error) => alert(`Не удалось остановить запуск: ${error.message}`));
});
els.runHistoryToggle?.addEventListener("click", () => {
  setRunHistoryExpanded(!state.runHistoryExpanded);
});
els.caseFilterBtn?.addEventListener("click", loadCases);
els.categoryFilter?.addEventListener("change", loadCases);
els.caseSearch?.addEventListener("keydown", (event) => {
  if (event.key === "Enter") loadCases();
});
els.exportCasesCsvBtn?.addEventListener("click", () => exportCurrentCases("csv").catch((error) => alert(`Не удалось скачать CSV: ${error.message}`)));
els.exportCasesXlsxBtn?.addEventListener("click", () => exportCurrentCases("xlsx").catch((error) => alert(`Не удалось скачать Excel: ${error.message}`)));
els.toggleRegistryBtn?.addEventListener("click", () => {
  setRegistryExpanded(!state.registryExpanded);
});
document.querySelectorAll("[data-log-filter]").forEach((button) => {
  button.addEventListener("click", () => {
    state.logFilter = button.dataset.logFilter || "all";
    document.querySelectorAll("[data-log-filter]").forEach((item) => {
      item.classList.toggle("active", item === button);
    });
    renderLogs(state.visibleLogs, state.visibleRunStatus);
  });
});
els.drawerClose?.addEventListener("click", closeDrawer);
els.drawerOverlay?.addEventListener("click", (event) => {
  if (event.target === els.drawerOverlay) closeDrawer();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    closeDrawer();
    setHealthDetailsOpen(false);
  }
});
if (els.trendChart) window.addEventListener("resize", () => drawTrend(state.cases));
els.trendChart?.addEventListener("mousemove", handleChartMove);
els.trendChart?.addEventListener("mouseleave", clearChartHover);

els.authForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  state.apiToken = els.apiTokenInput?.value.trim() || "";
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
    if (PAGE === "monitor") {
      await loadRuns();
      if (state.selectedRunId) await loadRun(state.selectedRunId);
      await loadCases();
      return;
    }
    if (PAGE === "registry") {
      setRegistryExpanded(true);
      await loadCases();
      return;
    }
    if (PAGE === "dynamics") {
      await loadCases();
      return;
    }
    if (PAGE === "runs") {
      await loadRuns();
      return;
    }
    if (PAGE === "journal") {
      await loadRuns();
      if (state.selectedRunId) await loadRun(state.selectedRunId);
    }
  }
}

bootstrap().catch(console.error);
