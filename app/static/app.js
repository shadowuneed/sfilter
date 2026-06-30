const state = {
  selectedRunId: null,
  pollTimer: null,
  cases: [],
  filteredCases: [],
  runs: [],
  activityRunId: null,
  apiToken: localStorage.getItem("argus_api_token") || "",
  authRequired: true,
  authConfigured: false,
};

const els = {
  scanForm: document.getElementById("scanForm"),
  healthLine: document.getElementById("healthLine"),
  geminiPill: document.getElementById("geminiPill"),
  kzAccessPill: document.getElementById("kzAccessPill"),
  runBtn: document.getElementById("runBtn"),
  stopBtn: document.getElementById("stopBtn"),
  seedQuery: document.getElementById("seedQuery"),
  maxCandidates: document.getElementById("maxCandidates"),
  takeScreenshots: document.getElementById("takeScreenshots"),
  manualTarget: document.getElementById("manualTarget"),
  manualCategory: document.getElementById("manualCategory"),
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
  caseSearch: document.getElementById("caseSearch"),
  categoryFilter: document.getElementById("categoryFilter"),
  caseMinRisk: document.getElementById("caseMinRisk"),
  caseFilterBtn: document.getElementById("caseFilterBtn"),
  casesList: document.getElementById("casesList"),
  evidenceCards: document.getElementById("evidenceCards"),
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
  completed: "готово",
  failed: "ошибка",
};

const categoryLabels = {
  casino: "Казино",
  phishing: "Фишинг",
  pyramid: "Пирамиды",
  suspicious: "Подозрительный",
};

const categoryColors = {
  casino: "#f59e0b",
  phishing: "#ef4444",
  pyramid: "#8b5cf6",
  suspicious: "#3b82f6",
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
    if (response.status === 401 || response.status === 503) {
      showAuth(text || response.statusText);
    }
    throw new Error(text || response.statusText);
  }
  return response.json();
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

function normalizeCategory(value) {
  const text = String(value || "").toLowerCase();
  if (/(casino|gambling|betting|bookmaker)/.test(text)) return "casino";
  if (/(phishing|scam|malware)/.test(text)) return "phishing";
  if (/(pyramid|investment)/.test(text)) return "pyramid";
  return "suspicious";
}

function categoryLabel(value) {
  return categoryLabels[normalizeCategory(value)] || "Подозрительный";
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

function latestLog(logs = []) {
  return logs.length ? logs[logs.length - 1] : null;
}

function activityStageIndex(run = {}, logs = []) {
  if (run.status === "completed" || run.status === "failed" || run.status === "canceled") {
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
  const done = ["completed", "failed", "canceled"].includes(run.status);
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
  els.activityPanel.classList.toggle("failed", done && run.status !== "completed");
  els.activityHeadline.textContent = run.id
    ? `Запуск #${run.id}: ${statusLabel(run.status)}`
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

function renderPill(el, text, cls) {
  el.textContent = text;
  el.className = `health-pill ${cls}`;
}

async function loadHealth() {
  try {
    const health = await api("/api/health");
    state.authRequired = Boolean(health.auth_required);
    state.authConfigured = Boolean(health.auth_configured);
    renderPill(els.geminiPill, health.gemini_configured ? "AI: готов" : "AI: нет ключа", health.gemini_configured ? "ok" : "warn");
    renderPill(
      els.kzAccessPill,
      health.kz_proxy_configured ? "KZ: proxy" : "KZ: сеть сервера",
      health.kz_proxy_configured ? "ok" : "warn",
    );
    const keyCount = health.gemini_key_count ?? health.gemini_keys?.length ?? 0;
    els.healthLine.textContent = health.gemini_configured
      ? `${keyCount} ключ(а), модель ${health.gemini_model}. Доступность: ${health.kz_access_label}.`
      : "Добавьте GEMINI_API_KEYS в .env или Render Environment.";
    if (state.authRequired && !state.authConfigured) {
      showAuth("ADMIN_TOKEN is not configured on the server.");
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
    const payload = {
      seed_query: els.seedQuery.value.trim() || null,
      max_candidates: Number(els.maxCandidates.value || 8),
      take_screenshots: els.takeScreenshots.checked,
    };
    const result = await api("/api/runs", { method: "POST", body: JSON.stringify(payload) });
    state.selectedRunId = result.run_id;
    primeActivity(result.run_id, "auto");
    await loadRuns();
    await loadRun(result.run_id);
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
      category: els.manualCategory?.value || "suspicious",
      take_screenshots: els.takeScreenshots.checked,
    };
    const result = await api("/api/manual-check", { method: "POST", body: JSON.stringify(payload) });
    state.selectedRunId = result.run_id;
    primeActivity(result.run_id, "manual");
    await loadRuns();
    await loadRun(result.run_id);
    startPolling();
  } catch (error) {
    alert(`Не удалось запустить ручную проверку: ${error.message}`);
  } finally {
    els.manualBtn.disabled = false;
    els.manualBtn.textContent = "Проверить сайт";
  }
}

async function stopRun() {
  if (!state.selectedRunId) return;
  els.stopBtn.disabled = true;
  await api(`/api/runs/${state.selectedRunId}/cancel`, { method: "POST" });
  await loadRun(state.selectedRunId);
}

async function loadRuns() {
  const data = await api("/api/runs?limit=40");
  state.runs = data.runs || [];
  if (!state.selectedRunId && state.runs.length) state.selectedRunId = state.runs[0].id;
  renderRuns();
}

async function loadRun(runId) {
  if (!runId) return;
  const data = await api(`/api/runs/${runId}`);
  const run = data.run;
  state.selectedRunId = run.id;

  els.currentRun.textContent = `#${run.id}`;
  els.runStatus.textContent = `${statusLabel(run.status)} · ${run.finding_count || 0}/${run.candidate_count || 0}`;
  els.stopBtn.disabled = !runningStatus(run.status);

  showActivity(run, data.logs || []);
  renderMethodology(run.methodology || []);
  renderLogs(data.logs || []);
  await loadRuns();

  if (runningStatus(run.status)) startPolling();
  else {
    stopPolling();
    await loadCases();
  }
}

function renderRuns() {
  if (!state.runs.length) {
    els.runsList.innerHTML = '<div class="empty-state">Запусков пока нет.</div>';
    return;
  }
  els.runsList.innerHTML = state.runs.map((run) => {
    const active = run.id === state.selectedRunId ? "active" : "";
    const signal = runningStatus(run.status) ? "live" : run.status === "failed" ? "bad" : "done";
    return `
      <button class="run-item ${active}" data-run-id="${run.id}" type="button">
        <span class="run-signal ${signal}"></span>
        <span>
          <strong>#${run.id}</strong>
          <small>${escapeHtml(formatDateTime(run.started_at))}</small>
        </span>
        <span>
          <strong>${escapeHtml(statusLabel(run.status))}</strong>
          <small>${run.finding_count || 0} находок</small>
        </span>
      </button>`;
  }).join("");
  document.querySelectorAll("[data-run-id]").forEach((button) => {
    button.addEventListener("click", () => loadRun(Number(button.dataset.runId)).catch(console.error));
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
  if (!meta || !Object.keys(meta).length) return "";
  const parts = [];
  if (meta.domain) parts.push(`домен: ${meta.domain}`);
  if (meta.url) parts.push(`url: ${meta.url}`);
  if (meta.reason) parts.push(`причина: ${meta.reason}`);
  if (meta.access_origin) parts.push(`сеть: ${meta.access_origin}`);
  if (meta.count !== undefined) parts.push(`кол-во: ${meta.count}`);
  if (meta.findings !== undefined) parts.push(`в отчете: ${meta.findings}`);
  if (meta.risk_score !== undefined) parts.push(`риск: ${meta.risk_score}`);
  if (meta.status_code !== undefined && meta.status_code !== null) parts.push(`HTTP: ${meta.status_code}`);
  if (meta.error) parts.push(`ошибка: ${meta.error}`);
  return parts.length ? ` · ${parts.join(" · ")}` : "";
}

function renderLogs(logs) {
  const warnings = logs.filter((log) => ["warning", "error"].includes(log.level)).length;
  els.warningCount.textContent = `${warnings} предупреждений`;
  if (!logs.length) {
    els.logsList.innerHTML = '<div class="empty-state">Журнал появится после запуска.</div>';
    return;
  }
  els.logsList.innerHTML = logs.slice(-80).map((log) => {
    const cls = log.level === "error" ? "error" : log.level === "warning" ? "warning" : "";
    return `
      <div class="log-line ${cls}">
        <span>${escapeHtml(formatDateTime(log.timestamp))}</span>
        <strong>${escapeHtml(log.level)}</strong>
        <p>${escapeHtml(log.message)}${escapeHtml(formatMeta(log.meta))}</p>
      </div>`;
  }).join("");
  els.logsList.scrollTop = els.logsList.scrollHeight;
}

async function loadCases() {
  const params = new URLSearchParams({ archived: "false", limit: "1000" });
  if (els.caseSearch.value.trim()) params.set("q", els.caseSearch.value.trim());
  if (els.caseMinRisk.value) params.set("min_risk", els.caseMinRisk.value);
  const data = await api(`/api/cases?${params.toString()}`);
  state.cases = data.cases || [];
  const category = els.categoryFilter.value;
  state.filteredCases = category
    ? state.cases.filter((item) => normalizeCategory(item.category) === category)
    : state.cases;
  renderCaseStats(state.cases);
  renderCases(state.filteredCases);
  drawTrend(state.cases);
}

function renderCaseStats(cases) {
  els.activeCaseCount.textContent = cases.length;
  els.highRiskCount.textContent = cases.filter((item) => Number(item.best_risk_score || 0) >= 70).length;
  els.evidenceCount.textContent = cases.filter((item) => item.html_path || item.screenshot_path).length;
}

function renderCases(cases) {
  renderEvidenceCards(cases);
  if (!cases.length) {
    els.casesList.innerHTML = '<div class="empty-state">В выбранном фильтре нет рабочих доменов.</div>';
    return;
  }
  els.casesList.innerHTML = cases.map(domainRow).join("");
  bindCaseOpenButtons(els.casesList);
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
  const sslClass = tls.valid ? "good" : "bad";
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
          ${techRow("Дней до истечения", daysLeft ?? "None", daysLeft !== null && daysLeft >= 14 ? "good" : "bad")}
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
}

async function openCase(caseId) {
  els.drawerOverlay.hidden = false;
  els.caseDetailContent.innerHTML = '<div class="empty-state">Загружаю доказательства...</div>';
  const data = await api(`/api/cases/${caseId}`);
  renderCaseDetail(data.case, data.findings || []);
}

function latestFinding(item, findings) {
  return findings[0] || item || {};
}

function positiveSignals(finding) {
  const evidence = finding.evidence || {};
  const tls = finding.tls || {};
  const dns = finding.dns || {};
  const signals = [];
  if (finding.status_code >= 200 && finding.status_code < 400) signals.push(`Сайт отвечает HTTP ${finding.status_code}`);
  if (tls.valid) signals.push(`SSL сертификат действителен${tls.issuer ? `, издатель ${tls.issuer}` : ""}`);
  if ((dns.records || []).length) signals.push(`DNS возвращает ${(dns.records || []).length} IP адрес(ов)`);
  if (finding.html_sha256) signals.push("HTML сохранен с SHA-256 отпечатком");
  if (finding.screenshot_path) signals.push("Скриншот страницы сохранен");
  if (evidence.response_time_ms && evidence.response_time_ms < 1500) signals.push(`Быстрый ответ: ${formatResponseTime(evidence.response_time_ms)}`);
  if (evidence.access_origin) signals.push(`Проверено через: ${evidence.access_origin}`);
  return signals.length ? signals : ["Положительные технические признаки не выделены"];
}

function negativeSignals(finding) {
  const evidence = finding.evidence || {};
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
  return signals.length ? signals : ["Явные негативные признаки не найдены"];
}

function renderSignalList(items, type) {
  return `
    <div class="signal-box ${type}">
      <h3>${type === "positive" ? "Позитивные признаки" : "Подозрительные признаки"}</h3>
      <ul>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
    </div>`;
}

function techRow(label, value, cls = "") {
  return `<div class="tech-row"><span>${escapeHtml(label)}</span><strong class="${cls}">${escapeHtml(value ?? "N/A")}</strong></div>`;
}

function techCard(title, rows) {
  return `<article class="tech-card"><h3>${escapeHtml(title)}</h3>${rows.join("")}</article>`;
}

function renderCaseDetail(item, findings) {
  const finding = latestFinding(item, findings);
  const evidence = finding.evidence || {};
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
          techRow("Статус", tls.valid ? "Действителен" : "Недействителен", tls.valid ? "good" : "bad"),
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
  stopPolling();
  state.pollTimer = setInterval(() => {
    if (state.selectedRunId) loadRun(state.selectedRunId).catch(console.error);
  }, 4000);
}

function stopPolling() {
  if (state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
}

els.scanForm.addEventListener("submit", startRun);
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
els.drawerClose.addEventListener("click", closeDrawer);
els.drawerOverlay.addEventListener("click", (event) => {
  if (event.target === els.drawerOverlay) closeDrawer();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeDrawer();
});
window.addEventListener("resize", () => drawTrend(state.cases));

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
  if (state.authRequired && (!state.authConfigured || !state.apiToken)) {
    drawTrend([]);
    return;
  }
  await loadRuns();
  if (state.selectedRunId) await loadRun(state.selectedRunId);
  await loadCases();
}

bootstrap().catch(console.error);
