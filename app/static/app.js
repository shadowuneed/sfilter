const state = {
  selectedRunId: null,
  pollTimer: null,
  selectedCases: new Set(),
  runStatuses: new Map(),
  cases: [],
};

const els = {
  healthLine: document.getElementById("healthLine"),
  statusPill: document.getElementById("statusPill"),
  runBtn: document.getElementById("runBtn"),
  stopBtn: document.getElementById("stopBtn"),
  refreshBtn: document.getElementById("refreshBtn"),
  seedQuery: document.getElementById("seedQuery"),
  maxCandidates: document.getElementById("maxCandidates"),
  takeScreenshots: document.getElementById("takeScreenshots"),
  currentRun: document.getElementById("currentRun"),
  runStatus: document.getElementById("runStatus"),
  candidateCount: document.getElementById("candidateCount"),
  findingCount: document.getElementById("findingCount"),
  runsList: document.getElementById("runsList"),
  findingsList: document.getElementById("findingsList"),
  logsList: document.getElementById("logsList"),
  warningCount: document.getElementById("warningCount"),
  csvLink: document.getElementById("csvLink"),
  xlsxLink: document.getElementById("xlsxLink"),
  casesList: document.getElementById("casesList"),
  caseSearch: document.getElementById("caseSearch"),
  caseStatusFilter: document.getElementById("caseStatusFilter"),
  caseArchiveFilter: document.getElementById("caseArchiveFilter"),
  caseSavedFilter: document.getElementById("caseSavedFilter"),
  caseMinRisk: document.getElementById("caseMinRisk"),
  caseFilterBtn: document.getElementById("caseFilterBtn"),
  selectedCsvBtn: document.getElementById("selectedCsvBtn"),
  selectedXlsxBtn: document.getElementById("selectedXlsxBtn"),
  totalCaseCount: document.getElementById("totalCaseCount"),
  activeCaseCount: document.getElementById("activeCaseCount"),
  savedCaseCount: document.getElementById("savedCaseCount"),
  selectedCaseCount: document.getElementById("selectedCaseCount"),
  drawerOverlay: document.getElementById("drawerOverlay"),
  drawerClose: document.getElementById("drawerClose"),
  drawerTitle: document.getElementById("drawerTitle"),
  caseDetailContent: document.getElementById("caseDetailContent"),
  aiActivity: document.getElementById("aiActivity"),
  aiActivityTitle: document.getElementById("aiActivityTitle"),
  aiActivityText: document.getElementById("aiActivityText"),
  aiActivityJump: document.getElementById("aiActivityJump"),
};

const statusLabels = {
  queued: "в очереди",
  running: "идет поиск",
  canceling: "останавливается",
  canceled: "остановлено",
  completed: "готово",
  failed: "ошибка",
};

const caseStatusLabels = {
  uninvestigated: "Не расследован",
  investigating: "Расследуется",
  investigated: "Расследован",
};

const verdictLabels = {
  suspected_fraud_or_illegal: "высокий риск",
  suspicious: "подозрительно",
  needs_review: "проверить вручную",
  low_signal: "слабый сигнал",
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || response.statusText);
  }
  return response.json();
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
  return String(path).replaceAll("\\", "/");
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("ru-RU", { dateStyle: "short", timeStyle: "short" });
}

function statusLabel(status) {
  return statusLabels[status] || status || "-";
}

function caseStatusLabel(status) {
  return caseStatusLabels[status] || status || "-";
}

function verdictLabel(verdict) {
  return verdictLabels[verdict] || verdict || "-";
}

function riskClass(score) {
  if (score >= 80) return "high";
  if (score >= 55) return "mid";
  return "low";
}

function terminalStatus(status) {
  return ["completed", "failed", "canceled"].includes(status);
}

function runningStatus(status) {
  return ["queued", "running", "canceling"].includes(status);
}

function selectedCaseQuery() {
  return Array.from(state.selectedCases).join(",");
}

function updateSelectedCount() {
  els.selectedCaseCount.textContent = state.selectedCases.size;
}

function formatMeta(meta) {
  if (!meta || !Object.keys(meta).length) return "";
  const parts = [];
  if (meta.domain) parts.push(`домен: ${meta.domain}`);
  if (meta.url) parts.push(`url: ${meta.url}`);
  if (meta.reason) parts.push(`причина: ${meta.reason}`);
  if (meta.count !== undefined) parts.push(`кол-во: ${meta.count}`);
  if (meta.findings !== undefined) parts.push(`в отчете: ${meta.findings}`);
  if (meta.risk_score !== undefined) parts.push(`риск: ${meta.risk_score}`);
  if (meta.status_code !== undefined && meta.status_code !== null) parts.push(`HTTP: ${meta.status_code}`);
  if (meta.error) parts.push(`ошибка: ${meta.error}`);
  return parts.length ? ` · ${parts.join(" · ")}` : "";
}

function showAiActivity(title, text, status = "running") {
  els.aiActivity.hidden = false;
  els.aiActivity.className = `ai-activity ${status}`;
  els.aiActivityTitle.textContent = title;
  els.aiActivityText.textContent = text || "Argus продолжает проверку...";
}

function hideAiActivity() {
  els.aiActivity.hidden = true;
}

function latestActivityText(logs) {
  if (!logs || !logs.length) return "Gemini собирает кандидатов и источники...";
  const last = logs[logs.length - 1];
  return `${last.message}${formatMeta(last.meta)}`;
}

function updateAiActivity(run, logs = []) {
  if (!run || !runningStatus(run.status)) {
    hideAiActivity();
    return;
  }
  if (run.status === "queued") {
    showAiActivity("ИИ готовит запуск", "Создаю проверку и подключаю Gemini...", "queued");
    return;
  }
  if (run.status === "canceling") {
    showAiActivity("Останавливаю проверку", "Даю текущему запросу завершиться и закрываю запуск.", "canceling");
    return;
  }
  showAiActivity("ИИ ищет подозрительные сайты", latestActivityText(logs), "running");
}

async function loadHealth() {
  try {
    const health = await api("/api/health");
    els.statusPill.textContent = health.gemini_configured ? "готово" : "нет ключа";
    els.statusPill.className = health.gemini_configured ? "ok" : "warn";
    els.healthLine.textContent = health.gemini_configured
      ? `${health.gemini_keys.length} ключ(а), ${health.rpm_limit}/мин и ${health.rpd_limit}/день на ключ`
      : "Добавьте GEMINI_API_KEYS в .env";
  } catch (error) {
    els.statusPill.textContent = "ошибка";
    els.statusPill.className = "warn";
    els.healthLine.textContent = error.message;
  }
}

async function startRun() {
  els.runBtn.disabled = true;
  els.runBtn.textContent = "Запускаю...";
  showAiActivity("ИИ готовит запуск", "Создаю проверку и подключаю Gemini...", "queued");
  try {
    const payload = {
      seed_query: els.seedQuery.value.trim() || null,
      max_candidates: Number(els.maxCandidates.value || 8),
      take_screenshots: els.takeScreenshots.checked,
    };
    const result = await api("/api/runs", { method: "POST", body: JSON.stringify(payload) });
    state.selectedRunId = result.run_id;
    await loadRuns();
    await loadRun(result.run_id, { refreshRegistry: false });
    startPolling();
  } catch (error) {
    hideAiActivity();
    alert(`Не удалось запустить проверку: ${error.message}`);
  } finally {
    els.runBtn.disabled = false;
    els.runBtn.textContent = "Начать проверку";
  }
}

async function stopRun() {
  if (!state.selectedRunId) return;
  showAiActivity("Останавливаю проверку", "Отправляю команду остановки...", "canceling");
  els.stopBtn.disabled = true;
  await api(`/api/runs/${state.selectedRunId}/cancel`, { method: "POST" });
  await loadRun(state.selectedRunId, { refreshRegistry: true });
}

async function loadRuns() {
  const data = await api("/api/runs?limit=50");
  if (!data.runs.length) {
    els.runsList.innerHTML = '<div class="empty-state">Пока нет запусков.</div>';
    return;
  }
  if (!state.selectedRunId) state.selectedRunId = data.runs[0].id;
  els.runsList.innerHTML = data.runs.map((run) => {
    const active = run.id === state.selectedRunId ? "active" : "";
    const signal = runningStatus(run.status) ? "live" : run.status === "failed" ? "bad" : "done";
    return `
      <button class="run-item ${active}" data-run-id="${run.id}">
        <span class="run-signal ${signal}"></span>
        <span class="run-main">
          <strong>#${run.id}</strong>
          <small>${escapeHtml(formatDate(run.started_at))}</small>
        </span>
        <span class="run-side">
          <strong>${escapeHtml(statusLabel(run.status))}</strong>
          <small>${run.finding_count || 0} в отчете</small>
        </span>
      </button>`;
  }).join("");
  document.querySelectorAll(".run-item").forEach((button) => {
    button.addEventListener("click", () => {
      state.selectedRunId = Number(button.dataset.runId);
      loadRun(state.selectedRunId, { refreshRegistry: false });
    });
  });
}

async function loadRun(runId, options = {}) {
  if (!runId) return;
  const data = await api(`/api/runs/${runId}`);
  const run = data.run;
  const previousStatus = state.runStatuses.get(run.id);
  state.runStatuses.set(run.id, run.status);
  state.selectedRunId = run.id;

  els.currentRun.textContent = `#${run.id}`;
  els.runStatus.textContent = statusLabel(run.status);
  els.candidateCount.textContent = run.candidate_count || 0;
  els.findingCount.textContent = run.finding_count || 0;
  els.csvLink.href = `/api/runs/${run.id}/export.csv`;
  els.xlsxLink.href = `/api/runs/${run.id}/export.xlsx`;
  els.csvLink.classList.remove("link-disabled");
  els.xlsxLink.classList.remove("link-disabled");
  els.stopBtn.disabled = !runningStatus(run.status);

  renderFindings(data.findings || []);
  renderLogs(data.logs || []);
  updateAiActivity(run, data.logs || []);
  await loadRuns();

  const finishedNow = terminalStatus(run.status) && previousStatus && runningStatus(previousStatus);
  if (options.refreshRegistry || finishedNow) await loadCases();
  if (runningStatus(run.status)) startPolling();
  else stopPolling();
}

function renderFindings(findings) {
  if (!findings.length) {
    els.findingsList.innerHTML = '<div class="empty-state">В этом запуске пока нет зафиксированных сайтов.</div>';
    return;
  }
  els.findingsList.innerHTML = findings.map(findingCard).join("");
}

function findingCard(finding) {
  const screenshot = relPath(finding.screenshot_path);
  const html = relPath(finding.html_path);
  const sourceUrl = finding.sources?.[0]?.url;
  const reasons = (finding.reasons || []).slice(0, 5);
  const evidence = finding.evidence || {};
  return `
    <article class="finding-card">
      <div class="finding-title-row">
        <div>
          <strong>${escapeHtml(finding.domain)}</strong>
          ${finding.title ? `<span>${escapeHtml(finding.title)}</span>` : ""}
        </div>
        <div class="risk-pill ${riskClass(finding.risk_score)}">${finding.risk_score}/100</div>
      </div>
      <div class="fact-grid">
        <div><span>Вердикт</span><strong>${escapeHtml(verdictLabel(finding.verdict))}</strong></div>
        <div><span>Тип</span><strong>${escapeHtml(finding.category || "подозрительный")}</strong></div>
        <div><span>HTTP</span><strong>${escapeHtml(finding.status_code || "-")}</strong></div>
      </div>
      ${reasons.length ? `<ul class="reason-list">${reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}</ul>` : ""}
      ${evidence.search_query ? `<div class="soft-note">Запрос: ${escapeHtml(evidence.search_query)}</div>` : ""}
      <div class="inline-actions">
        <a href="${escapeHtml(finding.final_url || finding.url)}" target="_blank">Открыть сайт</a>
        ${screenshot ? `<a href="/${escapeHtml(screenshot)}" target="_blank">Скриншот</a>` : ""}
        ${html ? `<a href="/${escapeHtml(html)}" target="_blank">HTML</a>` : ""}
        ${sourceUrl ? `<a href="${escapeHtml(sourceUrl)}" target="_blank">Источник</a>` : ""}
      </div>
    </article>`;
}

function renderLogs(logs) {
  const warnings = logs.filter((log) => ["warning", "error"].includes(log.level)).length;
  els.warningCount.textContent = `${warnings} ошибок/пропусков`;
  if (!logs.length) {
    els.logsList.innerHTML = '<div class="empty-state">Журнал появится после запуска.</div>';
    return;
  }
  els.logsList.innerHTML = logs.map((log) => {
    const cls = log.level === "error" ? "error" : log.level === "warning" ? "warning" : "";
    return `<div class="log-line ${cls}"><span>${escapeHtml(formatDate(log.timestamp))}</span><strong>${escapeHtml(log.level)}</strong><span>${escapeHtml(log.message)}${escapeHtml(formatMeta(log.meta))}</span></div>`;
  }).join("");
  els.logsList.scrollTop = els.logsList.scrollHeight;
}

async function loadCases() {
  const params = new URLSearchParams({ limit: "1000" });
  if (els.caseSearch.value.trim()) params.set("q", els.caseSearch.value.trim());
  if (els.caseStatusFilter.value) params.set("status", els.caseStatusFilter.value);
  if (els.caseArchiveFilter.value !== "") params.set("archived", els.caseArchiveFilter.value);
  if (els.caseSavedFilter.value !== "") params.set("saved", els.caseSavedFilter.value);
  if (els.caseMinRisk.value) params.set("min_risk", els.caseMinRisk.value);
  const data = await api(`/api/cases?${params.toString()}`);
  state.cases = data.cases || [];
  renderCaseStats(state.cases);
  renderCases(state.cases);
}

function renderCaseStats(cases) {
  els.totalCaseCount.textContent = cases.length;
  els.activeCaseCount.textContent = cases.filter((item) => !item.archived).length;
  els.savedCaseCount.textContent = cases.filter((item) => item.saved).length;
  updateSelectedCount();
}

function renderCases(cases) {
  if (!cases.length) {
    els.casesList.innerHTML = '<div class="empty-state">В этом фильтре пока ничего нет.</div>';
    return;
  }
  els.casesList.innerHTML = cases.map((item) => caseRow(item)).join("");
  bindCaseControls();
}

function caseRow(item) {
  const checked = state.selectedCases.has(item.id) ? "checked" : "";
  const archivedClass = item.archived ? "archived" : "";
  const screenshot = relPath(item.screenshot_path);
  const evidenceBits = [
    item.screenshot_path ? "скриншот" : null,
    item.html_path ? "HTML" : null,
    item.html_sha256 ? "SHA-256" : null,
  ].filter(Boolean).join(" · ");
  return `
    <article class="case-row ${archivedClass}" data-case-id="${item.id}">
      <div class="case-main">
        <input class="case-select" type="checkbox" data-case-select="${item.id}" ${checked}>
        <div>
          <button class="case-domain-button" data-case-open="${item.id}">${escapeHtml(item.domain)}</button>
          ${item.title ? `<p>${escapeHtml(item.title)}</p>` : ""}
          <div class="case-chips">
            <span>${escapeHtml(item.category || "suspicious")}</span>
            <span>${escapeHtml(evidenceBits || "без скриншота")}</span>
            ${item.saved ? "<span>сохранено</span>" : ""}
            ${item.archived ? "<span>архив</span>" : ""}
          </div>
        </div>
      </div>
      <div class="risk-pill ${riskClass(item.best_risk_score)}">${item.best_risk_score}/100</div>
      <select class="case-status-select" data-case-status="${item.id}">
        ${Object.entries(caseStatusLabels).map(([value, label]) => `<option value="${value}" ${item.status === value ? "selected" : ""}>${label}</option>`).join("")}
      </select>
      <div class="case-runs">
        <strong>${item.run_total || 0}</strong>
        <span>запусков</span>
        <small>последний #${escapeHtml(item.latest_run_id || "-")}</small>
      </div>
      <div class="case-actions">
        <button class="secondary-btn mini" data-case-open="${item.id}">Дело</button>
        ${screenshot ? `<a class="secondary-btn mini" href="/${escapeHtml(screenshot)}" target="_blank">Скрин</a>` : ""}
        <button class="secondary-btn mini" data-case-save="${item.id}">${item.saved ? "Убрать" : "Сохранить"}</button>
        <button class="secondary-btn mini" data-case-archive="${item.id}">${item.archived ? "Вернуть" : "Архив"}</button>
      </div>
    </article>`;
}

function bindCaseControls() {
  document.querySelectorAll("[data-case-select]").forEach((box) => {
    box.addEventListener("change", () => {
      const id = Number(box.dataset.caseSelect);
      if (box.checked) state.selectedCases.add(id);
      else state.selectedCases.delete(id);
      updateSelectedCount();
    });
  });
  document.querySelectorAll("[data-case-status]").forEach((select) => {
    select.addEventListener("change", () => updateCase(Number(select.dataset.caseStatus), { status: select.value }));
  });
  document.querySelectorAll("[data-case-save]").forEach((button) => {
    button.addEventListener("click", () => {
      const id = Number(button.dataset.caseSave);
      const current = state.cases.find((item) => item.id === id);
      updateCase(id, { saved: !current?.saved });
    });
  });
  document.querySelectorAll("[data-case-archive]").forEach((button) => {
    button.addEventListener("click", () => {
      const id = Number(button.dataset.caseArchive);
      const current = state.cases.find((item) => item.id === id);
      updateCase(id, { archived: !current?.archived });
    });
  });
  document.querySelectorAll("[data-case-open]").forEach((button) => {
    button.addEventListener("click", () => openCase(Number(button.dataset.caseOpen)));
  });
}

async function updateCase(caseId, patch) {
  await api(`/api/cases/${caseId}`, { method: "PATCH", body: JSON.stringify(patch) });
  await loadCases();
}

async function openCase(caseId) {
  els.drawerOverlay.hidden = false;
  els.caseDetailContent.innerHTML = '<div class="empty-state">Загружаю доказательства...</div>';
  const data = await api(`/api/cases/${caseId}`);
  renderCaseDetail(data.case, data.findings || []);
}

function renderCaseDetail(item, findings) {
  els.drawerTitle.textContent = item.domain;
  const reasons = (item.reasons || []).slice(0, 6);
  els.caseDetailContent.innerHTML = `
    <div class="detail-summary">
      <div class="risk-pill ${riskClass(item.best_risk_score)}">${item.best_risk_score}/100</div>
      <div><span>Статус</span><strong>${escapeHtml(caseStatusLabel(item.status))}</strong></div>
      <div><span>Запусков</span><strong>${item.run_total || 0}</strong></div>
      <div><span>Находок</span><strong>${item.finding_total || findings.length}</strong></div>
    </div>
    <div class="detail-actions">
      <a class="primary-btn" href="${escapeHtml(item.final_url || item.url || "#")}" target="_blank">Открыть сайт</a>
      ${item.html_path ? `<a class="secondary-btn" href="/${escapeHtml(relPath(item.html_path))}" target="_blank">HTML</a>` : ""}
      ${item.screenshot_path ? `<a class="secondary-btn" href="/${escapeHtml(relPath(item.screenshot_path))}" target="_blank">Скриншот</a>` : ""}
    </div>
    ${reasons.length ? `<div class="detail-block"><h4>Вердикт</h4><ul>${reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}</ul></div>` : ""}
    <div class="detail-block"><h4>История фиксаций</h4>${findings.map(findingTimelineItem).join("") || '<div class="empty-state">История пуста.</div>'}</div>
  `;
}

function findingTimelineItem(finding) {
  const screenshot = relPath(finding.screenshot_path);
  const html = relPath(finding.html_path);
  const sourceUrl = finding.sources?.[0]?.url;
  return `
    <article class="timeline-item">
      <div class="timeline-top">
        <strong>Запуск #${finding.run_id}</strong>
        <span>${escapeHtml(formatDate(finding.created_at))}</span>
        <span class="risk-pill ${riskClass(finding.risk_score)}">${finding.risk_score}/100</span>
      </div>
      <p>${escapeHtml((finding.reasons || [])[0] || verdictLabel(finding.verdict))}</p>
      <div class="inline-actions">
        <a href="${escapeHtml(finding.final_url || finding.url)}" target="_blank">Сайт</a>
        ${screenshot ? `<a href="/${escapeHtml(screenshot)}" target="_blank">Скриншот</a>` : ""}
        ${html ? `<a href="/${escapeHtml(html)}" target="_blank">HTML</a>` : ""}
        ${sourceUrl ? `<a href="${escapeHtml(sourceUrl)}" target="_blank">Источник</a>` : ""}
      </div>
      ${finding.html_sha256 ? `<small>SHA-256: ${escapeHtml(finding.html_sha256)}</small>` : ""}
    </article>`;
}

function closeDrawer() {
  els.drawerOverlay.hidden = true;
}

function exportSelected(kind) {
  const ids = selectedCaseQuery();
  if (!ids) {
    alert("Выберите хотя бы одно дело в реестре.");
    return;
  }
  window.location.href = `/api/cases/export.${kind}?ids=${encodeURIComponent(ids)}`;
}

function startPolling() {
  stopPolling();
  state.pollTimer = setInterval(() => {
    if (state.selectedRunId) loadRun(state.selectedRunId, { refreshRegistry: false }).catch(console.error);
  }, 4000);
}

function stopPolling() {
  if (state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
}

els.runBtn.addEventListener("click", startRun);
els.stopBtn.addEventListener("click", stopRun);
els.refreshBtn.addEventListener("click", async () => {
  await loadRuns();
  if (state.selectedRunId) await loadRun(state.selectedRunId, { refreshRegistry: false });
  await loadCases();
});
els.caseFilterBtn.addEventListener("click", loadCases);
els.caseSearch.addEventListener("keydown", (event) => { if (event.key === "Enter") loadCases(); });
els.selectedCsvBtn.addEventListener("click", () => exportSelected("csv"));
els.selectedXlsxBtn.addEventListener("click", () => exportSelected("xlsx"));
els.drawerClose.addEventListener("click", closeDrawer);
els.drawerOverlay.addEventListener("click", (event) => { if (event.target === els.drawerOverlay) closeDrawer(); });
els.aiActivityJump.addEventListener("click", () => {
  document.getElementById("runSection")?.scrollIntoView({ behavior: "smooth", block: "start" });
});
document.addEventListener("keydown", (event) => { if (event.key === "Escape") closeDrawer(); });

loadHealth();
loadRuns()
  .then(() => (state.selectedRunId ? loadRun(state.selectedRunId, { refreshRegistry: false }) : null))
  .then(loadCases)
  .catch(console.error);
