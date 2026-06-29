const state = {
  selectedRunId: null,
  pollTimer: null,
  selectedCases: new Set(),
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

function statusLabel(status) {
  return statusLabels[status] || status || "-";
}

function riskClass(score) {
  if (score >= 80) return "high";
  if (score >= 55) return "mid";
  return "low";
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

function formatMeta(meta) {
  if (!meta || !Object.keys(meta).length) return "";
  const parts = [];
  if (meta.domain) parts.push(`домен: ${meta.domain}`);
  if (meta.url) parts.push(`url: ${meta.url}`);
  if (meta.reason) parts.push(`причина: ${meta.reason}`);
  if (meta.count !== undefined) parts.push(`кол-во: ${meta.count}`);
  if (meta.findings !== undefined) parts.push(`в отчете: ${meta.findings}`);
  if (meta.risk_score !== undefined) parts.push(`риск: ${meta.risk_score}`);
  if (meta.status_code !== undefined && meta.status_code !== null) parts.push(`ответ сайта: ${meta.status_code}`);
  if (meta.error) parts.push(`ошибка: ${meta.error}`);
  return parts.length ? ` · ${parts.join(" · ")}` : "";
}

function selectedCaseQuery() {
  return Array.from(state.selectedCases).join(",");
}

async function loadHealth() {
  try {
    const health = await api("/api/health");
    els.statusPill.textContent = health.gemini_configured ? "готово" : "нет ключа";
    els.statusPill.className = `status-pill ${health.gemini_configured ? "ok" : "warn"}`;
    els.healthLine.textContent = health.gemini_configured
      ? `Gemini подключен: ${health.gemini_keys.length} ключ(а), лимит ${health.rpm_limit}/мин и ${health.rpd_limit}/день на ключ.`
      : "Добавьте GEMINI_API_KEYS в .env, чтобы работал поиск в интернете.";
  } catch (error) {
    els.statusPill.textContent = "ошибка";
    els.statusPill.className = "status-pill warn";
    els.healthLine.textContent = error.message;
  }
}

async function startRun() {
  els.runBtn.disabled = true;
  els.runBtn.textContent = "Запускаю...";
  try {
    const payload = {
      seed_query: els.seedQuery.value.trim() || null,
      max_candidates: Number(els.maxCandidates.value || 8),
      take_screenshots: els.takeScreenshots.checked,
    };
    const result = await api("/api/runs", { method: "POST", body: JSON.stringify(payload) });
    state.selectedRunId = result.run_id;
    await loadRuns();
    await loadRun(result.run_id);
    startPolling();
  } catch (error) {
    alert(`Не удалось запустить проверку: ${error.message}`);
  } finally {
    els.runBtn.disabled = false;
    els.runBtn.textContent = "Начать проверку";
  }
}

async function stopRun() {
  if (!state.selectedRunId) return;
  els.stopBtn.disabled = true;
  await api(`/api/runs/${state.selectedRunId}/cancel`, { method: "POST" });
  await loadRun(state.selectedRunId);
}

async function loadRuns() {
  const data = await api("/api/runs?limit=50");
  if (!data.runs.length) {
    els.runsList.innerHTML = '<div class="empty">Проверок пока нет.</div>';
    return;
  }
  if (!state.selectedRunId) state.selectedRunId = data.runs[0].id;
  els.runsList.innerHTML = data.runs.map((run) => {
    const active = run.id === state.selectedRunId ? "active" : "";
    return `
      <button class="run-item ${active}" data-run-id="${run.id}">
        <div class="run-row"><span>#${run.id}</span><span>${escapeHtml(statusLabel(run.status))}</span></div>
        <div class="run-meta">${escapeHtml(formatDate(run.started_at))} · ${run.finding_count || 0} в отчете</div>
      </button>`;
  }).join("");
  document.querySelectorAll(".run-item").forEach((button) => {
    button.addEventListener("click", () => {
      state.selectedRunId = Number(button.dataset.runId);
      loadRun(state.selectedRunId);
    });
  });
}

async function loadRun(runId) {
  if (!runId) return;
  const data = await api(`/api/runs/${runId}`);
  const run = data.run;
  state.selectedRunId = run.id;
  els.currentRun.textContent = `#${run.id}`;
  els.runStatus.textContent = statusLabel(run.status);
  els.candidateCount.textContent = run.candidate_count || 0;
  els.findingCount.textContent = run.finding_count || 0;
  els.csvLink.href = `/api/runs/${run.id}/export.csv`;
  els.xlsxLink.href = `/api/runs/${run.id}/export.xlsx`;
  els.csvLink.classList.remove("link-disabled");
  els.xlsxLink.classList.remove("link-disabled");
  els.stopBtn.disabled = !["queued", "running", "canceling"].includes(run.status);
  renderFindings(data.findings || []);
  renderLogs(data.logs || []);
  await loadRuns();
  await loadCases();

  if (["queued", "running", "canceling"].includes(run.status)) startPolling();
  else stopPolling();
}

function renderFindings(findings) {
  if (!findings.length) {
    els.findingsList.innerHTML = '<div class="empty">Пока нет сайтов, которые удалось открыть и зафиксировать. Подробности смотрите в журнале работы.</div>';
    return;
  }
  els.findingsList.innerHTML = findings.map(findingCard).join("");
}

function findingCard(finding) {
  const screenshot = relPath(finding.screenshot_path);
  const html = relPath(finding.html_path);
  const reasons = (finding.reasons || []).slice(0, 5);
  const sourceUrl = finding.sources?.[0]?.url;
  const evidence = finding.evidence || {};
  const screenshotLink = screenshot ? `<a href="/${escapeHtml(screenshot)}" target="_blank">Скриншот</a>` : "";
  const htmlLink = html ? `<a href="/${escapeHtml(html)}" target="_blank">HTML</a>` : "";
  const sourceLink = sourceUrl ? `<a href="${escapeHtml(sourceUrl)}" target="_blank">Источник</a>` : "";
  const openLink = `<a href="${escapeHtml(finding.final_url || finding.url)}" target="_blank">Открыть сайт</a>`;
  return `
    <article class="finding-card">
      <div class="finding-top">
        <div><div class="finding-domain">${escapeHtml(finding.domain)}</div>${finding.title ? `<div class="finding-title">${escapeHtml(finding.title)}</div>` : ""}</div>
        <div class="risk ${riskClass(finding.risk_score)}">${finding.risk_score}/100</div>
      </div>
      <div class="finding-grid">
        <div class="info-box"><span class="info-label">Оценка</span>${escapeHtml(verdictLabels[finding.verdict] || finding.verdict)}</div>
        <div class="info-box"><span class="info-label">Тип</span>${escapeHtml(finding.category || "подозрительный")}</div>
        <div class="info-box"><span class="info-label">Зеркала</span>${escapeHtml(finding.mirror_group || "не найдены")}</div>
      </div>
      ${reasons.length ? `<ul class="reason-list">${reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}</ul>` : ""}
      ${evidence.search_query ? `<div class="muted">Найдено по запросу: ${escapeHtml(evidence.search_query)}</div>` : ""}
      <div class="evidence-links">${openLink}${screenshotLink}${htmlLink}${sourceLink}</div>
    </article>`;
}

function renderLogs(logs) {
  const warnings = logs.filter((log) => ["warning", "error"].includes(log.level)).length;
  els.warningCount.textContent = `${warnings} ошибок/пропусков`;
  if (!logs.length) {
    els.logsList.innerHTML = '<div class="empty">Журнал появится после запуска проверки.</div>';
    return;
  }
  els.logsList.innerHTML = logs.map((log) => {
    const cls = log.level === "error" ? "error" : log.level === "warning" ? "warning" : "";
    return `<div class="log-line ${cls}"><span>${escapeHtml(formatDate(log.timestamp))}</span><span class="log-level">${escapeHtml(log.level)}</span><span>${escapeHtml(log.message)}${escapeHtml(formatMeta(log.meta))}</span></div>`;
  }).join("");
  els.logsList.scrollTop = els.logsList.scrollHeight;
}

async function loadCases() {
  const params = new URLSearchParams();
  if (els.caseSearch.value.trim()) params.set("q", els.caseSearch.value.trim());
  if (els.caseStatusFilter.value) params.set("status", els.caseStatusFilter.value);
  if (els.caseArchiveFilter.value !== "") params.set("archived", els.caseArchiveFilter.value);
  if (els.caseSavedFilter.value !== "") params.set("saved", els.caseSavedFilter.value);
  if (els.caseMinRisk.value) params.set("min_risk", els.caseMinRisk.value);
  const data = await api(`/api/cases?${params.toString()}`);
  renderCases(data.cases || []);
}

function renderCases(cases) {
  if (!cases.length) {
    els.casesList.innerHTML = '<div class="empty">В этом фильтре пока ничего нет.</div>';
    return;
  }
  els.casesList.innerHTML = cases.map((item) => {
    const checked = state.selectedCases.has(item.id) ? "checked" : "";
    const archivedClass = item.archived ? "archived" : "";
    const screenshot = relPath(item.screenshot_path);
    const html = relPath(item.html_path);
    const openUrl = item.final_url || item.url || "#";
    return `
      <article class="case-card ${archivedClass}" data-case-id="${item.id}">
        <div class="case-top">
          <input class="case-select" type="checkbox" data-case-select="${item.id}" ${checked}>
          <div>
            <div class="case-domain">${escapeHtml(item.domain)}</div>
            ${item.title ? `<div class="case-title">${escapeHtml(item.title)}</div>` : ""}
          </div>
          <div class="risk ${riskClass(item.best_risk_score)}">${item.best_risk_score}/100</div>
          <select class="case-status-select" data-case-status="${item.id}">
            ${Object.entries(caseStatusLabels).map(([value, label]) => `<option value="${value}" ${item.status === value ? "selected" : ""}>${label}</option>`).join("")}
          </select>
          <span>${item.saved ? '<span class="saved-badge">сохранено</span>' : 'не сохранено'}</span>
          <span>${item.archived ? 'архив' : 'активно'}</span>
        </div>
        <div class="case-actions">
          <a href="${escapeHtml(openUrl)}" target="_blank">Открыть</a>
          ${screenshot ? `<a href="/${escapeHtml(screenshot)}" target="_blank">Скриншот</a>` : ""}
          ${html ? `<a href="/${escapeHtml(html)}" target="_blank">HTML</a>` : ""}
          <button data-case-save="${item.id}">${item.saved ? "Убрать из сохраненных" : "Сохранить"}</button>
          <button data-case-archive="${item.id}">${item.archived ? "Вернуть из архива" : "В архив"}</button>
        </div>
      </article>`;
  }).join("");

  document.querySelectorAll("[data-case-select]").forEach((box) => {
    box.addEventListener("change", () => {
      const id = Number(box.dataset.caseSelect);
      if (box.checked) state.selectedCases.add(id);
      else state.selectedCases.delete(id);
    });
  });
  document.querySelectorAll("[data-case-status]").forEach((select) => {
    select.addEventListener("change", () => updateCase(Number(select.dataset.caseStatus), { status: select.value }));
  });
  document.querySelectorAll("[data-case-save]").forEach((button) => {
    button.addEventListener("click", () => {
      const card = button.closest(".case-card");
      const saved = !button.textContent.includes("Убрать");
      updateCase(Number(button.dataset.caseSave), { saved });
    });
  });
  document.querySelectorAll("[data-case-archive]").forEach((button) => {
    button.addEventListener("click", () => {
      const archived = button.textContent.includes("В архив");
      updateCase(Number(button.dataset.caseArchive), { archived });
    });
  });
}

async function updateCase(caseId, patch) {
  await api(`/api/cases/${caseId}`, { method: "PATCH", body: JSON.stringify(patch) });
  await loadCases();
}

function exportSelected(kind) {
  const ids = selectedCaseQuery();
  if (!ids) {
    alert("Выберите хотя бы один домен в общем списке.");
    return;
  }
  window.location.href = `/api/cases/export.${kind}?ids=${encodeURIComponent(ids)}`;
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

els.runBtn.addEventListener("click", startRun);
els.stopBtn.addEventListener("click", stopRun);
els.refreshBtn.addEventListener("click", async () => {
  await loadRuns();
  if (state.selectedRunId) await loadRun(state.selectedRunId);
  await loadCases();
});
els.caseFilterBtn.addEventListener("click", loadCases);
els.caseSearch.addEventListener("keydown", (event) => { if (event.key === "Enter") loadCases(); });
els.selectedCsvBtn.addEventListener("click", () => exportSelected("csv"));
els.selectedXlsxBtn.addEventListener("click", () => exportSelected("xlsx"));

loadHealth();
loadRuns()
  .then(() => {
    if (state.selectedRunId) return loadRun(state.selectedRunId);
    return null;
  })
  .then(loadCases)
  .catch(console.error);
