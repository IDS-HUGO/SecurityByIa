/**
 * Security Control Center - Frontend Application
 * DevSecOps Platform & Accuracy Benchmark Engine
 */

const state = {
  activeTab: 'overview',
  findings: [],
  report: '',
  result: null,
  scanTimer: null,
  analysisId: null,
  benchTimer: null,
  benchmarkData: null,
};

const $ = (id) => document.getElementById(id);
const text = (value, fallback = '') => (value === undefined || value === null ? fallback : String(value));

// Format point deltas (e.g., +4.5 pts or -2.1 pts)
function formatDelta(pts, invert = false, hasPrevious = true) {
  if (!hasPrevious) {
    return { text: '— sin corrida previa', cls: 'neutral' };
  }
  const num = Number(pts) || 0;
  if (Math.abs(num) < 0.05) {
    return { text: '— 0.0 pts', cls: 'neutral' };
  }
  const isPositive = num > 0;
  // If invert is true (e.g., for FPR, lower is better), positive is bad and negative is good
  const isGood = invert ? !isPositive : isPositive;
  const sign = isPositive ? '+' : '';
  const arrow = isPositive ? '▲' : '▼';
  return {
    text: `${arrow} ${sign}${num.toFixed(1)} pts`,
    cls: isGood ? 'positive' : 'negative',
  };
}

// -----------------------------------------------------------------------------
// TAB NAVIGATION
// -----------------------------------------------------------------------------
function setupTabs() {
  const navItems = document.querySelectorAll('.nav-item');
  navItems.forEach((item) => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      const tabName = item.getAttribute('data-tab');
      switchTab(tabName);
    });
  });

  // Handle URL hash on load
  const hash = window.location.hash.replace('#', '');
  if (['overview', 'findings', 'benchmark', 'report'].includes(hash)) {
    switchTab(hash);
  }
}

function switchTab(tabName) {
  state.activeTab = tabName;
  window.location.hash = tabName;

  document.querySelectorAll('.nav-item').forEach((item) => {
    item.classList.toggle('active', item.getAttribute('data-tab') === tabName);
  });

  document.querySelectorAll('.tab-pane').forEach((pane) => {
    pane.classList.toggle('active', pane.id === `tab-${tabName}`);
  });

  const titles = {
    overview: 'Dashboard & Análisis SAST',
    findings: 'Hallazgos de Seguridad & Remediaciones',
    benchmark: 'Accuracy Benchmark Engine & Regresión SAST',
    report: 'Reporte Técnico & Entregable de Auditoría',
  };
  if ($('page-title')) {
    $('page-title').textContent = titles[tabName] || 'Security Control Center';
  }

  if (tabName === 'benchmark') {
    loadBenchmark();
  }
}

// -----------------------------------------------------------------------------
// REPO ANALYSIS (SAST SCAN ENGINE)
// -----------------------------------------------------------------------------
const normalizeStatus = (value) => {
  const status = text(value, 'queued').toLowerCase();
  if (status === 'processing' || status === 'in_progress') return 'running';
  if (status === 'error') return 'failed';
  return ['queued', 'running', 'completed', 'failed'].includes(status) ? status : 'queued';
};

const normalizeFinding = (item) => ({
  ...item,
  severity: text(item.severity, 'low').toLowerCase(),
  severity_reason: text(item.severity_reason, 'Evaluado según exposición y controles de seguridad.'),
  remediation_deadline: text(item.remediation_deadline, '180 días'),
  tools: Array.isArray(item.tools) && item.tools.length ? item.tools : ['semgrep'],
  package: item.package || (item.extra && item.extra.package) || null,
  file: text(item.file || item.archivo, 'Unknown file'),
  title: text(item.title || item.problema || item.rule || item.regla, 'Security finding'),
  rule: text(item.rule || item.regla, '—'),
  problem: text(item.problem || item.problema),
  solution: text(item.solution || item.solucion),
  owasp: text(item.owasp || item.owasp_category || item.categoria_owasp, 'Uncategorized'),
  cwe: Array.isArray(item.cwe) ? item.cwe.join(', ') : text(item.cwe || item.cwe_id, 'Unspecified'),
  status: text(item.status, 'open').toLowerCase(),
});

function setScanProgress(data = {}) {
  // Mientras el trabajo está en cola (aún no arrancó el clon) el estado es "queued".
  const status = data.stage === 'queued' ? 'queued' : normalizeStatus(data.status);
  const progress = data.progress === undefined && status === 'completed' ? 100 : Number(data.progress) || 0;
  $('progress-panel').classList.remove('hidden');
  $('progress-bar').style.width = `${progress}%`;
  $('progress-value').textContent = `${progress}%`;
  $('progress-message').textContent = text(data.message, status === 'failed' ? 'Análisis falló' : 'Procesando');
  $('progress-stage').textContent = status === 'queued' ? 'En cola' : text(data.stage, status);

  const badge = $('progress-status');
  badge.textContent = status;
  badge.className = `status status-${status}`;

  const rawError = text(data.error_message || data.error);
  const technicalError = $('technical-error');
  technicalError.textContent = rawError;
  technicalError.classList.toggle('hidden', !rawError);
  renderActionableError(rawError);
}

// Traduce las fallas técnicas del backend a un mensaje accionable por causa.
function actionableErrorMessage(raw) {
  const msg = String(raw || '').toLowerCase();
  if (!msg) return null;
  if (msg.includes('only https') || msg.includes('repository url is required') ||
      (msg.includes('url') && msg.includes('valid'))) {
    return {
      title: 'La URL del repositorio no es válida.',
      action: 'Usá una URL pública con formato https://github.com/organizacion/repositorio. No se aceptan http://, rutas locales (file://) ni SSH.',
    };
  }
  if (msg.includes('could not be cloned') || msg.includes('not found') ||
      msg.includes('authentication failed') || msg.includes('could not read username')) {
    return {
      title: 'El repositorio es privado o no existe.',
      action: 'Verificá que la URL sea exacta y que el repositorio sea público: si al abrirla en una ventana de incógnito pide login, la plataforma no puede clonarlo sin credenciales.',
    };
  }
  if (msg.includes('exceeds the maximum allowed size')) {
    return {
      title: 'El repositorio supera el límite de tamaño permitido.',
      action: 'Analizá un repositorio más chico, o ampliá el límite con la variable SECURITY_MAX_REPO_MB en el servidor.',
    };
  }
  if (msg.includes('timed out') || msg.includes('time budget')) {
    return {
      title: 'El análisis agotó el tiempo disponible.',
      action: 'Reintentá con un repositorio más chico, o aumentá los límites con SECURITY_CLONE_TIMEOUT y SECURITY_TOTAL_TIMEOUT en el servidor.',
    };
  }
  if (msg.includes('not installed') || msg.includes('not available on path')) {
    return {
      title: 'Falta una herramienta de análisis en el servidor.',
      action: 'Instalá la herramienta mencionada en el detalle técnico (Semgrep: pip install semgrep; Gitleaks: binario en PATH o variable GITLEAKS_PATH) y volvé a ejecutar el análisis.',
    };
  }
  return {
    title: 'El análisis falló.',
    action: 'Revisá el detalle técnico, verificá que el repositorio sea público y accesible, y reintentá.',
  };
}

function renderActionableError(rawError) {
  const banner = $('actionable-error');
  if (!banner) return;
  const guidance = actionableErrorMessage(rawError);
  if (!guidance) {
    banner.textContent = '';
    banner.classList.add('hidden');
    return;
  }
  banner.replaceChildren();
  const strong = document.createElement('strong');
  strong.textContent = guidance.title;
  const detail = document.createElement('span');
  detail.textContent = ` ${guidance.action}`;
  banner.append(strong, detail);
  banner.classList.remove('hidden');
}

function renderSummary(summary = {}) {
  ['total', 'critical', 'high', 'medium', 'low'].forEach((key) => {
    const el = $(`${key}-count`);
    if (el) el.textContent = text(summary[key], '0');
  });

  const total = Number(summary.total) || 0;
  const navBadge = $('nav-findings-badge');
  if (navBadge) {
    navBadge.textContent = total;
    navBadge.classList.toggle('hidden', total === 0);
  }
}

function fillFilter(id, values, label) {
  const select = $(id);
  if (!select) return;
  const current = select.value;
  select.replaceChildren(new Option(label, ''));
  [...new Set(values.filter(Boolean))].sort().forEach((value) => {
    select.appendChild(new Option(value, value));
  });
  select.value = values.includes(current) ? current : '';
}

function renderSummaryBar() {
  const bar = $('findings-summary-bar');
  if (!bar) return;
  if (!state.findings.length) {
    bar.classList.add('hidden');
    return;
  }
  bar.classList.remove('hidden');
  bar.replaceChildren();

  // 1. Group: Por Severidad
  const sevGroup = document.createElement('div');
  sevGroup.className = 'summary-bar-group';
  const sevLabel = document.createElement('span');
  sevLabel.className = 'summary-bar-label';
  sevLabel.textContent = 'Por Severidad:';
  sevGroup.appendChild(sevLabel);

  const curSev = $('severity-filter') ? $('severity-filter').value : '';
  const severities = ['critical', 'high', 'medium', 'low'];
  const sevNames = { critical: 'Crítico', high: 'Alto', medium: 'Medio', low: 'Bajo' };

  const allSevPill = document.createElement('span');
  allSevPill.className = `summary-pill ${!curSev ? 'active' : ''}`;
  allSevPill.innerHTML = `Todas <span class="summary-pill-count">${state.findings.length}</span>`;
  allSevPill.addEventListener('click', () => {
    if ($('severity-filter')) $('severity-filter').value = '';
    renderFindings();
  });
  sevGroup.appendChild(allSevPill);

  severities.forEach((sev) => {
    const count = state.findings.filter((f) => f.severity === sev).length;
    const pill = document.createElement('span');
    pill.className = `summary-pill ${curSev === sev ? 'active' : ''}`;
    pill.innerHTML = `<span class="badge badge-${sev}" style="padding: 1px 6px; font-size: 11px;">${sevNames[sev]}</span> <span class="summary-pill-count">${count}</span>`;
    pill.addEventListener('click', () => {
      if ($('severity-filter')) {
        $('severity-filter').value = $('severity-filter').value === sev ? '' : sev;
      }
      renderFindings();
    });
    sevGroup.appendChild(pill);
  });

  // 2. Group: Por Categoría OWASP
  const owaspGroup = document.createElement('div');
  owaspGroup.className = 'summary-bar-group';
  const owaspLabel = document.createElement('span');
  owaspLabel.className = 'summary-bar-label';
  owaspLabel.textContent = 'Por OWASP:';
  owaspGroup.appendChild(owaspLabel);

  const curOwasp = $('owasp-filter') ? $('owasp-filter').value : '';
  const owaspCounts = {};
  state.findings.forEach((f) => {
    if (f.owasp) {
      owaspCounts[f.owasp] = (owaspCounts[f.owasp] || 0) + 1;
    }
  });

  Object.entries(owaspCounts).sort().forEach(([cat, count]) => {
    const shortCat = cat.split(' - ')[0] || cat;
    const pill = document.createElement('span');
    pill.className = `summary-pill ${curOwasp === cat ? 'active' : ''}`;
    pill.title = cat;
    pill.innerHTML = `<span>${escapeHtml(shortCat)}</span> <span class="summary-pill-count">${count}</span>`;
    pill.addEventListener('click', () => {
      if ($('owasp-filter')) {
        $('owasp-filter').value = $('owasp-filter').value === cat ? '' : cat;
      }
      renderFindings();
    });
    owaspGroup.appendChild(pill);
  });

  bar.append(sevGroup, owaspGroup);
}

function renderFindings() {
  fillFilter('owasp-filter', state.findings.map((item) => item.owasp), 'Todas las categorías OWASP');
  fillFilter('cwe-filter', state.findings.map((item) => item.cwe), 'Todos los CWE');

  // Fill tool filter dynamically
  const allTools = [];
  state.findings.forEach((f) => (f.tools || []).forEach((t) => allTools.push(t)));
  fillFilter('tool-filter', allTools, 'Todas las herramientas');

  const severity = $('severity-filter') ? $('severity-filter').value : '';
  const owasp = $('owasp-filter') ? $('owasp-filter').value : '';
  const cwe = $('cwe-filter') ? $('cwe-filter').value : '';
  const tool = $('tool-filter') ? $('tool-filter').value : '';
  const type = $('type-filter') ? $('type-filter').value : '';
  const status = $('status-filter') ? $('status-filter').value : '';
  const file = $('file-filter') ? $('file-filter').value.toLowerCase() : '';

  const isDependency = (f) => {
    if (f.package) return true;
    const depTools = ['osv-scanner', 'pip-audit', 'npm-audit', 'dependabot', 'deptry', 'depcheck'];
    return (f.tools || []).some((t) => depTools.includes(t)) || (f.cwe && (f.cwe.includes('1104') || f.cwe.includes('937')));
  };

  const isSecret = (f) => {
    const secTools = ['gitleaks', 'trufflehog'];
    return (f.tools || []).some((t) => secTools.includes(t)) ||
      (f.rule && f.rule.toLowerCase().includes('secret')) ||
      (f.cwe && (f.cwe.includes('798') || f.cwe.includes('259')));
  };

  const matchesType = (f, t) => {
    if (!t) return true;
    if (t === 'dependency') return isDependency(f);
    if (t === 'secret') return isSecret(f);
    if (t === 'code') return !isDependency(f) && !isSecret(f);
    return true;
  };

  const visible = state.findings.filter((item) => {
    return (
      (!severity || item.severity === severity) &&
      (!owasp || item.owasp === owasp) &&
      (!cwe || item.cwe === cwe) &&
      (!tool || (item.tools || []).includes(tool)) &&
      matchesType(item, type) &&
      (!status || item.status === status) &&
      (!file || item.file.toLowerCase().includes(file))
    );
  });

  renderSummaryBar();

  const body = $('findings-body');
  body.replaceChildren();

  if (!visible.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 6;
    cell.className = 'empty-row';
    cell.innerHTML = `
      <div class="empty-state-compact">
        <p>No hay hallazgos que coincidan con los filtros seleccionados.</p>
      </div>`;
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }

  visible.forEach((item) => {
    const row = document.createElement('tr');
    row.addEventListener('click', () => showDetail(item));

    const tdSeverity = document.createElement('td');
    const sevLabel = { critical: 'CRÍTICO', high: 'ALTO', medium: 'MEDIO', low: 'BAJO' }[item.severity] || item.severity.toUpperCase();
    tdSeverity.innerHTML = `<span class="badge badge-${item.severity}">${escapeHtml(sevLabel)}</span>`;

    const tdFinding = document.createElement('td');
    tdFinding.innerHTML = `
      <span class="finding-title">${escapeHtml(item.title)}</span>
      <span class="finding-sub">Regla: ${escapeHtml(item.rule)}</span>`;

    const tdOwasp = document.createElement('td');
    tdOwasp.innerHTML = `
      <div style="font-size: 12px; font-weight: 600;">${escapeHtml(item.owasp)}</div>
      <div class="cwe-badge">${escapeHtml(item.cwe)}</div>`;

    const tdLoc = document.createElement('td');
    tdLoc.innerHTML = `<code style="font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary);">${escapeHtml(item.file)}:${text(item.line, '?')}</code>`;

    const tdTools = document.createElement('td');
    tdTools.className = 'td-tools';
    const tools = Array.isArray(item.tools) && item.tools.length ? item.tools : ['semgrep'];
    tdTools.innerHTML = tools.map((t) => {
      const cls = t.toLowerCase().replace(/[^a-z0-9_-]/g, '');
      return `<span class="tool-tag ${cls}">${escapeHtml(t)}</span>`;
    }).join(' ');

    const tdStatus = document.createElement('td');
    tdStatus.innerHTML = `<span class="status status-${item.status}">${item.status}</span>`;

    row.append(tdSeverity, tdFinding, tdOwasp, tdLoc, tdTools, tdStatus);
    body.appendChild(row);
  });
}

function showDetail(item) {
  const panel = $('finding-detail');
  panel.replaceChildren();

  const title = document.createElement('h3');
  title.textContent = item.title;

  const meta = document.createElement('div');
  meta.className = 'finding-detail-meta';
  meta.textContent = `${item.file}:${text(item.line, '?')} · ${item.owasp} · ${item.cwe} · Severidad: ${item.severity.toUpperCase()}`;

  // Severity reason & SLA remediation deadline (F4)
  const reasonBox = document.createElement('div');
  reasonBox.className = 'detail-reason-box';
  reasonBox.innerHTML = `
    <div style="margin-bottom: 6px;">
      <strong style="color: var(--text-main);">Motivo de severidad:</strong>
      <span style="color: var(--text-secondary);">${escapeHtml(item.severity_reason || 'Calculada según exposición y controles de seguridad.')}</span>
    </div>
    <div>
      <strong style="color: var(--text-main);">Plazo de remediación (Control 6):</strong>
      <span class="badge badge-${item.severity}" style="margin-left: 6px; padding: 2px 8px; font-size: 11px;">${escapeHtml(item.remediation_deadline || 'No especificado')}</span>
    </div>
  `;

  // Dependency details (F3: paquete, versión instalada, versión corregida)
  let depBox = null;
  const pkg = item.package || (item.extra && item.extra.package);
  if (pkg && typeof pkg === 'object') {
    depBox = document.createElement('div');
    depBox.className = 'detail-dep-box';
    depBox.innerHTML = `
      <h4 style="margin: 0 0 8px 0; font-size: 13px; color: var(--cyan); text-transform: uppercase; letter-spacing: 0.05em;">Detalle de Dependencia (SCA)</h4>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; font-size: 12px;">
        <div><strong>Paquete:</strong> <code>${escapeHtml(pkg.name || 'Desconocido')}</code></div>
        <div><strong>Versión instalada:</strong> <code style="color: var(--orange);">${escapeHtml(pkg.version || 'No reportada')}</code></div>
        <div><strong>Versión corregida:</strong> <code style="color: var(--emerald);">${escapeHtml(pkg.fixed_version || 'No reportada')}</code></div>
        ${pkg.ecosystem ? `<div><strong>Ecosistema:</strong> <span>${escapeHtml(pkg.ecosystem)}</span></div>` : ''}
      </div>
    `;
  }

  const problem = document.createElement('p');
  problem.innerHTML = `<strong>Problema detectado:</strong> ${escapeHtml(item.problem)}`;

  const solution = document.createElement('p');
  solution.innerHTML = `<strong>Recomendación técnica:</strong> ${escapeHtml(item.solution)}`;

  panel.append(title, meta, reasonBox);
  if (depBox) panel.appendChild(depBox);
  panel.append(problem, solution);

  if (Array.isArray(item.code_context) && item.code_context.length) {
    const code = document.createElement('pre');
    code.textContent = item.code_context.map((line) => `${String(line.line).padStart(4, ' ')} | ${line.text}`).join('\n');
    panel.appendChild(code);
  }

  panel.classList.remove('hidden');
}

function renderResultMeta(data) {
  const meta = $('result-meta');
  if (!meta) return;
  const repo = (data.repository && typeof data.repository === 'object') ? data.repository : {};
  const sha = text(repo.commit);
  const branch = text(repo.branch);
  $('result-repo').textContent = text(repo.url || repo.name, '—');
  $('result-branch').textContent = branch || '—';
  $('result-sha').textContent = sha || '—';
  meta.classList.toggle('hidden', !sha && !branch);
}

function renderResult(data) {
  state.findings = (data.findings || []).map(normalizeFinding);
  state.report = text(data.markdown_report);
  state.result = data;

  renderSummary(data.summary || { total: state.findings.length });
  renderResultMeta(data);
  renderFindings();

  $('report-content').textContent = state.report || 'No se generó reporte Markdown.';
  $('download-report').disabled = !state.report;
  $('download-json').disabled = false;
}

async function pollAnalysis(id) {
  try {
    const response = await fetch(`/api/analysis/${encodeURIComponent(id)}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || data.error_message || 'No se pudo obtener el análisis.');

    setScanProgress(data);
    const status = normalizeStatus(data.status);

    if (status === 'queued' || status === 'running') {
      state.scanTimer = setTimeout(() => pollAnalysis(id), 1200);
      return;
    }

    if (status === 'failed') {
      $('form-error').textContent = data.error_message || data.error || 'Análisis fallido.';
      $('btn-start-scan').disabled = false;
      return;
    }

    $('btn-start-scan').disabled = false;
    renderResult(data);
    loadHistory();
  } catch (error) {
    setScanProgress({ status: 'failed', error_message: error.message });
    $('form-error').textContent = error.message;
    $('btn-start-scan').disabled = false;
  }
}

function renderHistory(items = []) {
  const list = $('history-list');
  list.replaceChildren();

  if (!items.length) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.innerHTML = '<p class="muted">Aún no se han ejecutado análisis de repositorios.</p>';
    list.appendChild(empty);
    return;
  }

  items.forEach((item) => {
    const row = document.createElement('div');
    row.className = 'history-item';

    const repoUrl = typeof item.repository === 'object' && item.repository !== null ? item.repository.url : item.repository;
    const cleanUrl = text(item.url || repoUrl, 'Repositorio');

    const repo = document.createElement('span');
    repo.className = 'history-repo';
    repo.textContent = cleanUrl;

    const date = document.createElement('span');
    date.className = 'history-meta';
    date.textContent = text(item.created_at || item.timestamp, 'Fecha no disponible');

    const normalized = normalizeStatus(item.status);
    const status = document.createElement('span');
    status.className = `status status-${normalized}`;
    status.textContent = normalized;

    const total = item.total_findings ?? (item.summary && item.summary.total) ?? item.findings_count ?? 0;
    const result = document.createElement('span');
    result.className = 'history-meta';
    result.textContent = `${total} hallazgos`;

    const button = document.createElement('button');
    button.className = 'btn-secondary';
    button.type = 'button';
    button.textContent = 'Re-analizar';
    button.addEventListener('click', () => {
      $('repo-url').value = cleanUrl;
      $('scan-form').requestSubmit();
      switchTab('overview');
    });

    row.append(repo, date, status, result, button);
    list.appendChild(row);
  });
}

async function loadHistory() {
  try {
    const response = await fetch('/api/analyses');
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'No se pudo cargar el historial.');
    renderHistory(Array.isArray(data) ? data : data.analyses || []);
  } catch (error) {
    const list = $('history-list');
    list.replaceChildren();
    const msg = document.createElement('p');
    msg.className = 'empty-state muted';
    msg.textContent = `Historial no disponible: ${error.message}`;
    list.appendChild(msg);
  }
}

// -----------------------------------------------------------------------------
// BENCHMARK HARNESS & EVALUATION ENGINE
// -----------------------------------------------------------------------------

async function loadBenchmark() {
  try {
    const response = await fetch('/api/bench');
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    state.benchmarkData = data;
    renderBenchmark(data);

    // If a run is in progress, poll until completion
    if (data.is_running) {
      clearTimeout(state.benchTimer);
      state.benchTimer = setTimeout(loadBenchmark, 1500);
    }
  } catch (err) {
    console.error('Error loading benchmark:', err);
    showBenchmarkError(err.message);
  }
}

function showBenchmarkError(msg) {
  $('bench-loading-panel').classList.add('hidden');
  $('bench-empty-panel').classList.add('hidden');
  $('bench-results-container').classList.add('hidden');
  $('bench-error-panel').classList.remove('hidden');
  $('bench-error-message').textContent = msg || 'Ocurrió un error al cargar el benchmark.';
  $('btn-run-benchmark').disabled = false;
}

function renderBenchmark(data) {
  const isRunning = Boolean(data.is_running);
  const loadingPanel = $('bench-loading-panel');
  const errorPanel = $('bench-error-panel');
  const emptyPanel = $('bench-empty-panel');
  const resultsContainer = $('bench-results-container');
  const btnRun = $('btn-run-benchmark');

  btnRun.disabled = isRunning;

  // 1. Loading state
  if (isRunning) {
    loadingPanel.classList.remove('hidden');
    errorPanel.classList.add('hidden');
    $('bench-loading-title').textContent = data.message || 'Ejecutando benchmark...';
    $('bench-loading-desc').textContent = `Etapa: ${data.stage || 'procesando'} (${data.progress || 0}%)`;
    $('bench-loading-bar').style.width = `${data.progress || 15}%`;
  } else {
    loadingPanel.classList.add('hidden');
  }

  // 2. Error state
  if (!isRunning && data.status === 'error' && data.error) {
    errorPanel.classList.remove('hidden');
    $('bench-error-message').textContent = data.error;
    emptyPanel.classList.add('hidden');
    resultsContainer.classList.add('hidden');
    return;
  }
  errorPanel.classList.add('hidden');

  const latest = data.latest_run;

  // 3. Empty state
  if (!latest) {
    if (!isRunning) {
      emptyPanel.classList.remove('hidden');
      resultsContainer.classList.add('hidden');
    }
    return;
  }

  // 4. Results populated
  emptyPanel.classList.add('hidden');
  resultsContainer.classList.remove('hidden');

  // Pre-fill feature input if empty
  const featureInput = $('bench-feature-input');
  if (featureInput && !featureInput.value) {
    featureInput.value = latest.feature || '';
  }

  // Meta Bar
  $('bench-run-date').textContent = latest.date_formatted || latest.timestamp;
  $('bench-run-feature').textContent = latest.feature || 'Feature default';
  $('bench-run-id').textContent = latest.run_id;

  const baselineBadge = $('bench-baseline-badge');
  if (latest.is_baseline) {
    baselineBadge.textContent = '★ Baseline Oficial';
    baselineBadge.className = 'badge-baseline active';
  } else {
    baselineBadge.textContent = 'Corrida Comparativa';
    baselineBadge.className = 'badge-baseline';
  }

  // Global KPI Metrics & Deltas
  const summary = latest.summary || {};
  const comparison = latest.comparison || {};
  const baselineDiff = latest.baseline_comparison || {};

  const recallPct = ((summary.avg_recall || 0) * 100).toFixed(1);
  const fprPct = ((summary.avg_fpr || 0) * 100).toFixed(1);
  const f1Val = (summary.avg_f1_score || 0).toFixed(3);

  $('bench-avg-recall').textContent = `${recallPct}%`;
  $('bench-recall-bar').style.width = `${Math.min(100, (summary.avg_recall || 0) * 100)}%`;

  $('bench-avg-fpr').textContent = `${fprPct}%`;
  $('bench-fpr-bar').style.width = `${Math.min(100, (summary.avg_fpr || 0) * 100)}%`;

  $('bench-avg-f1').textContent = f1Val;
  $('bench-f1-bar').style.width = `${Math.min(100, (summary.avg_f1_score || 0) * 100)}%`;

  $('bench-total-tp').textContent = `${summary.true_positives || 0} / ${summary.total_ground_truth || 0}`;
  $('bench-total-gt').textContent = `TP / Esperadas`;
  $('bench-fn-count').textContent = `${summary.false_negatives || 0} Falsos Negativos (omitidos)`;

  // Deltas vs previous run
  applyDeltaBadge('delta-recall-badge', comparison.delta_recall_pts, false, comparison.has_previous);
  applyDeltaBadge('delta-fpr-badge', comparison.delta_fpr_pts, true, comparison.has_previous); // For FPR lower is better!
  applyDeltaBadge('delta-f1-badge', comparison.delta_f1_pts, false, comparison.has_previous);

  // Baseline comparison
  const baseDelta = baselineDiff.delta_recall_pts || 0;
  applyDeltaBadge('bench-baseline-diff-badge', baseDelta, false, baselineDiff.has_previous);
  const baselineObj = data.baseline;
  if (baselineObj && baselineObj.summary) {
    const baseRecall = ((baselineObj.summary.avg_recall || 0) * 100).toFixed(1);
    $('bench-baseline-recall').textContent = `${baseRecall}% base`;
    $('bench-baseline-tag').textContent = `Fijado en: ${baselineObj.date_formatted || 'anterior'}`;
  } else {
    $('bench-baseline-recall').textContent = `${recallPct}%`;
    $('bench-baseline-tag').textContent = 'Esta corrida actúa como baseline';
  }

  // Render Reference Repositories
  renderReferenceRepos(latest.repositories || []);

  // Render CWE Breakdown Table
  renderCweTable(latest.cwe_categories || []);

  // Render Tool Evaluations & Scanner Pairs (F3)
  renderToolEvaluations(latest.tool_evaluations || [], latest.scanner_pairs || []);

  // Render History
  renderBenchHistory(data.history || []);
}

function renderToolEvaluations(toolEvals = [], pairsEvals = []) {
  const toolsBody = $('bench-tools-table-body');
  if (toolsBody) {
    toolsBody.replaceChildren();
    if (!toolEvals.length) {
      toolsBody.innerHTML = `<tr><td colspan="7" class="empty-row text-center muted">No se registraron herramientas individuales en esta corrida.</td></tr>`;
    } else {
      toolEvals.forEach((item) => {
        const row = document.createElement('tr');
        const recPct = ((item.recall || 0) * 100).toFixed(1);
        const precPct = ((item.precision || 0) * 100).toFixed(1);
        const fprPct = ((item.fpr || 0) * 100).toFixed(1);
        const cls = String(item.tool || '').toLowerCase().replace(/[^a-z0-9_-]/g, '');
        row.innerHTML = `
          <td><span class="tool-tag ${cls}">${escapeHtml(item.tool)}</span></td>
          <td><strong style="color: var(--cyan);">${recPct}%</strong></td>
          <td><strong style="color: var(--emerald);">${precPct}%</strong></td>
          <td><span style="color: var(--orange);">${fprPct}%</span></td>
          <td>${item.true_positives} / ${item.total_ground_truth}</td>
          <td>${item.false_positives}</td>
          <td>${item.false_negatives}</td>
        `;
        toolsBody.appendChild(row);
      });
    }
  }

  const pairsBody = $('bench-pairs-table-body');
  if (pairsBody) {
    pairsBody.replaceChildren();
    if (!pairsEvals.length) {
      pairsBody.innerHTML = `<tr><td colspan="7" class="empty-row text-center muted">No se registraron combinaciones de escáneres en esta corrida.</td></tr>`;
    } else {
      pairsEvals.forEach((pair) => {
        const row = document.createElement('tr');
        const recPct = ((pair.recall || 0) * 100).toFixed(1);
        const precPct = ((pair.precision || 0) * 100).toFixed(1);
        const fprPct = ((pair.fpr || 0) * 100).toFixed(1);
        const tags = (pair.tools || []).map((t) => {
          const cls = String(t).toLowerCase().replace(/[^a-z0-9_-]/g, '');
          return `<span class="tool-tag ${cls}">${escapeHtml(t)}</span>`;
        }).join(' <span style="color: var(--text-muted); font-size: 10px;">+</span> ');
        row.innerHTML = `
          <td>${tags}</td>
          <td><strong style="color: var(--cyan);">${recPct}%</strong></td>
          <td><strong style="color: var(--emerald);">${precPct}%</strong></td>
          <td><span style="color: var(--orange);">${fprPct}%</span></td>
          <td>${pair.true_positives} / ${pair.total_ground_truth}</td>
          <td>${pair.false_positives}</td>
          <td>${pair.false_negatives}</td>
        `;
        pairsBody.appendChild(row);
      });
    }
  }

  const tag = $('bench-tools-count-tag');
  if (tag) {
    tag.textContent = `${toolEvals.length} herramientas · ${pairsEvals.length} combinaciones`;
  }
}

function applyDeltaBadge(elementId, pts, invert = false, hasPrevious = true) {
  const el = $(elementId);
  if (!el) return;
  const d = formatDelta(pts, invert, hasPrevious);
  el.textContent = d.text;
  el.className = `delta-badge ${d.cls}`;
}

function renderReferenceRepos(repos) {
  const grid = $('bench-repos-grid');
  grid.replaceChildren();

  $('bench-repos-count-tag').textContent = `${repos.length} repositorios evaluados`;

  repos.forEach((repo) => {
    const card = document.createElement('div');
    card.className = 'repo-card';

    const metrics = repo.metrics || {};
    const comparison = repo.comparison || {};
    const recallPct = ((metrics.recall || 0) * 100).toFixed(1);
    const fprPct = ((metrics.fpr || 0) * 100).toFixed(1);

    const deltaRec = formatDelta(comparison.delta_recall_pts, false, comparison.has_previous);
    const deltaFpr = formatDelta(comparison.delta_fpr_pts, true, comparison.has_previous);

    card.innerHTML = `
      <div class="repo-card-head">
        <div>
          <h3 class="repo-card-title">${escapeHtml(repo.name || repo.id)}</h3>
          <span class="muted" style="font-size: 11px; font-family: var(--font-mono);">${escapeHtml(repo.id)}</span>
        </div>
        <span class="repo-card-type">${escapeHtml(repo.type || 'benchmark')}</span>
      </div>
      <p class="repo-card-desc">${escapeHtml(repo.description || 'Dataset de prueba de seguridad.')}</p>
      <div class="repo-metrics-row">
        <div>
          <span class="metric-col-label">Recall / TPR</span>
          <div class="metric-col-val" style="color: var(--cyan);">${recallPct}%</div>
          <span class="delta-badge ${deltaRec.cls}">${deltaRec.text}</span>
        </div>
        <div>
          <span class="metric-col-label">FPR (Falsos Positivos)</span>
          <div class="metric-col-val" style="color: var(--orange);">${fprPct}%</div>
          <span class="delta-badge ${deltaFpr.cls}">${deltaFpr.text}</span>
        </div>
      </div>
      <div class="repo-breakdown-row">
        <span><strong>TP:</strong> ${metrics.true_positives || 0}</span>
        <span><strong>FP:</strong> ${metrics.false_positives || 0}</span>
        <span><strong>FN:</strong> ${metrics.false_negatives || 0}</span>
        <span><strong>Total GT:</strong> ${metrics.total_ground_truth || 0}</span>
      </div>
    `;

    grid.appendChild(card);
  });
}

function renderCweTable(categories) {
  const body = $('bench-cwe-body');
  body.replaceChildren();

  if (!categories.length) {
    const row = document.createElement('tr');
    row.innerHTML = `<td colspan="8" class="empty-row text-center muted">No se registraron categorías CWE en esta corrida.</td>`;
    body.appendChild(row);
    return;
  }

  categories.forEach((cat) => {
    const row = document.createElement('tr');
    const recallPct = ((cat.recall || 0) * 100).toFixed(1);
    const fprPct = ((cat.fpr || 0) * 100).toFixed(1);
    const deltaRec = formatDelta(cat.delta_recall_pts, false, cat.comparison?.has_previous);

    row.innerHTML = `
      <td>
        <span class="cwe-badge">${escapeHtml(cat.cwe)}</span>
        <span class="cwe-category-pill">${escapeHtml(cat.category || 'Vulnerability')}</span>
      </td>
      <td>
        <strong>${escapeHtml(cat.name || cat.cwe)}</strong>
      </td>
      <td style="text-align: center; font-family: var(--font-mono); font-weight: 700;">
        ${cat.total_gt || 0}
      </td>
      <td style="text-align: center; font-family: var(--font-mono); font-weight: 700; color: var(--cyan);">
        ${cat.detected || 0}
      </td>
      <td style="text-align: center; font-family: var(--font-mono); font-size: 11px;">
        <span style="color: var(--emerald);">${cat.tp || 0}</span> / 
        <span style="color: var(--orange);">${cat.fp || 0}</span> / 
        <span style="color: var(--crimson);">${cat.fn || 0}</span>
      </td>
      <td>
        <div class="mini-bar-cell">
          <span style="font-family: var(--font-mono); font-weight: 700; width: 44px;">${recallPct}%</span>
          <div class="mini-bar-track">
            <div class="mini-bar-fill" style="width: ${Math.min(100, (cat.recall || 0) * 100)}%;"></div>
          </div>
        </div>
      </td>
      <td>
        <span style="font-family: var(--font-mono); font-weight: 600; color: var(--orange);">${fprPct}%</span>
      </td>
      <td style="text-align: right;">
        <span class="delta-badge ${deltaRec.cls}">${deltaRec.text}</span>
      </td>
    `;

    body.appendChild(row);
  });
}

function renderBenchHistory(history) {
  const container = $('bench-history-list');
  container.replaceChildren();

  if (!history.length) {
    container.innerHTML = '<p class="muted" style="padding: 16px 24px;">No hay historial previo de benchmark.</p>';
    return;
  }

  history.forEach((h) => {
    const row = document.createElement('div');
    row.className = 'bench-history-item';

    const sum = h.summary || {};
    const recPct = ((sum.avg_recall || 0) * 100).toFixed(1);
    const fprPct = ((sum.avg_fpr || 0) * 100).toFixed(1);

    const baselineTag = h.is_baseline
      ? '<span class="badge-baseline active" style="font-size: 10px;">Baseline</span>'
      : '<span class="badge-baseline" style="font-size: 10px;">Run</span>';

    row.innerHTML = `
      <span class="muted" style="font-family: var(--font-mono); font-size: 11px;">${escapeHtml(h.date_formatted || h.timestamp)}</span>
      <div>
        <strong style="color: var(--text-main);">${escapeHtml(h.feature || 'Corrida')}</strong>
        <span class="muted" style="font-size: 11px; display: block; font-family: var(--font-mono);">${escapeHtml(h.run_id)}</span>
      </div>
      <div>
        <span class="muted" style="font-size: 11px;">Recall:</span>
        <strong style="color: var(--cyan); font-family: var(--font-mono);">${recPct}%</strong>
      </div>
      <div>
        <span class="muted" style="font-size: 11px;">FPR:</span>
        <strong style="color: var(--orange); font-family: var(--font-mono);">${fprPct}%</strong>
      </div>
      <div>${baselineTag}</div>
    `;

    container.appendChild(row);
  });
}

async function triggerBenchmarkRun() {
  const feature = ($('bench-feature-input').value || '').trim();
  const saveAsBaseline = $('bench-save-baseline').checked;
  const btnRun = $('btn-run-benchmark');

  btnRun.disabled = true;
  $('bench-error-panel').classList.add('hidden');
  $('bench-loading-panel').classList.remove('hidden');
  $('bench-loading-title').textContent = 'Iniciando suite de benchmark...';
  $('bench-loading-desc').textContent = 'Preparando ejecución con repositorios de referencia...';
  $('bench-loading-bar').style.width = '10%';

  try {
    const res = await fetch('/api/bench/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        feature: feature || undefined,
        save_as_baseline: saveAsBaseline,
      }),
    });

    const data = await res.json();

    if (res.status === 409) {
      alert('Ya hay una corrida de benchmark en ejecución en el servidor.');
      loadBenchmark();
      return;
    }

    if (!res.ok) {
      throw new Error(data.error || 'Error al iniciar la corrida de benchmark.');
    }

    // Start polling immediately
    setTimeout(loadBenchmark, 1000);
  } catch (err) {
    showBenchmarkError(err.message);
  }
}

// -----------------------------------------------------------------------------
// EVENT LISTENERS & INITIALIZATION
// -----------------------------------------------------------------------------

function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

$('scan-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('form-error').textContent = '';
  renderActionableError('');
  $('result-meta').classList.add('hidden');
  const url = $('repo-url').value.trim();
  $('btn-start-scan').disabled = true;

  try {
    const response = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || data.error_message || 'URL de repositorio inválida.');

    state.findings = [];
    state.result = null;
    renderFindings();
    renderSummary({});
    $('download-report').disabled = true;
    $('download-json').disabled = true;

    setScanProgress({
      status: data.status || 'queued',
      stage: data.stage,
      message: data.message,
      analysis_id: data.analysis_id,
    });
    state.analysisId = data.analysis_id;
    pollAnalysis(data.analysis_id);
  } catch (error) {
    $('btn-start-scan').disabled = false;
    $('form-error').textContent = error.message;
    setScanProgress({ status: 'failed', error_message: error.message });
  }
});

['severity-filter', 'owasp-filter', 'cwe-filter', 'tool-filter', 'type-filter', 'status-filter', 'file-filter'].forEach((id) => {
  const el = $(id);
  if (el) {
    el.addEventListener('input', renderFindings);
    el.addEventListener('change', renderFindings);
  }
});

$('refresh-history').addEventListener('click', loadHistory);
$('theme-refresh').addEventListener('click', () => {
  loadHistory();
  if (state.activeTab === 'benchmark') loadBenchmark();
});

$('btn-run-benchmark').addEventListener('click', triggerBenchmarkRun);
$('btn-bench-empty-run').addEventListener('click', triggerBenchmarkRun);
$('btn-bench-retry').addEventListener('click', triggerBenchmarkRun);

$('download-report').addEventListener('click', () => {
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([state.report], { type: 'text/markdown;charset=utf-8' }));
  link.download = 'security-report.md';
  link.click();
  URL.revokeObjectURL(link.href);
});

$('download-json').addEventListener('click', () => {
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([JSON.stringify(state.result, null, 2)], { type: 'application/json' }));
  link.download = 'security-report.json';
  link.click();
  URL.revokeObjectURL(link.href);
});

// Boot
setupTabs();
loadHistory();
loadBenchmark();
