const state = { findings: [], report: '', result: null, timer: null, analysisId: null };
const $ = (id) => document.getElementById(id);
const text = (value, fallback = '') => value === undefined || value === null ? fallback : String(value);
const normalizeStatus = (value) => {
  const status = text(value, 'queued').toLowerCase();
  if (status === 'processing' || status === 'in_progress') return 'running';
  if (status === 'error') return 'failed';
  return ['queued', 'running', 'completed', 'failed'].includes(status) ? status : 'queued';
};
const normalizeFinding = (item) => ({
  ...item,
  severity: text(item.severity, 'low').toLowerCase(),
  file: text(item.file || item.archivo, 'Unknown file'),
  title: text(item.title || item.problema || item.rule || item.regla, 'Security finding'),
  rule: text(item.rule || item.regla, '—'),
  problem: text(item.problem || item.problema),
  solution: text(item.solution || item.solucion),
  owasp: text(item.owasp || item.owasp_category || item.categoria_owasp, 'Uncategorized'),
  cwe: text(item.cwe || item.cwe_id, 'Unspecified'),
  status: text(item.status, 'open').toLowerCase()
});
function setProgress(data = {}) {
  const status = normalizeStatus(data.status);
  const progress = data.progress === undefined && status === 'completed' ? 100 : Number(data.progress) || 0;
  $('progress-panel').classList.remove('hidden');
  $('progress-bar').style.width = `${progress}%`;
  $('progress-value').textContent = `${progress}%`;
  $('progress-message').textContent = text(data.message, status === 'failed' ? 'Analysis failed' : 'Processing');
  $('progress-stage').textContent = text(data.stage, status);
  const badge = $('progress-status'); badge.textContent = status; badge.className = `status status-${status}`;
  const technicalError = $('technical-error');
  technicalError.textContent = text(data.error_message || data.error);
  technicalError.classList.toggle('hidden', !technicalError.textContent);
}
function renderSummary(summary = {}) {
  ['total', 'critical', 'high', 'medium', 'low'].forEach((key) => { $(`${key}-count`).textContent = text(summary[key], 0); });
}
function fillFilter(id, values, label) {
  const select = $(id); const current = select.value;
  select.replaceChildren(new Option(label, ''));
  [...new Set(values.filter(Boolean))].sort().forEach((value) => select.appendChild(new Option(value, value)));
  select.value = values.includes(current) ? current : '';
}
function renderFindings() {
  fillFilter('owasp-filter', state.findings.map((item) => item.owasp), 'All OWASP categories');
  fillFilter('cwe-filter', state.findings.map((item) => item.cwe), 'All CWE');
  const severity = $('severity-filter').value, owasp = $('owasp-filter').value;
  const cwe = $('cwe-filter').value, status = $('status-filter').value;
  const file = $('file-filter').value.toLowerCase();
  const visible = state.findings.filter((item) => (!severity || item.severity === severity) && (!owasp || item.owasp === owasp)
    && (!cwe || item.cwe === cwe) && (!status || item.status === status) && (!file || item.file.toLowerCase().includes(file)));
  const body = $('findings-body'); body.replaceChildren();
  if (!visible.length) { const row = document.createElement('tr'); const cell = document.createElement('td'); cell.colSpan = 5; cell.className = 'empty'; cell.textContent = 'No findings match the selected filters.'; row.appendChild(cell); body.appendChild(row); return; }
  visible.forEach((item) => {
    const row = document.createElement('tr'); row.addEventListener('click', () => showDetail(item));
    [[item.severity, `badge badge-${item.severity}`], [item.title, 'finding-title'], [item.rule, ''], [`${item.file}:${text(item.line, '?')}`, ''], [item.status, `status status-${item.status}`]].forEach(([value, className]) => {
      const cell = document.createElement('td'); cell.textContent = value; cell.className = className; row.appendChild(cell);
    }); body.appendChild(row);
  });
}
function showDetail(item) {
  const panel = $('finding-detail'); panel.replaceChildren();
  const title = document.createElement('h3'); title.textContent = item.title;
  const meta = document.createElement('p'); meta.textContent = `${item.file}:${text(item.line, '?')} · ${item.owasp} · ${item.cwe}`;
  const problem = document.createElement('p'); problem.textContent = item.problem;
  const solution = document.createElement('p'); solution.textContent = `Recommendation: ${item.solution}`;
  panel.append(title, meta, problem, solution);
  if (Array.isArray(item.code_context) && item.code_context.length) { const code = document.createElement('pre'); code.textContent = item.code_context.map((line) => `${line.line} | ${line.text}`).join('\n'); panel.appendChild(code); }
  panel.classList.remove('hidden');
}
function renderResult(data) {
  state.findings = (data.findings || []).map(normalizeFinding); state.report = text(data.markdown_report);
  state.result = data; renderSummary(data.summary || { total: state.findings.length }); renderFindings();
  $('report-content').textContent = state.report || 'No report was generated.';
  $('download-report').disabled = !state.report; $('download-json').disabled = false;
}
async function pollAnalysis(id) {
  try {
    const response = await fetch(`/api/analysis/${encodeURIComponent(id)}`); const data = await response.json();
    if (!response.ok) throw new Error(data.error || data.error_message || 'Could not retrieve analysis.');
    setProgress(data); const status = normalizeStatus(data.status);
    if (status === 'queued' || status === 'running') { state.timer = setTimeout(() => pollAnalysis(id), 1200); return; }
    if (status === 'failed') { $('form-error').textContent = data.error_message || data.error || 'Analysis failed.'; return; }
    renderResult(data); loadHistory();
  } catch (error) { setProgress({ status: 'failed', error_message: error.message }); $('form-error').textContent = error.message; }
}
function historyValue(item) { return item.analysis_id || item.id; }
function renderHistory(items = []) {
  const list = $('history-list'); list.replaceChildren();
  if (!items.length) { const empty = document.createElement('p'); empty.className = 'empty'; empty.textContent = 'No analyses yet.'; list.appendChild(empty); return; }
  items.forEach((item) => {
    const row = document.createElement('div'); row.className = 'history-item';
    const repository = item.repository;
    const repoUrl = typeof repository === 'object' && repository !== null ? repository.url : repository;
    const repo = document.createElement('span'); repo.className = 'history-repo'; repo.textContent = text(item.url || repoUrl, 'Repository');
    const date = document.createElement('span'); date.className = 'history-meta'; date.textContent = text(item.created_at || item.timestamp, 'Date unavailable');
    const status = document.createElement('span'); const normalized = normalizeStatus(item.status); status.className = `status status-${normalized}`; status.textContent = normalized;
    const total = item.total_findings ?? (item.summary && item.summary.total) ?? item.findings_count ?? 0;
    const result = document.createElement('span'); result.className = 'history-meta'; result.textContent = `${total} findings`;
    const button = document.createElement('button'); button.className = 'secondary'; button.type = 'button'; button.textContent = 'Re-analyze'; button.addEventListener('click', () => { $('repo-url').value = text(item.url || repoUrl); $('scan-form').requestSubmit(); });
    row.append(repo, date, status, result, button); list.appendChild(row);
  });
}
async function loadHistory() {
  try { const response = await fetch('/api/analyses'); const data = await response.json(); if (!response.ok) throw new Error(data.error || 'Unable to load history.'); renderHistory(Array.isArray(data) ? data : (data.analyses || [])); }
  catch (error) { const list = $('history-list'); list.replaceChildren(); const message = document.createElement('p'); message.className = 'empty'; message.textContent = `History unavailable: ${error.message}`; list.appendChild(message); }
}
$('scan-form').addEventListener('submit', async (event) => {
  event.preventDefault(); $('form-error').textContent = ''; const url = $('repo-url').value.trim();
  try {
    const response = await fetch('/api/analyze', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ url }) }); const data = await response.json();
    if (!response.ok) throw new Error(data.error || data.error_message || 'Invalid repository URL.');
    state.findings = []; state.result = null; renderFindings(); renderSummary({}); $('download-report').disabled = true; $('download-json').disabled = true; setProgress({ status: data.status || 'queued', message: data.message, analysis_id: data.analysis_id }); state.analysisId = data.analysis_id; pollAnalysis(data.analysis_id);
  } catch (error) { $('form-error').textContent = error.message; setProgress({ status: 'failed', error_message: error.message }); }
});
['severity-filter', 'owasp-filter', 'cwe-filter', 'status-filter', 'file-filter'].forEach((id) => $(id).addEventListener('input', renderFindings));
$('refresh-history').addEventListener('click', loadHistory);
$('download-report').addEventListener('click', () => { const link = document.createElement('a'); link.href = URL.createObjectURL(new Blob([state.report], {type: 'text/markdown;charset=utf-8'})); link.download = 'security-report.md'; link.click(); URL.revokeObjectURL(link.href); });
$('download-json').addEventListener('click', () => { const link = document.createElement('a'); link.href = URL.createObjectURL(new Blob([JSON.stringify(state.result, null, 2)], {type: 'application/json'})); link.download = 'security-report.json'; link.click(); URL.revokeObjectURL(link.href); });
loadHistory();
