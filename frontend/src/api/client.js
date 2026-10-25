/**
 * Single API access layer for Security Control Center.
 * Reads backend base URL from VITE_API_BASE_URL environment variable.
 * When empty, defaults to relative /api (proxied via Vite dev proxy or Nginx in production).
 */

const API_BASE = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/+$/, '');

async function request(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const headers = {
    Accept: 'application/json',
    ...(options.headers || {}),
  };

  if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(options.body);
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  const contentType = response.headers.get('content-type') || '';
  let data = null;
  if (contentType.includes('application/json')) {
    data = await response.json();
  } else {
    data = await response.text();
  }

  if (!response.ok) {
    const errorMsg = (data && data.error) || (data && data.message) || `Error HTTP ${response.status}: ${response.statusText}`;
    const err = new Error(errorMsg);
    err.status = response.status;
    err.data = data;
    throw err;
  }

  return data;
}

export const api = {
  // SAST analysis endpoints
  startAnalysis: (url, enableAiTriage = false) =>
    request('/api/analyze', {
      method: 'POST',
      body: {
        url,
        enable_ai_triage: Boolean(enableAiTriage),
      },
    }),

  getAnalysis: (analysisId) =>
    request(`/api/analysis/${encodeURIComponent(analysisId)}`, {
      method: 'GET',
    }),

  listAnalyses: () =>
    request('/api/analyses', {
      method: 'GET',
    }),

  // Reports & exports endpoints (Feature 9)
  getReportMarkdown: (analysisId) =>
    request(`/api/analysis/${encodeURIComponent(analysisId)}/report.md`, {
      method: 'GET',
    }),

  getReportSarif: (analysisId) =>
    request(`/api/analysis/${encodeURIComponent(analysisId)}/report.sarif`, {
      method: 'GET',
    }),

  getExecutiveSummary: (analysisId) =>
    request(`/api/analysis/${encodeURIComponent(analysisId)}/executive-summary`, {
      method: 'GET',
    }),

  compareAnalyses: (baseId, targetId) =>
    request(`/api/analyses/compare?base=${encodeURIComponent(baseId)}&target=${encodeURIComponent(targetId)}`, {
      method: 'GET',
    }),

  // AI & Human Triage endpoints
  triageFinding: (analysisId, findingId, { decision, reason, author }) =>
    request(`/api/analysis/${encodeURIComponent(analysisId)}/finding/${encodeURIComponent(findingId)}/triage`, {
      method: 'POST',
      body: {
        decision,
        reason,
        author: author || 'analista-seguridad',
      },
    }),

  getReviewQueue: (analysisId) =>
    request(`/api/analysis/${encodeURIComponent(analysisId)}/review-queue`, {
      method: 'GET',
    }),

  getTriageFingerprints: () =>
    request('/api/triage/fingerprints', {
      method: 'GET',
    }),

  // Benchmark endpoints
  getBenchmarkStatus: () =>
    request('/api/bench', {
      method: 'GET',
    }),

  runBenchmark: ({ feature, saveAsBaseline } = {}) =>
    request('/api/bench/run', {
      method: 'POST',
      body: {
        feature: feature || undefined,
        save_as_baseline: Boolean(saveAsBaseline),
      },
    }),

  getBenchmarkBaseline: () =>
    request('/api/bench/baseline', {
      method: 'GET',
    }),

  getBenchmarkHistory: () =>
    request('/api/bench/history', {
      method: 'GET',
    }),

  getBenchmarkRun: (runId) =>
    request(`/api/bench/run/${encodeURIComponent(runId)}`, {
      method: 'GET',
    }),

  // Remediation & Fixer endpoints (Feature 6)
  proposeFix: (analysisId, findingId) =>
    request(`/api/analysis/${encodeURIComponent(analysisId)}/finding/${encodeURIComponent(findingId)}/fix`, {
      method: 'POST',
    }),

  reviewRemediation: (analysisId, findingId, { decision, reason, author }) =>
    request(`/api/analysis/${encodeURIComponent(analysisId)}/finding/${encodeURIComponent(findingId)}/remediation/review`, {
      method: 'POST',
      body: {
        decision,
        reason,
        author: author || 'analista-seguridad',
      },
    }),

  runSandboxTests: (analysisId, { optIn, isOwnRepo } = {}) =>
    request(`/api/analysis/${encodeURIComponent(analysisId)}/tests/run`, {
      method: 'POST',
      body: {
        opt_in: Boolean(optIn),
        is_own_repo: Boolean(isOwnRepo),
      },
    }),

  // Secret & API proxy endpoints (Feature 8)
  getProxyStatus: () =>
    request('/api/proxy/status', {
      method: 'GET',
    }),

  getProxyAudit: (limit = 50) =>
    request(`/api/proxy/audit?limit=${encodeURIComponent(limit)}`, {
      method: 'GET',
    }),

  // Controls review endpoints (Feature 10)
  listControls: () =>
    request('/api/controls', {
      method: 'GET',
    }),

  getAnalysisControls: (analysisId) =>
    request(`/api/analysis/${encodeURIComponent(analysisId)}/controls`, {
      method: 'GET',
    }),

  reReviewControls: (analysisId) =>
    request(`/api/analysis/${encodeURIComponent(analysisId)}/controls/review`, {
      method: 'POST',
    }),

  // Live verification and evidence endpoints (Feature 11)
  runLiveVerification: (payload) =>
    request('/api/verificaciones/en-vivo', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  getVerificationAudit: (limit = 50) =>
    request(`/api/verificaciones/bitacora?limit=${encodeURIComponent(limit)}`, {
      method: 'GET',
    }),

  saveControlEvidence: (analysisId, controlId, payload) =>
    request(`/api/analysis/${encodeURIComponent(analysisId)}/controls/${encodeURIComponent(controlId)}/evidencia`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  // Credential Broker endpoints (Feature 12)
  listCredentialSites: () =>
    request('/api/credentials/sites', {
      method: 'GET',
    }),

  registerCredentialSite: (payload) =>
    request('/api/credentials/sites', {
      method: 'POST',
      body: payload,
    }),

  listCredentialApprovals: (status = '') =>
    request(`/api/credentials/approvals${status ? `?status=${encodeURIComponent(status)}` : ''}`, {
      method: 'GET',
    }),

  actOnCredentialApproval: (requestId, { action, reviewer, reason, granted_ttl_seconds }) =>
    request(`/api/credentials/approvals/${encodeURIComponent(requestId)}/action`, {
      method: 'POST',
      body: { action, reviewer, reason, granted_ttl_seconds },
    }),

  listCredentialSessions: () =>
    request('/api/credentials/sessions', {
      method: 'GET',
    }),

  revokeCredentialSession: (sessionId) =>
    request(`/api/credentials/sessions/${encodeURIComponent(sessionId)}/revoke`, {
      method: 'POST',
    }),

  getCredentialAudit: (limit = 50) =>
    request(`/api/credentials/audit?limit=${encodeURIComponent(limit)}`, {
      method: 'GET',
    }),

  // Tools & Tool Benchmark endpoints (Feature 13 & 14)
  listTools: () =>
    request('/api/tools', {
      method: 'GET',
    }),

  getToolBenchmarkStatus: () =>
    request('/api/bench/tools', {
      method: 'GET',
    }),

  runToolBenchmark: (payload = {}) =>
    request('/api/bench/tools/run', {
      method: 'POST',
      body: payload,
    }),
};

export default api;
