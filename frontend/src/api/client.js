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
};

export default api;
