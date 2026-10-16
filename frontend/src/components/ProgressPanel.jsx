import React from 'react';

export default function ProgressPanel({ analysis }) {
  if (!analysis) return null;

  const {
    status = 'queued',
    stage = 'queued',
    progress = 0,
    message = 'Iniciando análisis...',
    repository = {},
    error = null,
  } = analysis;

  const normalizedStatus =
    status === 'processing' || status === 'in_progress'
      ? 'running'
      : status === 'error'
      ? 'failed'
      : status;

  const repoName = repository.name || repository.url || '—';
  const repoBranch = repository.branch || '—';
  const repoSha = repository.commit ? repository.commit.slice(0, 7) : '—';

  return (
    <section className="card progress-card" aria-live="polite">
      <div className="progress-header">
        <div>
          <strong>{message}</strong>
          <small className="progress-sub">Etapa: {stage}</small>
        </div>
        <div className="progress-status-wrap">
          <span className={`status status-${normalizedStatus}`}>{normalizedStatus}</span>
          <span className="progress-pct">{progress}%</span>
        </div>
      </div>
      <div className="progress-bar-container">
        <div
          className="progress-bar-fill"
          style={{ width: `${Math.min(100, Math.max(0, progress))}%` }}
        ></div>
      </div>

      {(repository.url || repository.commit) && (
        <div className="result-meta">
          <span className="meta-item">
            <span className="meta-label">Repositorio</span>
            <code className="meta-code">{repoName}</code>
          </span>
          <span className="meta-item">
            <span className="meta-label">Rama analizada</span>
            <code className="meta-code">{repoBranch}</code>
          </span>
          <span className="meta-item">
            <span className="meta-label">SHA analizado</span>
            <code className="meta-code">{repoSha}</code>
          </span>
        </div>
      )}

      {error && (
        <div className="error-banner" role="alert" style={{ marginTop: '1rem' }}>
          <strong>Error en el análisis:</strong> {error}
        </div>
      )}
    </section>
  );
}
