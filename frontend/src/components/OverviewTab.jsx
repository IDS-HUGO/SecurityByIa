import React from 'react';

export default function OverviewTab({ currentAnalysis, recentAnalyses, onLoadAnalysis }) {
  const summary = (currentAnalysis && currentAnalysis.summary) || {
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  const hasLoaded = Boolean(currentAnalysis && currentAnalysis.summary);

  return (
    <div className="tab-pane active">
      {/* Summary KPI Grid */}
      <section className="summary-grid">
        <div className="kpi-card">
          <div className="kpi-icon total">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/>
            </svg>
          </div>
          <div>
            <span className="kpi-label">Total Hallazgos</span>
            <strong className="kpi-num">{hasLoaded ? summary.total : '—'}</strong>
            <small className="kpi-sub">En el repositorio analizado</small>
          </div>
        </div>

        <div className="kpi-card critical">
          <div className="kpi-icon critical">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
              <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
          </div>
          <div>
            <span className="kpi-label">Críticos</span>
            <strong className="kpi-num">{hasLoaded ? summary.critical : '—'}</strong>
            <small className="kpi-sub">Acción urgente (48h)</small>
          </div>
        </div>

        <div className="kpi-card high">
          <div className="kpi-icon high">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 14 14"/>
            </svg>
          </div>
          <div>
            <span className="kpi-label">Altos</span>
            <strong className="kpi-num">{hasLoaded ? summary.high : '—'}</strong>
            <small className="kpi-sub">Prioridad alta (30d)</small>
          </div>
        </div>

        <div className="kpi-card medium">
          <div className="kpi-icon medium">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
            </svg>
          </div>
          <div>
            <span className="kpi-label">Medios</span>
            <strong className="kpi-num">{hasLoaded ? summary.medium : '—'}</strong>
            <small className="kpi-sub">Atención planificada (90d)</small>
          </div>
        </div>

        <div className="kpi-card low">
          <div className="kpi-icon low">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <div>
            <span className="kpi-label">Bajos</span>
            <strong className="kpi-num">{hasLoaded ? summary.low : '—'}</strong>
            <small className="kpi-sub">Mejoras de código (180d)</small>
          </div>
        </div>
      </section>

      {/* Panel de Cobertura del Análisis (F14) */}
      {currentAnalysis && currentAnalysis.coverage && (
        <section className="card" style={{ marginTop: '20px', padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div>
              <p className="eyebrow" style={{ margin: 0 }}>PRINCIPIO DE COBERTURA DECLARADA (F14)</p>
              <h3 style={{ margin: '4px 0 0', fontSize: '16px' }}>Cobertura Políglota del Análisis</h3>
            </div>
            <span
              className="badge"
              style={{
                background: currentAnalysis.coverage.status === 'completed' ? 'rgba(34, 197, 94, 0.15)' : 'rgba(234, 179, 8, 0.15)',
                color: currentAnalysis.coverage.status === 'completed' ? '#22c55e' : '#eab308',
                border: currentAnalysis.coverage.status === 'completed' ? '1px solid rgba(34, 197, 94, 0.4)' : '1px solid rgba(234, 179, 8, 0.4)',
                padding: '0.3rem 0.75rem',
                borderRadius: '4px',
                fontWeight: 600,
                fontSize: '0.8rem',
              }}
            >
              {currentAnalysis.coverage.status === 'completed' ? '✓ Cobertura Total (Completed)' : '⚠️ Cobertura Parcial (Completed with Gaps)'}
            </span>
          </div>

          {currentAnalysis.coverage.gaps && currentAnalysis.coverage.gaps.length > 0 && (
            <div style={{ background: 'rgba(234, 179, 8, 0.08)', border: '1px solid rgba(234, 179, 8, 0.3)', borderRadius: '6px', padding: '12px 16px', marginBottom: '14px', fontSize: '0.85rem', color: '#fef08a' }}>
              <strong>Lagunas de cobertura detectadas:</strong>
              <ul style={{ margin: '6px 0 0 18px', padding: 0 }}>
                {currentAnalysis.coverage.gaps.map((gap, i) => (
                  <li key={i}>{gap}</li>
                ))}
              </ul>
              <div style={{ marginTop: '8px', fontSize: '0.8rem', color: '#94a3b8' }}>
                💡 <em>Por honestidad del análisis nunca se declara 'limpio' sin revisar. La revisión con IA asiste como cubierta complementaria.</em>
              </div>
            </div>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: '10px' }}>
            {(currentAnalysis.coverage.languages || []).map((lang) => (
              <div key={lang.name} style={{ background: 'var(--surface-color, #0f172a)', border: '1px solid var(--border-color, #334155)', borderRadius: '6px', padding: '12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <strong style={{ textTransform: 'capitalize', color: '#f8fafc' }}>{lang.name}</strong>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted, #94a3b8)' }}>{lang.files} archivos ({Math.round(lang.bytes / 1024)} KB)</span>
                </div>
                <div style={{ fontSize: '0.8rem', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <div>
                    <span style={{ color: 'var(--text-muted, #94a3b8)' }}>SAST: </span>
                    <span style={{ color: lang.sast ? '#38bdf8' : '#ef4444', fontWeight: 600 }}>{lang.sast || 'Sin SAST dedicado'}</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted, #94a3b8)' }}>SCA: </span>
                    <span style={{ color: lang.sca ? '#22c55e' : '#94a3b8' }}>{lang.sca || 'N/A'}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Recent Analyses History Section */}
      <section className="card" style={{ marginTop: '20px' }}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <p className="eyebrow">HISTORIAL DE ACTIVIDAD</p>
            <h3 style={{ margin: '4px 0 0', fontSize: '16px' }}>Últimos Análisis Realizados</h3>
          </div>
          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Persistidos en disco</span>
        </div>

        <div className="table-wrap">
          {recentAnalyses && recentAnalyses.length > 0 ? (
            <table className="findings-table">
              <thead>
                <tr>
                  <th>Repositorio</th>
                  <th>Fecha</th>
                  <th>Estado</th>
                  <th>Resumen de Severidad</th>
                  <th style={{ textAlign: 'right' }}>Acción</th>
                </tr>
              </thead>
              <tbody>
                {recentAnalyses.map((item) => {
                  const s = item.summary || {};
                  const repoUrl = (item.repository && item.repository.url) || '—';
                  const dateStr = item.created_at ? new Date(item.created_at).toLocaleString() : '—';
                  return (
                    <tr key={item.analysis_id}>
                      <td>
                        <strong style={{ color: 'var(--text-main)' }}>
                          {(item.repository && item.repository.name) || repoUrl}
                        </strong>
                        <div style={{ fontSize: '12px', color: 'var(--text-muted)', wordBreak: 'break-all', marginTop: '2px' }}>
                          {repoUrl}
                        </div>
                      </td>
                      <td style={{ fontSize: '13px', color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                        {dateStr}
                      </td>
                      <td>
                        <span className={`status status-${item.status === 'completed' ? 'completed' : item.status === 'error' ? 'failed' : 'queued'}`}>
                          {item.status || 'unknown'}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                          {s.critical > 0 && <span className="sev-badge critical">C: {s.critical}</span>}
                          {s.high > 0 && <span className="sev-badge high">A: {s.high}</span>}
                          {s.medium > 0 && <span className="sev-badge medium">M: {s.medium}</span>}
                          {s.low > 0 && <span className="sev-badge low">B: {s.low}</span>}
                          {(!s.total || s.total === 0) && <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>0 hallazgos</span>}
                        </div>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          type="button"
                          className="btn-secondary"
                          style={{ height: '30px', padding: '0 10px', fontSize: '12px' }}
                          onClick={() => onLoadAnalysis(item.analysis_id)}
                        >
                          Ver análisis
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          ) : (
            <div className="empty-state">
              <p>No hay análisis registrados todavía. Iniciá un análisis arriba para comenzar.</p>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
