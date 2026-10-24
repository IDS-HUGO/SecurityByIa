import React, { useState, useEffect } from 'react';
import api from '../api/client';

const SEVERITY_LABEL = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja' };
const REMEDIATION_LABEL = {
  open: 'Abierto',
  patch_proposed: 'Parche propuesto',
  verified: 'Verificado',
  discarded: 'Descartado',
  approved: 'Aprobado',
  rejected: 'Rechazado',
};

function MissingData({ value }) {
  if (value) return <>{value}</>;
  return <span style={{ color: 'var(--amber)', fontStyle: 'italic' }}>dato no disponible</span>;
}

export default function ExecutiveTab({ currentAnalysis }) {
  const analysisId = currentAnalysis?.analysis_id;
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    if (!analysisId) {
      setSummary(null);
      setError(null);
      return undefined;
    }
    let cancelled = false;
    setIsLoading(true);
    setError(null);
    api.getExecutiveSummary(analysisId)
      .then((data) => {
        if (!cancelled) setSummary(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err.message || 'Error al cargar el resumen ejecutivo');
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });
    return () => { cancelled = true; };
  }, [analysisId]);

  if (!analysisId) {
    return (
      <div className="tab-pane active">
        <section className="card">
          <div className="empty-state">
            <p>No hay ningún análisis cargado. Iniciá un análisis o cargá uno del historial para ver su resumen ejecutivo imprimible.</p>
          </div>
        </section>
      </div>
    );
  }

  const repo = summary?.repository || {};
  const counts = summary?.severity_counts || {};
  const remediation = summary?.remediation_counts || {};

  return (
    <div className="tab-pane active">
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginBottom: '12px' }} className="no-print">
        <button type="button" className="btn-primary" onClick={() => window.print()} disabled={!summary}>
          Imprimir / Guardar PDF
        </button>
      </div>

      <section className="card" style={{ padding: '24px' }}>
        {isLoading && <div className="empty-state"><p>Cargando resumen ejecutivo…</p></div>}

        {!isLoading && error && (
          <div className="empty-state"><p>{error}</p></div>
        )}

        {!isLoading && !error && !summary && (
          <div className="empty-state"><p>Sin resumen ejecutivo disponible para este análisis.</p></div>
        )}

        {!isLoading && summary && (
          <div className="executive-sheet">
            {/* Encabezado de página */}
            <header style={{ borderBottom: '2px solid var(--border-strong)', paddingBottom: '12px', marginBottom: '16px' }}>
              <p className="eyebrow" style={{ margin: 0 }}>RESUMEN EJECUTIVO DE SEGURIDAD — 1 PÁGINA</p>
              <h2 style={{ margin: '6px 0 0', fontSize: '22px' }}>
                <MissingData value={repo.name || repo.url} />
              </h2>
              <p className="muted" style={{ margin: '4px 0 0', fontSize: '13px' }}>
                Rama: <MissingData value={repo.branch} /> · Commit: <MissingData value={repo.commit ? String(repo.commit).slice(0, 12) : ''} /> · Fecha de análisis: {summary.analyzed_at || 'dato no disponible'} · ID: {summary.analysis_id}
              </p>
            </header>

            {/* KPIs de severidad */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(110px, 1fr))', gap: '10px', marginBottom: '16px' }}>
              {['critical', 'high', 'medium', 'low'].map((sev) => (
                <div key={sev} className={`sev-card sev-${sev}`} style={{ background: 'var(--bg-surface)', padding: '10px 14px', borderRadius: '8px', border: '1px solid var(--border-subtle)', textAlign: 'center' }}>
                  <div style={{ fontSize: '11px', textTransform: 'uppercase', fontWeight: 700, color: 'var(--text-muted)' }}>{SEVERITY_LABEL[sev]}</div>
                  <div style={{ fontSize: '24px', fontWeight: 700 }}>
                    <span className={`sev-badge ${sev}`}>{counts[sev] ?? 0}</span>
                  </div>
                </div>
              ))}
              <div style={{ background: 'var(--bg-surface)', padding: '10px 14px', borderRadius: '8px', border: '1px solid var(--border-subtle)', textAlign: 'center' }}>
                <div style={{ fontSize: '11px', textTransform: 'uppercase', fontWeight: 700, color: 'var(--text-muted)' }}>Total</div>
                <div style={{ fontSize: '24px', fontWeight: 700 }}>{counts.total ?? 0}</div>
              </div>
            </div>

            {/* Estado de remediación */}
            <h3 style={{ fontSize: '14px', margin: '0 0 8px' }}>Estado de remediación</h3>
            <p style={{ fontSize: '13px', margin: '0 0 16px', display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
              {Object.entries(remediation).filter(([, count]) => count > 0).map(([state, count]) => (
                <span key={state}><strong>{count}</strong> {REMEDIATION_LABEL[state] || state}</span>
              ))}
              {Object.values(remediation).every((count) => !count) && <span className="muted">Sin datos de remediación registrados.</span>}
            </p>

            {/* Hallazgos principales */}
            <h3 style={{ fontSize: '14px', margin: '0 0 8px' }}>Hallazgos principales</h3>
            {(summary.top_findings || []).length > 0 ? (
              <table className="findings-table" style={{ marginBottom: '16px' }}>
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Hallazgo</th>
                    <th>Severidad</th>
                    <th>Ubicación</th>
                    <th>Remediación</th>
                  </tr>
                </thead>
                <tbody>
                  {summary.top_findings.map((finding) => (
                    <tr key={finding.id}>
                      <td>{finding.id}</td>
                      <td>{finding.title || 'Dato no disponible: título'}</td>
                      <td><span className={`sev-badge ${finding.severity || 'low'}`}>{finding.severity || 'n/d'}</span></td>
                      <td><code style={{ fontSize: '12px' }}>{finding.file || 'n/d'}{finding.line ? `:${finding.line}` : ''}</code></td>
                      <td>{REMEDIATION_LABEL[finding.remediation_status] || finding.remediation_status}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="muted" style={{ fontSize: '13px' }}>El análisis no registró hallazgos: no se listan items para no inventar contenido.</p>
            )}

            {/* Guía de buenas prácticas (agente redactor) */}
            <h3 style={{ fontSize: '14px', margin: '0 0 8px' }}>Guía de buenas prácticas</h3>
            {(summary.best_practices_guide?.sections || []).length > 0 ? (
              <ul style={{ fontSize: '13px', margin: '0 0 12px', paddingLeft: '18px' }}>
                {summary.best_practices_guide.sections.map((section) => (
                  <li key={section.category} style={{ marginBottom: '4px' }}>
                    <strong>{section.category}</strong> ({section.finding_count} hallazgo/s){': '}
                    {section.practices && section.practices.length > 0
                      ? section.practices[0]
                      : (section.note || 'sin prácticas derivadas de datos reales')}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted" style={{ fontSize: '13px' }}>{summary.best_practices_guide?.note || 'Sin secciones: se construye solo con hallazgos reales.'}</p>
            )}

            {/* Datos faltantes declarados */}
            <h3 style={{ fontSize: '14px', margin: '12px 0 8px' }}>Datos faltantes declarados</h3>
            {(summary.data_gaps || []).length > 0 ? (
              <ul style={{ fontSize: '12px', margin: 0, paddingLeft: '18px', color: 'var(--text-muted)' }}>
                {summary.data_gaps.slice(0, 8).map((gap, index) => (
                  <li key={`${gap.scope}-${gap.field}-${index}`}><code>{gap.scope}</code> → falta <code>{gap.field}</code></li>
                ))}
                {(summary.data_gaps.length > 8) && <li>…y {summary.data_gaps.length - 8} más.</li>}
              </ul>
            ) : (
              <p className="muted" style={{ fontSize: '13px' }}>Ninguno: el análisis registró todos los campos usados en esta página.</p>
            )}

            <footer style={{ marginTop: '14px', paddingTop: '8px', borderTop: '1px solid var(--border-subtle)', fontSize: '11px', color: 'var(--text-muted)' }}>
              {summary.note}
            </footer>
          </div>
        )}
      </section>
    </div>
  );
}
