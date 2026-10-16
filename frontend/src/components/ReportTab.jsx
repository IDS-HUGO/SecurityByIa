import React from 'react';

export default function ReportTab({ currentAnalysis }) {
  const markdownReport = currentAnalysis?.markdown_report || '';
  const repoName = currentAnalysis?.repository?.name || 'analisis';

  const downloadMarkdown = () => {
    if (!markdownReport) return;
    const blob = new Blob([markdownReport], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `reporte-seguridad-${repoName}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadJson = () => {
    if (!currentAnalysis) return;
    const jsonStr = JSON.stringify(currentAnalysis, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `analisis-seguridad-${repoName}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="tab-pane active">
      <section className="card" style={{ padding: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '1rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '1rem' }}>
          <div>
            <p className="eyebrow">ENTREGABLE DE AUDITORÍA</p>
            <h2 style={{ margin: '0.2rem 0', fontSize: '1.25rem' }}>Reporte Técnico de Remediación</h2>
            <p className="muted" style={{ margin: 0, fontSize: '0.85rem' }}>
              Incluye hallazgos, plazos de remediación (Control 6) y contexto de seguridad.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              type="button"
              className="btn-secondary"
              onClick={downloadMarkdown}
              disabled={!markdownReport}
            >
              Descargar Markdown (.md)
            </button>
            <button
              type="button"
              className="btn-secondary"
              onClick={downloadJson}
              disabled={!currentAnalysis}
            >
              Descargar JSON (.json)
            </button>
          </div>
        </div>

        {/* Remediation KPI Summary (F6) */}
        {currentAnalysis && currentAnalysis.findings && currentAnalysis.findings.length > 0 && (() => {
          const findings = currentAnalysis.findings || [];
          const counts = {
            open: findings.filter((f) => (f.remediation?.status || 'open') === 'open').length,
            patch_proposed: findings.filter((f) => f.remediation?.status === 'patch_proposed').length,
            verified: findings.filter((f) => f.remediation?.status === 'verified').length,
            discarded: findings.filter((f) => f.remediation?.status === 'discarded').length,
            approved: findings.filter((f) => f.remediation?.status === 'approved').length,
            rejected: findings.filter((f) => f.remediation?.status === 'rejected').length,
          };
          return (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '0.75rem', marginBottom: '1.25rem' }}>
              <div style={{ background: 'var(--card-bg-subtle)', padding: '0.75rem 1rem', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--muted-color)', textTransform: 'uppercase', fontWeight: 600 }}>Abiertos</span>
                <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-color)' }}>{counts.open}</div>
              </div>
              <div style={{ background: 'var(--card-bg-subtle)', padding: '0.75rem 1rem', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                <span style={{ fontSize: '0.75rem', color: '#fde047', textTransform: 'uppercase', fontWeight: 600 }}>Parche Propuesto</span>
                <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#fde047' }}>{counts.patch_proposed}</div>
              </div>
              <div style={{ background: 'var(--card-bg-subtle)', padding: '0.75rem 1rem', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                <span style={{ fontSize: '0.75rem', color: '#4ade80', textTransform: 'uppercase', fontWeight: 600 }}>Verificados</span>
                <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#4ade80' }}>{counts.verified}</div>
              </div>
              <div style={{ background: 'var(--card-bg-subtle)', padding: '0.75rem 1rem', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                <span style={{ fontSize: '0.75rem', color: '#f87171', textTransform: 'uppercase', fontWeight: 600 }}>Descartados</span>
                <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#f87171' }}>{counts.discarded}</div>
              </div>
              <div style={{ background: 'var(--card-bg-subtle)', padding: '0.75rem 1rem', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                <span style={{ fontSize: '0.75rem', color: '#34d399', textTransform: 'uppercase', fontWeight: 600 }}>Aprobados</span>
                <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#34d399' }}>{counts.approved}</div>
              </div>
              <div style={{ background: 'var(--card-bg-subtle)', padding: '0.75rem 1rem', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                <span style={{ fontSize: '0.75rem', color: '#fb7185', textTransform: 'uppercase', fontWeight: 600 }}>Rechazados</span>
                <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#fb7185' }}>{counts.rejected}</div>
              </div>
            </div>
          );
        })()}

        {markdownReport ? (
          <div className="report-preview" style={{ background: 'var(--card-bg-subtle)', padding: '1.5rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <pre style={{ whiteSpace: 'pre-wrap', fontFamily: 'var(--font-mono)', fontSize: '0.88rem', lineHeight: 1.6, margin: 0 }}>
              {markdownReport}
            </pre>
          </div>
        ) : (
          <div className="empty-state" style={{ padding: '4rem 1rem' }}>
            <p>No hay ningún reporte generado todavía. Iniciá un análisis para ver su reporte técnico.</p>
          </div>
        )}
      </section>
    </div>
  );
}
