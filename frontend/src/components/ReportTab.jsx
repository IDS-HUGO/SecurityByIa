import React from 'react';
import api from '../api/client';

function downloadBlob(content, fileName, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName;
  a.click();
  URL.revokeObjectURL(url);
}

export default function ReportTab({ currentAnalysis }) {
  const markdownReport = currentAnalysis?.markdown_report || '';
  const analysisId = currentAnalysis?.analysis_id;
  const repoName = currentAnalysis?.repository?.name || 'analisis';

  const downloadMarkdown = async () => {
    // F9: primero el reporte enriquecido del backend (SHA, fecha, severidades,
    // remediación y agente redactor); si falla, cae al reporte embebido.
    if (!currentAnalysis) return;
    let content = '';
    try {
      if (analysisId) {
        content = await api.getReportMarkdown(analysisId);
      }
    } catch (err) {
      console.warn('Reporte enriquecido no disponible, se usa el embebido:', err);
    }
    if (!content) content = markdownReport;
    if (!content) return;
    downloadBlob(content, `reporte-seguridad-${repoName}.md`, 'text/markdown;charset=utf-8');
  };

  const downloadJson = () => {
    if (!currentAnalysis) return;
    const jsonStr = JSON.stringify(currentAnalysis, null, 2);
    downloadBlob(jsonStr, `analisis-seguridad-${repoName}.json`, 'application/json;charset=utf-8');
  };

  const downloadSarif = async () => {
    if (!analysisId) return;
    try {
      const sarif = await api.getReportSarif(analysisId);
      downloadBlob(
        JSON.stringify(sarif, null, 2),
        `reporte-seguridad-${repoName}.sarif`,
        'application/json;charset=utf-8'
      );
    } catch (err) {
      console.error('Error descargando SARIF:', err);
    }
  };

  return (
    <div className="tab-pane active">
      <section className="card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap', gap: '16px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '16px' }}>
          <div>
            <p className="eyebrow">ENTREGABLE DE AUDITORÍA</p>
            <h2 style={{ margin: '4px 0 0', fontSize: '18px' }}>Reporte Técnico de Remediación</h2>
            <p className="muted" style={{ margin: '4px 0 0', fontSize: '13px' }}>
              Incluye SHA, fecha, desglose de severidades, remediaciones verificadas y guía técnica de buenas prácticas.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            <button
              type="button"
              className="btn-secondary"
              onClick={downloadMarkdown}
              disabled={!currentAnalysis}
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
            <button
              type="button"
              className="btn-secondary"
              onClick={downloadSarif}
              disabled={!analysisId}
            >
              Descargar SARIF 2.1.0 (.sarif)
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
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '12px', marginBottom: '20px' }}>
              <div style={{ background: 'var(--bg-surface)', padding: '12px 16px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Abiertos</span>
                <div style={{ fontSize: '22px', fontWeight: 700, color: 'var(--text-main)', marginTop: '2px' }}>{counts.open}</div>
              </div>
              <div style={{ background: 'var(--amber-bg)', padding: '12px 16px', borderRadius: '6px', border: '1px solid var(--amber-border)' }}>
                <span style={{ fontSize: '11px', color: 'var(--amber)', textTransform: 'uppercase', fontWeight: 700 }}>Parche Propuesto</span>
                <div style={{ fontSize: '22px', fontWeight: 700, color: 'var(--amber)', marginTop: '2px' }}>{counts.patch_proposed}</div>
              </div>
              <div style={{ background: 'var(--emerald-bg)', padding: '12px 16px', borderRadius: '6px', border: '1px solid var(--emerald-border)' }}>
                <span style={{ fontSize: '11px', color: 'var(--emerald)', textTransform: 'uppercase', fontWeight: 700 }}>Verificados</span>
                <div style={{ fontSize: '22px', fontWeight: 700, color: 'var(--emerald)', marginTop: '2px' }}>{counts.verified}</div>
              </div>
              <div style={{ background: 'var(--crimson-bg)', padding: '12px 16px', borderRadius: '6px', border: '1px solid var(--crimson-border)' }}>
                <span style={{ fontSize: '11px', color: 'var(--crimson)', textTransform: 'uppercase', fontWeight: 700 }}>Descartados</span>
                <div style={{ fontSize: '22px', fontWeight: 700, color: 'var(--crimson)', marginTop: '2px' }}>{counts.discarded}</div>
              </div>
              <div style={{ background: 'var(--emerald-bg)', padding: '12px 16px', borderRadius: '6px', border: '1px solid var(--emerald-border)' }}>
                <span style={{ fontSize: '11px', color: 'var(--emerald)', textTransform: 'uppercase', fontWeight: 700 }}>Aprobados</span>
                <div style={{ fontSize: '22px', fontWeight: 700, color: 'var(--emerald)', marginTop: '2px' }}>{counts.approved}</div>
              </div>
              <div style={{ background: 'var(--crimson-bg)', padding: '12px 16px', borderRadius: '6px', border: '1px solid var(--crimson-border)' }}>
                <span style={{ fontSize: '11px', color: 'var(--crimson)', textTransform: 'uppercase', fontWeight: 700 }}>Rechazados</span>
                <div style={{ fontSize: '22px', fontWeight: 700, color: 'var(--crimson)', marginTop: '2px' }}>{counts.rejected}</div>
              </div>
            </div>
          );
        })()}

        {markdownReport ? (
          <div className="report-preview" style={{ background: 'var(--bg-surface)', padding: '20px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
            <pre style={{ whiteSpace: 'pre-wrap', fontFamily: 'var(--font-mono)', fontSize: '13px', lineHeight: 1.6, color: 'var(--text-main)', margin: 0 }}>
              {markdownReport}
            </pre>
          </div>
        ) : (
          <div className="empty-state">
            <p>No hay ningún reporte generado todavía. Iniciá un análisis para ver su reporte técnico.</p>
          </div>
        )}
      </section>
    </div>
  );
}
