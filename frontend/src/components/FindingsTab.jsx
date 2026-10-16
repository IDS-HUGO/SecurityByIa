import React, { useState, useMemo } from 'react';
import FindingDetailModal from './FindingDetailModal';

export default function FindingsTab({
  findings = [],
  analysisId,
  onTriageDecision,
  onProposeFix,
  onReviewRemediation,
}) {
  const [selectedTool, setSelectedTool] = useState('all');
  const [selectedType, setSelectedType] = useState('all');
  const [selectedVerdict, setSelectedVerdict] = useState('all');
  const [selectedRemStatus, setSelectedRemStatus] = useState('all');
  const [reviewQueueActive, setReviewQueueActive] = useState(false);
  const [activeFilterSev, setActiveFilterSev] = useState(null);
  const [activeFilterOwasp, setActiveFilterOwasp] = useState(null);
  const [detailFinding, setDetailFinding] = useState(null);

  // Compute distinct tools present in current findings
  const distinctTools = useMemo(() => {
    const s = new Set();
    findings.forEach((f) => {
      (f.tools || []).forEach((t) => s.add(t));
    });
    return Array.from(s).sort();
  }, [findings]);

  // Compute uncertain findings count for Review Queue
  const reviewQueueCount = useMemo(() => {
    return findings.filter((f) => {
      const v = f.triage?.verdict;
      return v === 'incierto' || f.needs_human_review === true;
    }).length;
  }, [findings]);

  // Compute severity counts
  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    findings.forEach((f) => {
      const sev = (f.severity || 'low').toLowerCase();
      if (counts[sev] !== undefined) counts[sev] += 1;
    });
    return counts;
  }, [findings]);

  // Compute OWASP category counts
  const owaspCounts = useMemo(() => {
    const map = {};
    findings.forEach((f) => {
      const cat = f.owasp || 'A05:2021 - Security Misconfiguration';
      // Short label: e.g. "A01:2021"
      const short = cat.split(' - ')[0] || cat;
      map[short] = (map[short] || 0) + 1;
    });
    return Object.entries(map).sort((a, b) => a[0].localeCompare(b[0]));
  }, [findings]);

  // Filter findings
  const filteredFindings = useMemo(() => {
    let list = findings;

    // Review Queue Mode: Only uncertain findings ordered by severity
    if (reviewQueueActive) {
      list = list.filter((f) => {
        const v = f.triage?.verdict;
        return v === 'incierto' || f.needs_human_review === true;
      });
      const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      return [...list].sort((a, b) => {
        const wa = sevOrder[(a.severity || 'low').toLowerCase()] ?? 4;
        const wb = sevOrder[(b.severity || 'low').toLowerCase()] ?? 4;
        return wa - wb;
      });
    }

    return list.filter((f) => {
      // 1. Tool filter
      if (selectedTool !== 'all') {
        const tools = f.tools || [];
        if (!tools.includes(selectedTool)) return false;
      }

      // 2. Type filter
      if (selectedType !== 'all') {
        const isSecret = (f.tools || []).includes('gitleaks') ||
                         (f.tools || []).includes('trufflehog') ||
                         Boolean(f.verification);
        const isDep = Boolean(f.package || (f.extra && f.extra.package));
        if (selectedType === 'secret' && !isSecret) return false;
        if (selectedType === 'dependency' && !isDep) return false;
        if (selectedType === 'code' && (isSecret || isDep)) return false;
      }

      // 3. Triage verdict filter
      if (selectedVerdict !== 'all') {
        const v = f.triage?.verdict || (f.status === 'false_positive' ? 'falso' : 'verdadero');
        if (v !== selectedVerdict) return false;
      }

      // 4. Remediation status filter (F6)
      if (selectedRemStatus !== 'all') {
        const rem = (f.remediation?.status || 'open').toLowerCase();
        if (rem !== selectedRemStatus) return false;
      }

      // 5. Clicked Severity filter
      if (activeFilterSev) {
        if ((f.severity || 'low').toLowerCase() !== activeFilterSev.toLowerCase()) return false;
      }

      // 6. Clicked OWASP filter
      if (activeFilterOwasp) {
        const cat = f.owasp || '';
        if (!cat.toLowerCase().startsWith(activeFilterOwasp.toLowerCase())) return false;
      }

      return true;
    });
  }, [findings, reviewQueueActive, selectedTool, selectedType, selectedVerdict, selectedRemStatus, activeFilterSev, activeFilterOwasp]);

  const clearFilters = () => {
    setSelectedTool('all');
    setSelectedType('all');
    setSelectedVerdict('all');
    setSelectedRemStatus('all');
    setReviewQueueActive(false);
    setActiveFilterSev(null);
    setActiveFilterOwasp(null);
  };

  const hasActiveFilters =
    selectedTool !== 'all' ||
    selectedType !== 'all' ||
    selectedVerdict !== 'all' ||
    selectedRemStatus !== 'all' ||
    reviewQueueActive ||
    activeFilterSev !== null ||
    activeFilterOwasp !== null;

  return (
    <div className="tab-pane active">
      {/* Clickable Summary Bar by Severity and OWASP Category */}
      <section className="card" style={{ marginBottom: '1.25rem', padding: '1rem 1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
          <div>
            <span className="eyebrow">RESUMEN CLICABLE DE HALLAZGOS</span>
            <p style={{ margin: '0.2rem 0 0', fontSize: '0.85rem', color: 'var(--muted-color)' }}>
              Hacé clic en cualquier severidad o categoría OWASP para filtrar la tabla automáticamente.
            </p>
          </div>
          {hasActiveFilters && (
            <button
              type="button"
              className="btn-secondary"
              style={{ fontSize: '0.8rem', padding: '0.35rem 0.75rem' }}
              onClick={clearFilters}
            >
              Limpiar filtros
            </button>
          )}
        </div>

        {/* Severities row */}
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
          {['critical', 'high', 'medium', 'low'].map((sev) => {
            const count = severityCounts[sev];
            const isSelected = activeFilterSev === sev;
            const labels = { critical: 'Crítico', high: 'Alto', medium: 'Medio', low: 'Bajo' };
            return (
              <button
                key={sev}
                type="button"
                className={`summary-pill sev-${sev} ${isSelected ? 'active-filter' : ''}`}
                onClick={() => setActiveFilterSev(isSelected ? null : sev)}
              >
                <span>{labels[sev]}</span>
                <strong>{count}</strong>
              </button>
            );
          })}
        </div>

        {/* OWASP categories row */}
        {owaspCounts.length > 0 && (
          <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', alignItems: 'center' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--muted-color)', marginRight: '0.25rem' }}>OWASP:</span>
            {owaspCounts.map(([catKey, count]) => {
              const isSelected = activeFilterOwasp === catKey;
              return (
                <button
                  key={catKey}
                  type="button"
                  className={`summary-pill owasp-pill ${isSelected ? 'active-filter' : ''}`}
                  onClick={() => setActiveFilterOwasp(isSelected ? null : catKey)}
                >
                  <span>{catKey}</span>
                  <strong>{count}</strong>
                </button>
              );
            })}
          </div>
        )}
      </section>

      {/* Filter Toolbar */}
      <section className="card" style={{ marginBottom: '1.25rem', padding: '0.85rem 1.25rem' }}>
        <div className="filter-bar" style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => setReviewQueueActive(!reviewQueueActive)}
            style={{
              borderColor: reviewQueueActive ? 'var(--warning-color, #f59e0b)' : 'var(--border-color)',
              background: reviewQueueActive ? 'rgba(245, 158, 11, 0.15)' : 'transparent',
              color: reviewQueueActive ? 'var(--warning-color, #f59e0b)' : 'var(--text-color)',
              fontWeight: 600,
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.4rem',
            }}
          >
            <span>Cola Por revisar</span>
            <span style={{
              background: reviewQueueCount > 0 ? '#f59e0b' : 'var(--muted-color)',
              color: '#000',
              borderRadius: '9999px',
              padding: '0.1rem 0.45rem',
              fontSize: '0.75rem',
              fontWeight: 700,
            }}>
              {reviewQueueCount}
            </span>
          </button>

          <div className="filter-group">
            <label htmlFor="tool-filter">Herramienta:</label>
            <select
              id="tool-filter"
              value={selectedTool}
              onChange={(e) => setSelectedTool(e.target.value)}
              disabled={reviewQueueActive}
            >
              <option value="all">Todas las herramientas</option>
              {distinctTools.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>

          <div className="filter-group">
            <label htmlFor="type-filter">Tipo de hallazgo:</label>
            <select
              id="type-filter"
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              disabled={reviewQueueActive}
            >
              <option value="all">Todos los tipos</option>
              <option value="code">Código</option>
              <option value="dependency">Dependencia</option>
              <option value="secret">Secreto</option>
            </select>
          </div>

          <div className="filter-group">
            <label htmlFor="verdict-filter">Veredicto Triage:</label>
            <select
              id="verdict-filter"
              value={selectedVerdict}
              onChange={(e) => setSelectedVerdict(e.target.value)}
              disabled={reviewQueueActive}
            >
              <option value="all">Todos los veredictos</option>
              <option value="verdadero">Verdadero</option>
              <option value="falso">Falso positivo</option>
              <option value="incierto">Incierto</option>
            </select>
          </div>

          <div className="filter-group">
            <label htmlFor="remediation-filter">Remediación (F6):</label>
            <select
              id="remediation-filter"
              value={selectedRemStatus}
              onChange={(e) => setSelectedRemStatus(e.target.value)}
              disabled={reviewQueueActive}
            >
              <option value="all">Todos los estados</option>
              <option value="open">Abierto</option>
              <option value="patch_proposed">Parche propuesto</option>
              <option value="verified">Verificado</option>
              <option value="discarded">Descartado</option>
              <option value="approved">Aprobado</option>
              <option value="rejected">Rechazado</option>
            </select>
          </div>

          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.85rem', color: 'var(--muted-color)' }}>
              Mostrando {filteredFindings.length} de {findings.length} hallazgos
            </span>
          </div>
        </div>
      </section>

      {/* Findings Table */}
      <section className="card">
        <div style={{ overflowX: 'auto' }}>
          {filteredFindings.length > 0 ? (
            <table className="findings-table">
              <thead>
                <tr>
                  <th style={{ width: '110px' }}>Severidad</th>
                  <th>Problema / Regla</th>
                  <th>Archivo / Línea</th>
                  <th>CWE</th>
                  <th>OWASP</th>
                  <th>Detectado por</th>
                  <th>Triage (F5)</th>
                  <th>Remediación (F6)</th>
                  <th style={{ textAlign: 'right' }}>Acción</th>
                </tr>
              </thead>
              <tbody>
                {filteredFindings.map((item) => {
                  const tools = item.tools || ['semgrep'];
                  const cweStr = Array.isArray(item.cwe) ? item.cwe.join(', ') : item.cwe || 'CWE-Other';
                  const verdict = item.triage?.verdict || (item.status === 'false_positive' ? 'falso' : 'verdadero');
                  const vClass = verdict === 'verdadero' ? 'completed' : verdict === 'falso' ? 'queued' : 'running';
                  const remStatus = (item.remediation?.status || 'open').toLowerCase();
                  const remStyles = {
                    verified: { bg: '#166534', color: '#86efac', text: 'VERIFICADO' },
                    approved: { bg: '#065f46', color: '#6ee7b7', text: 'APROBADO' },
                    discarded: { bg: '#991b1b', color: '#fca5a5', text: 'DESCARTADO' },
                    rejected: { bg: '#881337', color: '#fda4af', text: 'RECHAZADO' },
                    patch_proposed: { bg: '#854d0e', color: '#fde047', text: 'PROPUESTO' },
                    open: { bg: '#334155', color: '#cbd5e1', text: 'ABIERTO' },
                  };
                  const remBadge = remStyles[remStatus] || remStyles.open;
                  return (
                    <tr key={item.id}>
                      <td>
                        <span className={`sev-badge ${item.severity || 'low'}`}>
                          {(item.severity || 'low').toUpperCase()}
                        </span>
                      </td>
                      <td>
                        <strong>{item.title || item.rule}</strong>
                        <div style={{ fontSize: '0.78rem', color: 'var(--muted-color)' }}>
                          <code>{item.rule}</code>
                        </div>
                      </td>
                      <td>
                        <code>{item.file}:{item.line || '?'}</code>
                      </td>
                      <td>
                        <span className="meta-tag">{cweStr}</span>
                      </td>
                      <td style={{ fontSize: '0.82rem' }}>
                        {item.owasp || 'A05:2021'}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
                          {tools.map((t) => (
                            <span key={t} className="tool-tag">{t}</span>
                          ))}
                        </div>
                      </td>
                      <td>
                        <span className={`status status-${vClass}`} style={{ fontSize: '0.75rem', fontWeight: 600 }}>
                          {verdict.toUpperCase()}
                        </span>
                        <div style={{ fontSize: '0.7rem', color: 'var(--muted-color)' }}>
                          {item.triage?.decided_by || 'regla'}
                        </div>
                      </td>
                      <td>
                        <span style={{
                          background: remBadge.bg,
                          color: remBadge.color,
                          padding: '0.15rem 0.5rem',
                          borderRadius: '4px',
                          fontSize: '0.72rem',
                          fontWeight: 700,
                          textTransform: 'uppercase',
                          display: 'inline-block',
                        }}>
                          {remBadge.text}
                        </span>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          type="button"
                          className="btn-secondary"
                          style={{ padding: '0.35rem 0.75rem', fontSize: '0.8rem' }}
                          onClick={() => setDetailFinding(item)}
                        >
                          Ver detalle
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          ) : (
            <div className="empty-state" style={{ padding: '4rem 1rem' }}>
              <p>
                {findings.length === 0
                  ? 'No hay hallazgos para mostrar. Iniciá un análisis de repositorio.'
                  : 'No se encontraron hallazgos con los filtros seleccionados.'}
              </p>
              {hasActiveFilters && (
                <button
                  type="button"
                  className="btn-secondary"
                  style={{ marginTop: '0.5rem' }}
                  onClick={clearFilters}
                >
                  Restablecer filtros
                </button>
              )}
            </div>
          )}
        </div>
      </section>

      {/* Detail Modal */}
      {detailFinding && (
        <FindingDetailModal
          finding={detailFinding}
          onClose={() => setDetailFinding(null)}
          onTriageDecision={async (findingId, decisionData) => {
            if (onTriageDecision) {
              const res = await onTriageDecision(findingId, decisionData);
              if (res?.finding) {
                setDetailFinding(res.finding);
              }
              return res;
            }
          }}
          onProposeFix={async (findingId) => {
            if (onProposeFix) {
              const res = await onProposeFix(findingId);
              if (res?.finding) {
                setDetailFinding(res.finding);
              }
              return res;
            }
          }}
          onReviewRemediation={async (findingId, reviewData) => {
            if (onReviewRemediation) {
              const res = await onReviewRemediation(findingId, reviewData);
              if (res?.finding) {
                setDetailFinding(res.finding);
              }
              return res;
            }
          }}
        />
      )}
    </div>
  );
}
