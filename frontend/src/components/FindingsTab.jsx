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
      <section className="card" style={{ marginBottom: '16px', padding: '16px 20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
          <div>
            <span className="eyebrow">RESUMEN CLICABLE DE HALLAZGOS</span>
            <p style={{ margin: '2px 0 0', fontSize: '13px', color: 'var(--text-muted)' }}>
              Hacé clic en cualquier severidad o categoría OWASP para filtrar la tabla automáticamente.
            </p>
          </div>
          {hasActiveFilters && (
            <button
              type="button"
              className="btn-secondary"
              style={{ height: '30px', padding: '0 12px', fontSize: '12px' }}
              onClick={clearFilters}
            >
              Limpiar filtros
            </button>
          )}
        </div>

        {/* Severities row */}
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '10px' }}>
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
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', alignItems: 'center' }}>
            <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginRight: '4px' }}>OWASP:</span>
            {owaspCounts.map(([catKey, count]) => {
              const isSelected = activeFilterOwasp === catKey;
              return (
                <button
                  key={catKey}
                  type="button"
                  className={`summary-pill ${isSelected ? 'active-filter' : ''}`}
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
      <section className="card" style={{ marginBottom: '16px', padding: '14px 20px' }}>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => setReviewQueueActive(!reviewQueueActive)}
            style={{
              borderColor: reviewQueueActive ? 'var(--amber)' : 'var(--border-medium)',
              background: reviewQueueActive ? 'var(--amber-bg)' : 'transparent',
              color: reviewQueueActive ? 'var(--amber)' : 'var(--text-main)',
              fontWeight: 600,
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <span>Cola Por revisar</span>
            <span style={{
              background: reviewQueueCount > 0 ? 'var(--amber)' : 'var(--border-medium)',
              color: reviewQueueCount > 0 ? '#ffffff' : 'var(--text-secondary)',
              borderRadius: '999px',
              padding: '1px 7px',
              fontSize: '11px',
              fontWeight: 700,
            }}>
              {reviewQueueCount}
            </span>
          </button>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <label htmlFor="tool-filter" style={{ whiteSpace: 'nowrap' }}>Herramienta:</label>
            <select
              id="tool-filter"
              value={selectedTool}
              onChange={(e) => setSelectedTool(e.target.value)}
              disabled={reviewQueueActive}
              className="custom-select"
              style={{ width: 'auto', minWidth: '150px' }}
            >
              <option value="all">Todas</option>
              {distinctTools.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <label htmlFor="type-filter" style={{ whiteSpace: 'nowrap' }}>Tipo:</label>
            <select
              id="type-filter"
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              disabled={reviewQueueActive}
              className="custom-select"
              style={{ width: 'auto', minWidth: '130px' }}
            >
              <option value="all">Todos los tipos</option>
              <option value="code">Código</option>
              <option value="dependency">Dependencia</option>
              <option value="secret">Secreto</option>
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <label htmlFor="verdict-filter" style={{ whiteSpace: 'nowrap' }}>Triage:</label>
            <select
              id="verdict-filter"
              value={selectedVerdict}
              onChange={(e) => setSelectedVerdict(e.target.value)}
              disabled={reviewQueueActive}
              className="custom-select"
              style={{ width: 'auto', minWidth: '130px' }}
            >
              <option value="all">Todos</option>
              <option value="verdadero">Verdadero</option>
              <option value="falso">Falso positivo</option>
              <option value="incierto">Incierto</option>
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <label htmlFor="remediation-filter" style={{ whiteSpace: 'nowrap' }}>Remediación:</label>
            <select
              id="remediation-filter"
              value={selectedRemStatus}
              onChange={(e) => setSelectedRemStatus(e.target.value)}
              disabled={reviewQueueActive}
              className="custom-select"
              style={{ width: 'auto', minWidth: '140px' }}
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

          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
              Mostrando <strong>{filteredFindings.length}</strong> de {findings.length} hallazgos
            </span>
          </div>
        </div>
      </section>

      {/* Findings Table */}
      <section className="card">
        <div className="table-wrap">
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
                  <th>Triage IA</th>
                  <th>Remediación</th>
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
                    verified: { bg: 'var(--emerald-bg)', color: 'var(--emerald)', border: 'var(--emerald-border)', text: 'VERIFICADO' },
                    approved: { bg: 'var(--emerald-bg)', color: 'var(--emerald)', border: 'var(--emerald-border)', text: 'APROBADO' },
                    discarded: { bg: 'var(--crimson-bg)', color: 'var(--crimson)', border: 'var(--crimson-border)', text: 'DESCARTADO' },
                    rejected: { bg: 'var(--crimson-bg)', color: 'var(--crimson)', border: 'var(--crimson-border)', text: 'RECHAZADO' },
                    patch_proposed: { bg: 'var(--amber-bg)', color: 'var(--amber)', border: 'var(--amber-border)', text: 'PROPUESTO' },
                    open: { bg: 'var(--bg-inset)', color: 'var(--text-secondary)', border: 'var(--border-medium)', text: 'ABIERTO' },
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
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                          <code>{item.rule}</code>
                        </div>
                      </td>
                      <td>
                        <code>{item.file}:{item.line || '?'}</code>
                      </td>
                      <td>
                        <span className="meta-tag">{cweStr}</span>
                      </td>
                      <td style={{ fontSize: '12px' }}>
                        {item.owasp || 'A05:2021'}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                          {tools.map((t) => (
                            <span key={t} className="tool-tag">{t}</span>
                          ))}
                        </div>
                      </td>
                      <td>
                        <span className={`status status-${vClass}`}>
                          {verdict.toUpperCase()}
                        </span>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                          {item.triage?.decided_by || 'regla'}
                        </div>
                      </td>
                      <td>
                        <span style={{
                          background: remBadge.bg,
                          color: remBadge.color,
                          border: `1px solid ${remBadge.border}`,
                          padding: '2px 7px',
                          borderRadius: '4px',
                          fontSize: '11px',
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
                          style={{ height: '30px', padding: '0 10px', fontSize: '12px' }}
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
            <div className="empty-state">
              <p>
                {findings.length === 0
                  ? 'No hay hallazgos para mostrar. Iniciá un análisis de repositorio.'
                  : 'No se encontraron hallazgos con los filtros seleccionados.'}
              </p>
              {hasActiveFilters && (
                <button
                  type="button"
                  className="btn-secondary"
                  style={{ marginTop: '10px' }}
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
