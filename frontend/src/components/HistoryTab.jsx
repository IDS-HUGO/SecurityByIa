import React, { useMemo, useState } from 'react';
import api from '../api/client';

const REMEDIATION_LABEL = {
  open: 'Abierto',
  patch_proposed: 'Parche propuesto',
  verified: 'Verificado',
  discarded: 'Descartado',
  approved: 'Aprobado',
  rejected: 'Rechazado',
};

function repoKey(item) {
  return item?.repository?.url || '(sin url)';
}

function repoLabel(item) {
  return item?.repository?.name || item?.repository?.url || '(sin repositorio)';
}function shaShort(item) {
  const sha = item?.repository?.commit;
  return sha ? String(sha).slice(0, 10) : 'sin SHA';
}

function FindingRow({ finding }) {
  return (
    <tr>
      <td>{finding.id}</td>
      <td>{finding.title || finding.rule || 'Hallazgo'}</td>
      <td><span className={`sev-badge ${finding.severity || 'low'}`}>{finding.severity || 'n/d'}</span></td>
      <td><code style={{ fontSize: '12px' }}>{finding.file || 'n/d'}{finding.line ? `:${finding.line}` : ''}</code></td>
      <td>{REMEDIATION_LABEL[(finding.remediation?.status) || 'open'] || 'Abierto'}</td>
    </tr>
  );
}

function FindingsTable({ findings }) {
  if (!findings || findings.length === 0) {
    return <p className="muted" style={{ fontSize: '13px' }}>Ninguno.</p>;
  }
  return (
    <div className="table-wrap">
      <table className="findings-table">
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
          {findings.map((finding) => <FindingRow key={finding.id} finding={finding} />)}
        </tbody>
      </table>
    </div>
  );
}

export default function HistoryTab({ recentAnalyses, onLoadAnalysis }) {
  const [baseId, setBaseId] = useState('');
  const [targetId, setTargetId] = useState('');
  const [comparison, setComparison] = useState(null);
  const [error, setError] = useState(null);
  const [isComparing, setIsComparing] = useState(false);

  // Agrupar el historial por repositorio (los items ya traen repository.url/name).
  const repoGroups = useMemo(() => {
    const groups = new Map();
    for (const item of recentAnalyses || []) {
      const key = repoKey(item);
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(item);
    }
    return Array.from(groups.entries())
      .map(([url, items]) => ({ url, items }))
      .filter((group) => group.items.length >= 2); // comparar exige ≥2 análisis
  }, [recentAnalyses]);

  const handleCompare = async () => {
    setError(null);
    setComparison(null);
    if (!baseId || !targetId) {
      setError('Seleccioná los dos análisis a comparar (base anterior y target actual).');
      return;
    }
    if (baseId === targetId) {
      setError('Los dos análisis deben ser distintos.');
      return;
    }
    setIsComparing(true);
    try {
      const data = await api.compareAnalyses(baseId, targetId);
      setComparison(data);
    } catch (err) {
      setError(err.message || 'Error al comparar los análisis');
    } finally {
      setIsComparing(false);
    }
  };

  return (
    <div className="tab-pane active">
      <section className="card" style={{ padding: '20px' }}>
        <div style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '14px', marginBottom: '16px' }}>
          <p className="eyebrow">CONTROL 6 — INVENTARIO</p>
          <h2 style={{ margin: '4px 0 0', fontSize: '18px' }}>Historial por repositorio</h2>
          <p className="muted" style={{ margin: '4px 0 0', fontSize: '13px' }}>
            Compará dos análisis del mismo repositorio para revisar si los hallazgos de auditorías anteriores se cerraron:
            nuevos, corregidos y persistentes (huella regla + archivo + línea).
          </p>
        </div>

        {repoGroups.length === 0 ? (
          <div className="empty-state">
            <p>Todavía no hay ningún repositorio con al menos dos análisis en el historial.</p>
          </div>
        ) : (
          <>
            {/* Historial agrupado por repo */}
            {repoGroups.map((group) => (
              <div key={group.url} style={{ marginBottom: '18px' }}>
                <h3 style={{ fontSize: '14px', margin: '0 0 6px' }}>{repoLabel(group.items[0])} <span className="muted" style={{ fontSize: '12px' }}>— {group.url}</span></h3>
                <div className="table-wrap">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Análisis</th>
                        <th>Fecha</th>
                        <th>SHA</th>
                        <th>Resumen</th>
                        <th>Comparar como</th>
                        <th></th>
                      </tr>
                    </thead>
                    <tbody>
                      {group.items.map((item) => (
                        <tr key={item.analysis_id}>
                          <td><code style={{ fontSize: '11px' }}>{String(item.analysis_id).slice(0, 8)}</code></td>
                          <td>{item.created_at || 'n/d'}</td>
                          <td><code style={{ fontSize: '11px' }}>{shaShort(item)}</code></td>
                          <td style={{ fontSize: '12px' }}>
                            {`Total ${item.summary?.total ?? 'n/d'} · C ${item.summary?.critical ?? 0} · A ${item.summary?.high ?? 0} · M ${item.summary?.medium ?? 0} · B ${item.summary?.low ?? 0}`}
                          </td>
                          <td>
                            <div style={{ display: 'flex', gap: '12px', fontSize: '12px' }}>
                              <label>
                                <input
                                  type="radio"
                                  name={`base-${group.url}`}
                                  checked={baseId === item.analysis_id}
                                  onChange={() => setBaseId(item.analysis_id)}
                                />{' '}Base
                              </label>
                              <label>
                                <input
                                  type="radio"
                                  name={`target-${group.url}`}
                                  checked={targetId === item.analysis_id}
                                  onChange={() => setTargetId(item.analysis_id)}
                                />{' '}Target
                              </label>
                            </div>
                          </td>
                          <td>
                            <button
                              type="button"
                              className="btn-icon"
                              title={`Cargar análisis ${String(item.analysis_id).slice(0, 8)}`}
                              onClick={() => onLoadAnalysis && onLoadAnalysis(item.analysis_id)}
                            >
                              ↗
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ))}

            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginTop: '8px' }}>
              <button type="button" className="btn-primary" onClick={handleCompare} disabled={isComparing}>
                {isComparing ? 'Comparando…' : 'Comparar análisis'}
              </button>
              <span className="muted" style={{ fontSize: '12px' }}>
                {baseId || targetId
                  ? `Base: ${baseId ? String(baseId).slice(0, 8) : '—'} · Target: ${targetId ? String(targetId).slice(0, 8) : '—'}`
                  : 'Base = análisis anterior · Target = análisis actual.'}
              </span>
            </div>
          </>
        )}

        {error && (
          <div style={{ marginTop: '14px', padding: '10px 14px', borderRadius: '8px', background: 'var(--crimson-bg)', border: '1px solid var(--crimson-border)', color: 'var(--crimson)', fontSize: '13px' }}>
            {error}
          </div>
        )}

        {comparison && (
          <div style={{ marginTop: '20px', paddingTop: '16px', borderTop: '1px solid var(--border-strong)' }}>
            <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', marginBottom: '12px', fontSize: '13px' }}>
              <span><strong>Base:</strong> {String(comparison.base?.analysis_id || '').slice(0, 8)} · {comparison.base?.branch || 'sin rama'} · <code>{comparison.base?.commit ? String(comparison.base.commit).slice(0, 10) : 'sin SHA'}</code></span>
              <span><strong>Target:</strong> {String(comparison.target?.analysis_id || '').slice(0, 8)} · {comparison.target?.branch || 'sin rama'} · <code>{comparison.target?.commit ? String(comparison.target.commit).slice(0, 10) : 'sin SHA'}</code></span>
              <span className="delta-badge positive"><strong>+{comparison.counts?.new ?? 0}</strong> nuevos</span>
              <span className="delta-badge neutral"><strong>{comparison.counts?.persistent ?? 0}</strong> persistentes</span>
              <span className="delta-badge negative"><strong>−{comparison.counts?.fixed ?? 0}</strong> corregidos</span>
            </div>
            <p className="muted" style={{ fontSize: '12px', marginTop: 0 }}>{comparison.note}</p>

            <h3 style={{ fontSize: '14px', margin: '12px 0 6px' }}>Nuevos (solo en target)</h3>
            <FindingsTable findings={comparison.new} />

            <h3 style={{ fontSize: '14px', margin: '12px 0 6px' }}>Corregidos (solo en base)</h3>
            <FindingsTable findings={comparison.fixed} />

            <h3 style={{ fontSize: '14px', margin: '12px 0 6px' }}>Persistentes (en ambos)</h3>
            <FindingsTable findings={comparison.persistent} />
          </div>
        )}
      </section>
    </div>
  );
}
