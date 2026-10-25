import React, { useState, useEffect } from 'react';
import api from '../api/client';

export default function ToolsTab() {
  const [tools, setTools] = useState([]);
  const [loading, setLoading] = useState(false);
  const [runningBench, setRunningBench] = useState(false);
  const [error, setError] = useState(null);
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [languageFilter, setLanguageFilter] = useState('all');
  const [selectedToolEvidence, setSelectedToolEvidence] = useState(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getToolBenchmarkStatus();
      setTools(res.tools || []);
    } catch (err) {
      setError('No se pudieron cargar los datos de benchmark de herramientas: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRunAll = async () => {
    setRunningBench(true);
    setError(null);
    try {
      const res = await api.runToolBenchmark();
      setTools(res.tools || []);
    } catch (err) {
      setError('Error al ejecutar la corrida de benchmark: ' + err.message);
    } finally {
      setRunningBench(false);
    }
  };

  // Filtrado
  const filteredTools = tools.filter((tool) => {
    if (categoryFilter !== 'all' && tool.category !== categoryFilter) return false;
    if (languageFilter !== 'all') {
      const langs = tool.languages || [];
      if (!langs.includes('all') && !langs.includes(languageFilter)) return false;
    }
    return true;
  });

  const categories = ['all', 'sast', 'secrets', 'sca', 'iac', 'ci', 'licencias', 'sbom', 'reputacion'];
  const languages = ['all', 'python', 'javascript', 'go', 'java', 'terraform', 'dockerfile', 'github-actions'];

  return (
    <div className="tab-pane active tools-tab">
      <div className="section-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.25rem' }}>
            <h2 style={{ margin: 0 }}>Catálogo & Benchmark de Herramientas</h2>
            <span className="badge" style={{ background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8', border: '1px solid rgba(56, 189, 248, 0.3)', padding: '0.2rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem', fontWeight: 600 }}>
              📊 Evaluación Independiente
            </span>
          </div>
          <p className="section-desc" style={{ maxWidth: '850px', margin: 0 }}>
            Medición empírica y honesta de precisión, recall, FPR, tiempos y contribución marginal de cada herramienta sobre datasets de referencia con commits fijados. Configuración activa en <code>backend/tools/defaults.yml</code>.
          </p>
        </div>

        <button
          className="btn btn-primary"
          onClick={handleRunAll}
          disabled={runningBench || loading}
          style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.65rem 1.25rem', fontWeight: 600 }}
        >
          {runningBench ? 'Evaluando...' : '▶ Ejecutar Benchmark de Herramientas'}
        </button>
      </div>

      {error && (
        <div className="alert alert-danger" style={{ marginTop: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>{error}</span>
          <button className="btn-close" onClick={() => setError(null)}>✕</button>
        </div>
      )}

      {/* Barra de Filtros */}
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', margin: '1.25rem 0', padding: '1rem', background: 'var(--card-bg, #1e293b)', borderRadius: '8px', border: '1px solid var(--border-color, #334155)', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <label style={{ fontSize: '0.85rem', color: 'var(--text-muted, #94a3b8)', fontWeight: 600 }}>Categoría:</label>
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            style={{ padding: '0.4rem 0.75rem', borderRadius: '4px', background: '#0f172a', border: '1px solid #334155', color: '#fff', fontSize: '0.85rem' }}
          >
            {categories.map((c) => (
              <option key={c} value={c}>{c.toUpperCase()}</option>
            ))}
          </select>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <label style={{ fontSize: '0.85rem', color: 'var(--text-muted, #94a3b8)', fontWeight: 600 }}>Lenguaje:</label>
          <select
            value={languageFilter}
            onChange={(e) => setLanguageFilter(e.target.value)}
            style={{ padding: '0.4rem 0.75rem', borderRadius: '4px', background: '#0f172a', border: '1px solid #334155', color: '#fff', fontSize: '0.85rem' }}
          >
            {languages.map((l) => (
              <option key={l} value={l}>{l === 'all' ? 'TODOS' : l}</option>
            ))}
          </select>
        </div>

        <div style={{ marginLeft: 'auto', fontSize: '0.8rem', color: 'var(--text-muted, #94a3b8)' }}>
          Mostrando <strong>{filteredTools.length}</strong> de {tools.length} herramientas
        </div>
      </div>

      {/* Tabla de Herramientas */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted, #94a3b8)' }}>
          Cargando métricas de benchmark...
        </div>
      ) : filteredTools.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '3rem', background: 'var(--card-bg, #1e293b)', borderRadius: '8px' }}>
          <p style={{ color: 'var(--text-muted, #94a3b8)', margin: 0 }}>No hay herramientas que coincidan con los filtros seleccionados.</p>
        </div>
      ) : (
        <div style={{ overflowX: 'auto', background: 'var(--card-bg, #1e293b)', borderRadius: '8px', border: '1px solid var(--border-color, #334155)' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-color, #334155)', color: 'var(--text-muted, #94a3b8)' }}>
                <th style={{ padding: '0.85rem' }}>Herramienta</th>
                <th style={{ padding: '0.85rem' }}>Categoría</th>
                <th style={{ padding: '0.85rem' }}>Lenguajes</th>
                <th style={{ padding: '0.85rem' }}>Recall</th>
                <th style={{ padding: '0.85rem' }}>Precisión</th>
                <th style={{ padding: '0.85rem' }}>FPR</th>
                <th style={{ padding: '0.85rem' }}>F1-Score</th>
                <th style={{ padding: '0.85rem' }}>Tiempo Mediano</th>
                <th style={{ padding: '0.85rem' }}>TP Únicos</th>
                <th style={{ padding: '0.85rem' }}>Estado</th>
                <th style={{ padding: '0.85rem', textAlign: 'right' }}>Evidencia</th>
              </tr>
            </thead>
            <tbody>
              {filteredTools.map((t) => {
                const isRecom = t.status === 'recomendada';
                const isOp = t.status === 'opcional';
                const statusColor = isRecom ? '#22c55e' : isOp ? '#38bdf8' : '#ef4444';
                const statusBg = isRecom ? 'rgba(34, 197, 94, 0.15)' : isOp ? 'rgba(56, 189, 248, 0.15)' : 'rgba(239, 68, 68, 0.15)';

                return (
                  <tr key={t.tool_id} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                    <td style={{ padding: '0.85rem', fontWeight: 600, color: '#f8fafc' }}>
                      {t.tool_id}
                    </td>
                    <td style={{ padding: '0.85rem', textTransform: 'uppercase', fontSize: '0.75rem', color: '#94a3b8' }}>
                      {t.category}
                    </td>
                    <td style={{ padding: '0.85rem', fontSize: '0.8rem', color: 'var(--text-muted, #94a3b8)' }}>
                      {(t.languages || []).join(', ')}
                    </td>
                    <td style={{ padding: '0.85rem' }}>
                      {t.is_comparable && t.recall !== null ? (
                        <span style={{ fontWeight: 600, color: t.recall >= 0.8 ? '#22c55e' : '#eab308' }}>
                          {(t.recall * 100).toFixed(0)}%
                        </span>
                      ) : (
                        <span style={{ color: '#64748b', fontStyle: 'italic', fontSize: '0.75rem' }}>No comparable</span>
                      )}
                    </td>
                    <td style={{ padding: '0.85rem' }}>
                      {t.is_comparable && t.precision !== null ? (
                        <span style={{ fontWeight: 600, color: t.precision >= 0.7 ? '#22c55e' : '#eab308' }}>
                          {(t.precision * 100).toFixed(0)}%
                        </span>
                      ) : (
                        <span style={{ color: '#64748b', fontStyle: 'italic', fontSize: '0.75rem' }}>No comparable</span>
                      )}
                    </td>
                    <td style={{ padding: '0.85rem' }}>
                      {t.fpr !== null && t.fpr !== undefined ? (
                        <span style={{ color: t.fpr <= 0.05 ? '#22c55e' : '#ef4444' }}>
                          {(t.fpr * 100).toFixed(1)}%
                        </span>
                      ) : (
                        <span style={{ color: '#64748b', fontSize: '0.75rem' }}>N/A</span>
                      )}
                    </td>
                    <td style={{ padding: '0.85rem' }}>
                      {t.is_comparable && t.f1 !== null ? (
                        <span style={{ fontWeight: 600 }}>{t.f1.toFixed(2)}</span>
                      ) : (
                        <span style={{ color: '#64748b', fontSize: '0.75rem' }}>-</span>
                      )}
                    </td>
                    <td style={{ padding: '0.85rem', fontFamily: 'monospace' }}>
                      {t.median_time_ms} ms
                    </td>
                    <td style={{ padding: '0.85rem' }}>
                      <span className="badge" style={{ background: 'rgba(255,255,255,0.06)', padding: '0.2rem 0.5rem', borderRadius: '4px' }}>
                        +{t.unique_tp || 0}
                      </span>
                    </td>
                    <td style={{ padding: '0.85rem' }}>
                      <span className="badge" style={{ background: statusBg, color: statusColor, padding: '0.25rem 0.6rem', borderRadius: '4px', fontWeight: 600, fontSize: '0.75rem' }}>
                        {t.status.toUpperCase()}
                      </span>
                    </td>
                    <td style={{ padding: '0.85rem', textAlign: 'right' }}>
                      <button
                        className="btn btn-sm btn-outline"
                        onClick={() => setSelectedToolEvidence(t)}
                        style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem' }}
                      >
                        JSON Verdad
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Modal de Detalle de Evidencia JSON */}
      {selectedToolEvidence && (
        <div className="modal-backdrop" style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '1rem' }}>
          <div className="modal-content" style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '12px', width: '100%', maxWidth: '600px', maxHeight: '85vh', overflowY: 'auto', padding: '1.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ margin: 0 }}>Evidencia de Benchmark: {selectedToolEvidence.tool_id}</h3>
              <button onClick={() => setSelectedToolEvidence(null)} style={{ background: 'none', border: 'none', color: '#94a3b8', fontSize: '1.5rem', cursor: 'pointer' }}>✕</button>
            </div>
            <p style={{ fontSize: '0.85rem', color: '#94a3b8', margin: '0 0 1rem 0' }}>
              {selectedToolEvidence.notes}
            </p>
            <pre style={{ background: '#0f172a', padding: '1rem', borderRadius: '6px', fontSize: '0.75rem', overflowX: 'auto', color: '#38bdf8' }}>
              {JSON.stringify(selectedToolEvidence, null, 2)}
            </pre>
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '1rem' }}>
              <button className="btn btn-primary" onClick={() => setSelectedToolEvidence(null)}>Cerrar</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
