import React, { useState } from 'react';

function formatDelta(pts, invert = false, hasPrevious = true) {
  if (!hasPrevious) {
    return { text: '— sin corrida previa', cls: 'neutral' };
  }
  const num = Number(pts) || 0;
  if (Math.abs(num) < 0.05) {
    return { text: '— 0.0 pts', cls: 'neutral' };
  }
  const isPositive = num > 0;
  const isGood = invert ? !isPositive : isPositive;
  const sign = isPositive ? '+' : '';
  const arrow = isPositive ? '▲' : '▼';
  return {
    text: `${arrow} ${sign}${num.toFixed(1)} pts`,
    cls: isGood ? 'positive' : 'negative',
  };
}

export default function BenchmarkTab({
  benchmarkStatus,
  onRunBenchmark,
  isRunning,
  isLoading,
  error,
}) {
  const [featureName, setFeatureName] = useState('');
  const [saveBaseline, setSaveBaseline] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    onRunBenchmark({
      feature: featureName.trim() || undefined,
      saveAsBaseline: saveBaseline,
    });
  };

  const latestRun = benchmarkStatus?.latest_run;
  const baseline = benchmarkStatus?.baseline;
  const summary = latestRun?.summary || {};
  const comparison = latestRun?.comparison || {};
  const hasPrevious = Boolean(comparison.previous_run_id);

  const recallDelta = formatDelta(comparison.delta_recall_pts, false, hasPrevious);
  const fprDelta = formatDelta(comparison.delta_fpr_pts, true, hasPrevious);
  const precDelta = formatDelta(comparison.delta_precision_pts, false, hasPrevious);
  const f1Delta = formatDelta(comparison.delta_f1_pts, false, hasPrevious);

  return (
    <div className="tab-pane active">
      {/* Run Benchmark Card */}
      <section className="card" style={{ marginBottom: '1.5rem', padding: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem', marginBottom: '1rem' }}>
          <div>
            <p className="eyebrow">MEDICIÓN DE PRECISIÓN Y REGRESIÓN</p>
            <h2 style={{ margin: '0.25rem 0', fontSize: '1.25rem' }}>Ejecutar Suite de Benchmark</h2>
            <p className="muted" style={{ margin: 0, fontSize: '0.85rem' }}>
              Evalúa los escáneres contra repositorios de referencia con vulnerabilidades conocidas (ground truth).
            </p>
          </div>
          {latestRun && (
            <span className="text-muted" style={{ fontSize: '0.82rem' }}>
              Última corrida: <strong>{latestRun.date_formatted || latestRun.timestamp}</strong>
            </span>
          )}
        </div>

        <form onSubmit={handleSubmit} style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <input
            type="text"
            placeholder="Etiqueta de feature (ej: F4B - Separación de front y back)"
            value={featureName}
            onChange={(e) => setFeatureName(e.target.value)}
            disabled={isRunning}
            style={{ flex: '1', minWidth: '240px', padding: '0.5rem 0.85rem', background: 'var(--input-bg)', border: '1px solid var(--border-color)', borderRadius: '6px', color: 'var(--text-color)' }}
          />

          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={saveBaseline}
              onChange={(e) => setSaveBaseline(e.target.checked)}
              disabled={isRunning}
            />
            <span>Fijar como Baseline</span>
          </label>

          <button type="submit" className="btn-primary" disabled={isRunning}>
            {isRunning ? 'Ejecutando Benchmark...' : 'Iniciar Benchmark'}
          </button>
        </form>

        {isRunning && (
          <div style={{ marginTop: '1rem', padding: '0.75rem', background: 'rgba(56, 189, 248, 0.1)', border: '1px solid rgba(56, 189, 248, 0.3)', borderRadius: '6px' }}>
            <span className="status status-running" style={{ marginRight: '0.5rem' }}>En ejecución</span>
            <span>{benchmarkStatus?.message || 'Procesando suite de referencia...'} ({benchmarkStatus?.progress || 0}%)</span>
          </div>
        )}

        {error && (
          <div className="error-banner" style={{ marginTop: '1rem' }}>
            {error}
          </div>
        )}
      </section>

      {isLoading && !latestRun ? (
        <div className="empty-state">
          <p>Cargando datos de benchmark...</p>
        </div>
      ) : latestRun ? (
        <>
          {/* Global Metrics KPI Grid */}
          <section className="summary-grid" style={{ marginBottom: '1.5rem' }}>
            <div className="kpi-card">
              <span className="kpi-label">TPR / Recall Global</span>
              <strong className="kpi-num">
                {summary.avg_recall !== undefined ? `${(summary.avg_recall * 100).toFixed(1)}%` : '—'}
              </strong>
              <small className={`delta-tag ${recallDelta.cls}`}>{recallDelta.text}</small>
            </div>

            <div className="kpi-card">
              <span className="kpi-label">FPR Global</span>
              <strong className="kpi-num">
                {summary.avg_fpr !== undefined ? `${(summary.avg_fpr * 100).toFixed(1)}%` : '—'}
              </strong>
              <small className={`delta-tag ${fprDelta.cls}`}>{fprDelta.text}</small>
            </div>

            <div className="kpi-card">
              <span className="kpi-label">Precisión Global</span>
              <strong className="kpi-num">
                {summary.avg_precision !== undefined ? `${(summary.avg_precision * 100).toFixed(1)}%` : '—'}
              </strong>
              <small className={`delta-tag ${precDelta.cls}`}>{precDelta.text}</small>
            </div>

            <div className="kpi-card">
              <span className="kpi-label">F1-Score Global</span>
              <strong className="kpi-num">
                {summary.avg_f1_score !== undefined ? summary.avg_f1_score.toFixed(3) : '—'}
              </strong>
              <small className={`delta-tag ${f1Delta.cls}`}>{f1Delta.text}</small>
            </div>
          </section>

          {/* Reference Repositories Cards */}
          {latestRun.repositories && latestRun.repositories.length > 0 && (
            <section className="card" style={{ marginBottom: '1.5rem' }}>
              <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border-color)' }}>
                <p className="eyebrow">REPOSITORIOS DE REFERENCIA EVALUADOS</p>
                <h3 style={{ margin: '0.2rem 0', fontSize: '1.1rem' }}>Desempeño por Proyecto de Prueba</h3>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', padding: '1.25rem' }}>
                {latestRun.repositories.map((repo) => {
                  const m = repo.metrics || {};
                  return (
                    <div key={repo.id} className="repo-card">
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                        <strong style={{ fontSize: '1rem' }}>{repo.name}</strong>
                        <span className="meta-tag">{repo.type}</span>
                      </div>
                      <p style={{ margin: '0 0 0.75rem', fontSize: '0.8rem', color: 'var(--muted-color)' }}>
                        {repo.description}
                      </p>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontSize: '0.85rem' }}>
                        <div>Ground Truth: <strong>{repo.ground_truth_count}</strong></div>
                        <div>Detectados: <strong>{repo.findings_detected}</strong></div>
                        <div>Recall (TPR): <strong>{((m.recall || 0) * 100).toFixed(1)}%</strong></div>
                        <div>FPR: <strong>{((m.fpr || 0) * 100).toFixed(1)}%</strong></div>
                        <div>Precisión: <strong>{((m.precision || 0) * 100).toFixed(1)}%</strong></div>
                        <div>F1: <strong>{(m.f1_score || 0).toFixed(3)}</strong></div>
                      </div>
                      {repo.commit && (
                        <div style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: 'var(--muted-color)' }}>
                          Commit: <code>{repo.commit.slice(0, 8)}</code>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </section>
          )}

          {/* CWE Categories Breakdown Table */}
          {latestRun.cwe_categories && latestRun.cwe_categories.length > 0 && (
            <section className="card" style={{ marginBottom: '1.5rem' }}>
              <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border-color)' }}>
                <p className="eyebrow">DESGLOSE POR CATEGORÍA DE VULNERABILIDAD</p>
                <h3 style={{ margin: '0.2rem 0', fontSize: '1.1rem' }}>Matriz de CWE y Detecciones</h3>
              </div>
              <div style={{ overflowX: 'auto' }}>
                <table className="findings-table">
                  <thead>
                    <tr>
                      <th>CWE</th>
                      <th>Categoría / Nombre</th>
                      <th>Ground Truth</th>
                      <th>Detectados</th>
                      <th>TP</th>
                      <th>FP</th>
                      <th>FN</th>
                      <th>TPR (Recall)</th>
                      <th>FPR</th>
                      <th>Precisión</th>
                      <th>F1-Score</th>
                    </tr>
                  </thead>
                  <tbody>
                    {latestRun.cwe_categories.map((row) => (
                      <tr key={row.cwe}>
                        <td><code>{row.cwe}</code></td>
                        <td>{row.name}</td>
                        <td>{row.total_gt}</td>
                        <td>{row.detected}</td>
                        <td style={{ color: 'var(--success-color)' }}>{row.tp}</td>
                        <td style={{ color: row.fp > 0 ? 'var(--warning-color)' : 'var(--muted-color)' }}>{row.fp}</td>
                        <td style={{ color: row.fn > 0 ? 'var(--critical-color)' : 'var(--muted-color)' }}>{row.fn}</td>
                        <td><strong>{((row.recall || 0) * 100).toFixed(1)}%</strong></td>
                        <td>{((row.fpr || 0) * 100).toFixed(1)}%</td>
                        <td>{((row.precision || 0) * 100).toFixed(1)}%</td>
                        <td>{(row.f1_score || 0).toFixed(3)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {/* Individual Scanner Tools Evaluation Table */}
          {latestRun.tool_evaluations && latestRun.tool_evaluations.length > 0 && (
            <section className="card" style={{ marginBottom: '1.5rem' }}>
              <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border-color)' }}>
                <p className="eyebrow">EVALUACIÓN DE HERRAMIENTAS INDIVIDUALES</p>
                <h3 style={{ margin: '0.2rem 0', fontSize: '1.1rem' }}>Rendimiento Aislado por Escáner</h3>
              </div>
              <div style={{ overflowX: 'auto' }}>
                <table className="findings-table">
                  <thead>
                    <tr>
                      <th>Herramienta</th>
                      <th>TP</th>
                      <th>FP</th>
                      <th>FN</th>
                      <th>Total Detectados</th>
                      <th>Recall (TPR)</th>
                      <th>Precisión</th>
                      <th>FPR</th>
                    </tr>
                  </thead>
                  <tbody>
                    {latestRun.tool_evaluations.map((t) => (
                      <tr key={t.tool}>
                        <td><span className="tool-tag">{t.tool}</span></td>
                        <td style={{ color: 'var(--success-color)' }}>{t.true_positives}</td>
                        <td style={{ color: t.false_positives > 0 ? 'var(--warning-color)' : 'var(--muted-color)' }}>{t.false_positives}</td>
                        <td style={{ color: t.false_negatives > 0 ? 'var(--critical-color)' : 'var(--muted-color)' }}>{t.false_negatives}</td>
                        <td>{t.total_detected}</td>
                        <td><strong>{((t.recall || 0) * 100).toFixed(1)}%</strong></td>
                        <td>{((t.precision || 0) * 100).toFixed(1)}%</td>
                        <td>{((t.fpr || 0) * 100).toFixed(1)}%</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {/* Scanner Pairs Combined Table */}
          {latestRun.scanner_pairs && latestRun.scanner_pairs.length > 0 && (
            <section className="card">
              <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border-color)' }}>
                <p className="eyebrow">EVALUACIÓN DE PARES DE ESCÁNERES COMBINADOS</p>
                <h3 style={{ margin: '0.2rem 0', fontSize: '1.1rem' }}>Efecto de Cobertura Multi-Herramienta</h3>
              </div>
              <div style={{ overflowX: 'auto' }}>
                <table className="findings-table">
                  <thead>
                    <tr>
                      <th>Par de Escáneres</th>
                      <th>TP</th>
                      <th>FP</th>
                      <th>FN</th>
                      <th>Total Detectados</th>
                      <th>Recall (TPR)</th>
                      <th>Precisión</th>
                      <th>FPR</th>
                    </tr>
                  </thead>
                  <tbody>
                    {latestRun.scanner_pairs.map((p) => (
                      <tr key={p.pair_label}>
                        <td><strong>{p.pair_label}</strong></td>
                        <td style={{ color: 'var(--success-color)' }}>{p.true_positives}</td>
                        <td style={{ color: p.false_positives > 0 ? 'var(--warning-color)' : 'var(--muted-color)' }}>{p.false_positives}</td>
                        <td style={{ color: p.false_negatives > 0 ? 'var(--critical-color)' : 'var(--muted-color)' }}>{p.false_negatives}</td>
                        <td>{p.total_detected}</td>
                        <td><strong style={{ color: 'var(--accent-color)' }}>{((p.recall || 0) * 100).toFixed(1)}%</strong></td>
                        <td>{((p.precision || 0) * 100).toFixed(1)}%</td>
                        <td>{((p.fpr || 0) * 100).toFixed(1)}%</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {/* Multi-Model AI Triage Comparison Table (Feature 5) */}
          {latestRun.triage_benchmark && (
            <section className="card" style={{ marginTop: '1.5rem' }}>
              <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border-color)' }}>
                <p className="eyebrow" style={{ color: 'var(--primary, #6366f1)' }}>TRIAGE CON IA: COMPARATIVA MULTI-MODELO (F5)</p>
                <h3 style={{ margin: '0.2rem 0', fontSize: '1.1rem' }}>Efecto en la Tasa de Falsos Positivos (FPR)</h3>
                <p className="muted" style={{ margin: '0.25rem 0 0', fontSize: '0.85rem' }}>
                  Comparación de modelos (Gemini, OpenAI, Claude) evaluados con el mismo prompt estandarizado y contexto acotado.
                </p>
              </div>
              <div style={{ overflowX: 'auto' }}>
                <table className="findings-table">
                  <thead>
                    <tr>
                      <th>Modelo de IA</th>
                      <th>FPR Antes</th>
                      <th>FPR Después</th>
                      <th>Reducción FPR (pts)</th>
                      <th>FPs Eliminados</th>
                      <th>TPs Retenidos</th>
                      <th>Inciertos (Cola Humana)</th>
                      <th>Prompt Utilizado</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(latestRun.triage_benchmark.models_evaluated || []).map((m) => {
                      const deltaPts = m.delta_fpr_pts;
                      const isGood = deltaPts <= 0;
                      return (
                        <tr key={m.model_name}>
                          <td><strong>{m.model_name}</strong></td>
                          <td>{((m.fpr_before || 0) * 100).toFixed(1)}%</td>
                          <td style={{ color: 'var(--success-color)', fontWeight: 600 }}>
                            {((m.fpr_after || 0) * 100).toFixed(1)}%
                          </td>
                          <td style={{ color: isGood ? 'var(--success-color)' : 'var(--critical-color)', fontWeight: 700 }}>
                            {deltaPts > 0 ? `+${deltaPts}` : deltaPts} pts
                          </td>
                          <td style={{ color: 'var(--success-color)' }}>{m.false_positives_eliminated}</td>
                          <td>{m.true_positives_retained}</td>
                          <td style={{ color: 'var(--warning-color)' }}>{m.uncertain_sent_to_human_review}</td>
                          <td><span className="meta-tag">{m.standardized_prompt || 'TRIAGE_SYSTEM_PROMPT v1.0'}</span></td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </section>
          )}
        </>
      ) : (
        <div className="empty-state" style={{ padding: '4rem 1rem' }}>
          <p>No hay corridas de benchmark registradas aún.</p>
          <button type="button" className="btn-primary" onClick={handleSubmit} style={{ marginTop: '0.75rem' }}>
            Ejecutar primera corrida
          </button>
        </div>
      )}
    </div>
  );
}
