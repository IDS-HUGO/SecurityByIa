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
      <section className="card" style={{ marginBottom: '20px', padding: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px', marginBottom: '16px' }}>
          <div>
            <p className="eyebrow">MEDICIÓN DE PRECISIÓN Y REGRESIÓN</p>
            <h2 style={{ margin: '4px 0 0', fontSize: '18px' }}>Ejecutar Suite de Benchmark</h2>
            <p className="muted" style={{ margin: '4px 0 0', fontSize: '13px' }}>
              Evalúa los escáneres contra repositorios de referencia con vulnerabilidades conocidas (ground truth).
            </p>
          </div>
          {latestRun && (
            <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
              Última corrida: <strong style={{ color: 'var(--text-main)' }}>{latestRun.date_formatted || latestRun.timestamp}</strong>
            </span>
          )}
        </div>

        <form onSubmit={handleSubmit} style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
          <input
            type="text"
            placeholder="Etiqueta de la corrida (ej: Baseline de Producción, Regla OWASP v2.1)"
            value={featureName}
            onChange={(e) => setFeatureName(e.target.value)}
            disabled={isRunning}
            style={{ flex: '1', minWidth: '260px' }}
          />

          <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', cursor: 'pointer', color: 'var(--text-secondary)' }}>
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
          <div style={{ marginTop: '16px', padding: '12px 16px', background: 'var(--accent-soft)', border: '1px solid var(--accent-border)', borderRadius: '6px', color: 'var(--accent)' }}>
            <span className="status status-running" style={{ marginRight: '8px' }}>En ejecución</span>
            <span>{benchmarkStatus?.message || 'Procesando suite de referencia...'} ({benchmarkStatus?.progress || 0}%)</span>
          </div>
        )}

        {error && (
          <div className="error-banner" style={{ marginTop: '16px' }}>
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
          <section className="summary-grid" style={{ marginBottom: '20px' }}>
            <div className="kpi-card">
              <div style={{ width: '100%' }}>
                <span className="kpi-label">TPR / Recall Global</span>
                <strong className="kpi-num">
                  {summary.avg_recall !== undefined ? `${(summary.avg_recall * 100).toFixed(1)}%` : '—'}
                </strong>
                <span className={`delta-badge ${recallDelta.cls}`}>
                  {recallDelta.text}
                </span>
              </div>
            </div>

            <div className="kpi-card">
              <div style={{ width: '100%' }}>
                <span className="kpi-label">FPR Global (Falsos Positivos)</span>
                <strong className="kpi-num">
                  {summary.avg_fpr !== undefined ? `${(summary.avg_fpr * 100).toFixed(1)}%` : '—'}
                </strong>
                <span className={`delta-badge ${fprDelta.cls}`}>
                  {fprDelta.text}
                </span>
              </div>
            </div>

            <div className="kpi-card">
              <div style={{ width: '100%' }}>
                <span className="kpi-label">Precisión Global</span>
                <strong className="kpi-num">
                  {summary.avg_precision !== undefined ? `${(summary.avg_precision * 100).toFixed(1)}%` : '—'}
                </strong>
                <span className={`delta-badge ${precDelta.cls}`}>
                  {precDelta.text}
                </span>
              </div>
            </div>

            <div className="kpi-card">
              <div style={{ width: '100%' }}>
                <span className="kpi-label">F1-Score Global</span>
                <strong className="kpi-num">
                  {summary.avg_f1 !== undefined ? summary.avg_f1.toFixed(3) : '—'}
                </strong>
                <span className={`delta-badge ${f1Delta.cls}`}>
                  {f1Delta.text}
                </span>
              </div>
            </div>

            <div className="kpi-card">
              <div style={{ width: '100%' }}>
                <span className="kpi-label">Total Detecciones TP</span>
                <strong className="kpi-num" style={{ color: 'var(--emerald)' }}>
                  {summary.total_tp ?? '—'}
                </strong>
                <small className="kpi-sub">FP: {summary.total_fp ?? 0} · FN: {summary.total_fn ?? 0}</small>
              </div>
            </div>
          </section>

          {/* Repositories Cards Grid */}
          {latestRun.repositories && latestRun.repositories.length > 0 && (
            <section className="card" style={{ marginBottom: '20px' }}>
              <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)' }}>
                <p className="eyebrow">REPOSITORIOS DE REFERENCIA EVALUADOS</p>
                <h3 style={{ margin: '2px 0 0', fontSize: '16px' }}>Resultados por Dataset Ground Truth</h3>
              </div>
              <div className="bench-repos-grid">
                {latestRun.repositories.map((repo) => {
                  const m = repo.metrics || {};
                  return (
                    <div key={repo.repo_id || repo.name} className="repo-card">
                      <div className="repo-card-head">
                        <div>
                          <h4 className="repo-card-title">{repo.name || repo.repo_id}</h4>
                          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{repo.type || 'vulnerabilities.json'}</span>
                        </div>
                        <span className="repo-card-type">{repo.language || 'Multi'}</span>
                      </div>
                      <div className="repo-metrics-row">
                        <div>
                          <span className="metric-col-label">Ground Truth</span>
                          <strong className="metric-col-val">{repo.ground_truth_total || 0}</strong>
                        </div>
                        <div>
                          <span className="metric-col-label">Detectadas</span>
                          <strong className="metric-col-val" style={{ color: 'var(--accent)' }}>{repo.findings_detected || 0}</strong>
                        </div>
                      </div>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '12px', color: 'var(--text-secondary)' }}>
                        <div>Recall (TPR): <strong style={{ color: 'var(--text-main)' }}>{((m.recall || 0) * 100).toFixed(1)}%</strong></div>
                        <div>FPR: <strong style={{ color: 'var(--text-main)' }}>{((m.fpr || 0) * 100).toFixed(1)}%</strong></div>
                        <div>Precisión: <strong style={{ color: 'var(--text-main)' }}>{((m.precision || 0) * 100).toFixed(1)}%</strong></div>
                        <div>F1: <strong style={{ color: 'var(--text-main)' }}>{(m.f1_score || 0).toFixed(3)}</strong></div>
                      </div>
                      {repo.commit && (
                        <div style={{ marginTop: '8px', fontSize: '11px', color: 'var(--text-muted)', paddingTop: '6px', borderTop: '1px solid var(--border-subtle)' }}>
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
            <section className="card" style={{ marginBottom: '20px' }}>
              <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)' }}>
                <p className="eyebrow">DESGLOSE POR CATEGORÍA DE VULNERABILIDAD</p>
                <h3 style={{ margin: '2px 0 0', fontSize: '16px' }}>Matriz de CWE y Detecciones</h3>
              </div>
              <div className="table-wrap">
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
                        <td style={{ color: 'var(--emerald)', fontWeight: 600 }}>{row.tp}</td>
                        <td style={{ color: row.fp > 0 ? 'var(--amber)' : 'var(--text-muted)' }}>{row.fp}</td>
                        <td style={{ color: row.fn > 0 ? 'var(--crimson)' : 'var(--text-muted)' }}>{row.fn}</td>
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
            <section className="card" style={{ marginBottom: '20px' }}>
              <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)' }}>
                <p className="eyebrow">EVALUACIÓN DE HERRAMIENTAS INDIVIDUALES</p>
                <h3 style={{ margin: '2px 0 0', fontSize: '16px' }}>Rendimiento Aislado por Escáner</h3>
              </div>
              <div className="table-wrap">
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
                        <td style={{ color: 'var(--emerald)', fontWeight: 600 }}>{t.true_positives}</td>
                        <td style={{ color: t.false_positives > 0 ? 'var(--amber)' : 'var(--text-muted)' }}>{t.false_positives}</td>
                        <td style={{ color: t.false_negatives > 0 ? 'var(--crimson)' : 'var(--text-muted)' }}>{t.false_negatives}</td>
                        <td>{t.total_detected}</td>
                        <td><strong style={{ color: 'var(--accent)' }}>{((t.recall || 0) * 100).toFixed(1)}%</strong></td>
                        <td>{((t.precision || 0) * 100).toFixed(1)}%</td>
                        <td>{((t.fpr || 0) * 100).toFixed(1)}%</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {/* Pair Evaluation Table */}
          {latestRun.pair_evaluations && latestRun.pair_evaluations.length > 0 && (
            <section className="card" style={{ marginBottom: '20px' }}>
              <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)' }}>
                <p className="eyebrow">EVALUACIÓN COMBINADA POR PARES DE ESCÁNERES</p>
                <h3 style={{ margin: '2px 0 0', fontSize: '16px' }}>Matriz de Cobertura Multi-Herramienta</h3>
              </div>
              <div className="table-wrap">
                <table className="findings-table">
                  <thead>
                    <tr>
                      <th>Par de Herramientas</th>
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
                    {latestRun.pair_evaluations.map((p) => (
                      <tr key={p.pair}>
                        <td><code>{p.pair}</code></td>
                        <td style={{ color: 'var(--emerald)', fontWeight: 600 }}>{p.true_positives}</td>
                        <td style={{ color: p.false_positives > 0 ? 'var(--amber)' : 'var(--text-muted)' }}>{p.false_positives}</td>
                        <td style={{ color: p.false_negatives > 0 ? 'var(--crimson)' : 'var(--text-muted)' }}>{p.false_negatives}</td>
                        <td>{p.total_detected}</td>
                        <td><strong style={{ color: 'var(--accent)' }}>{((p.recall || 0) * 100).toFixed(1)}%</strong></td>
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
            <section className="card" style={{ marginTop: '20px' }}>
              <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)' }}>
                <p className="eyebrow" style={{ color: 'var(--accent)' }}>TRIAGE ASISTIDO POR IA: COMPARATIVA MULTI-MODELO</p>
                <h3 style={{ margin: '2px 0 0', fontSize: '16px' }}>Efecto en la Tasa de Falsos Positivos (FPR)</h3>
                <p className="muted" style={{ margin: '4px 0 0', fontSize: '13px' }}>
                  Comparación de modelos (Gemini, OpenAI, Claude) evaluados con el mismo prompt estandarizado y contexto acotado.
                </p>
              </div>
              <div className="table-wrap">
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
                          <td style={{ color: 'var(--emerald)', fontWeight: 600 }}>
                            {((m.fpr_after || 0) * 100).toFixed(1)}%
                          </td>
                          <td style={{ color: isGood ? 'var(--emerald)' : 'var(--crimson)', fontWeight: 700 }}>
                            {deltaPts > 0 ? `+${deltaPts}` : deltaPts} pts
                          </td>
                          <td style={{ color: 'var(--emerald)' }}>{m.false_positives_eliminated}</td>
                          <td>{m.true_positives_retained}</td>
                          <td style={{ color: 'var(--amber)', fontWeight: 600 }}>{m.uncertain_sent_to_human_review}</td>
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
        <div className="empty-state">
          <p>No hay corridas de benchmark registradas aún.</p>
          <button type="button" className="btn-primary" onClick={handleSubmit} style={{ marginTop: '12px' }}>
            Ejecutar primera corrida
          </button>
        </div>
      )}
    </div>
  );
}
