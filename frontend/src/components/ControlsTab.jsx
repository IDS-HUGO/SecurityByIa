import React, { useState, useEffect, useMemo } from 'react';
import api from '../api/client';

const CRITICIDAD_LABEL = {
  CRITICO: 'Crítico',
  ALTO: 'Alto',
  MEDIO: 'Medio',
  COMPLEMENTARIO: 'Complementario',
};

// Controles no automatizables que requieren ficha de evidencia manual
const MANUAL_EVIDENCE_CONTROLS = ['4', 'C1', 'C6', 'C9', 'C12'];

const EVIDENCE_GUIDANCE = {
  '4': 'Prueba de que se dispara la alerta: Captura de pantalla o registro del log de SIEM / CloudWatch / alerta emitida tras registrar 5 o más intentos fallidos en 5 minutos.',
  'C1': 'MFA en IdP / paneles: Reporte de configuración de políticas de acceso condicional en el proveedor de identidad (Okta, Azure AD, Auth0) exigiendo MFA obligatorio.',
  'C6': 'Prueba de restauración: Informe técnico, ticket o acta del simulacro periódico de restauración exitosa de bases de datos desde respaldo.',
  'C9': 'MFA del root en la nube: Captura de pantalla de la consola AWS IAM mostrando MFA activado en la cuenta root y configuración de CloudTrail multirregión.',
  'C12': 'Términos del proveedor de IA: Contrato DPA firmado o términos oficiales del proveedor acreditando la política de retención cero (Zero Data Retention) y no entrenamiento.',
};

function EstadoBadge({ estado }) {
  const cls = {
    'cumple': 'ctl-badge cumple',
    'parcial': 'ctl-badge parcial',
    'no cumple': 'ctl-badge no-cumple',
    'no aplica': 'ctl-badge no-aplica',
    'requiere evidencia': 'ctl-badge no-evaluado',
    'no_evaluado': 'ctl-badge no-evaluado',
    'descartado': 'ctl-badge no-evaluado',
  }[estado] || 'ctl-badge no-evaluado';
  const label = {
    'no cumple': 'No cumple',
    'no aplica': 'No aplica',
    'requiere evidencia': 'Requiere evidencia',
    'no_evaluado': 'Por revisar',
    'descartado': 'Por revisar',
  }[estado] || estado.charAt(0).toUpperCase() + estado.slice(1);
  return <span className={cls}>{label}</span>;
}

function MetodoBadge({ metodo }) {
  const m = String(metodo || 'repo').toLowerCase();
  if (m === 'en_vivo' || m === 'en vivo' || m === 'nube') {
    return <span className="ctl-badge-method live">en vivo</span>;
  }
  if (m === 'evidencia') {
    return <span className="ctl-badge-method evidence">evidencia</span>;
  }
  return <span className="ctl-badge-method repo">repo</span>;
}

function evidenceHref(repository, item) {
  if (!item?.archivo || !item.linea) return null;
  const url = repository?.url;
  const commit = repository?.commit;
  if (!url || !commit || !/^https:\/\/github\.com\//.test(url)) return null;
  return `${url.replace(/\.git$/, '')}/blob/${commit}/${item.archivo}#L${item.linea}`;
}

export default function ControlsTab({ currentAnalysis }) {
  const analysisId = currentAnalysis?.analysis_id;
  const repo = currentAnalysis?.repository || {};
  const [review, setReview] = useState(null);
  const [error, setError] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [estadoFilter, setEstadoFilter] = useState('todos');
  const [metodoFilter, setMetodoFilter] = useState('todos');
  const [familiaFilter, setFamiliaFilter] = useState('todas');
  const [isReReviewing, setIsReReviewing] = useState(false);

  // Modal para Ficha de Evidencia
  const [evidenceModalControl, setEvidenceModalControl] = useState(null);
  const [evidenceWho, setEvidenceWho] = useState('Hugo - SecOps');
  const [evidenceDate, setEvidenceDate] = useState(new Date().toISOString().slice(0, 10));
  const [evidenceNotes, setEvidenceNotes] = useState('');
  const [evidenceStatus, setEvidenceStatus] = useState('cumple');
  const [isSavingEvidence, setIsSavingEvidence] = useState(false);

  // Modal para Verificación en Vivo
  const [isLiveVerifyModalOpen, setIsLiveVerifyModalOpen] = useState(false);
  const [liveTarget, setLiveTarget] = useState('');
  const [liveMode, setLiveMode] = useState('http');
  const [authConfirmed, setAuthConfirmed] = useState(false);
  const [isRunningLiveVerify, setIsRunningLiveVerify] = useState(false);
  const [liveVerifyResults, setLiveVerifyResults] = useState(null);
  const [liveVerifyError, setLiveVerifyError] = useState(null);

  useEffect(() => {
    if (!analysisId) {
      setReview(null);
      setError(null);
      return undefined;
    }
    let cancelled = false;
    setIsLoading(true);
    setError(null);
    api.getAnalysisControls(analysisId)
      .then((data) => { if (!cancelled) setReview(data?.controls_review || null); })
      .catch((err) => { if (!cancelled) setError(err.message || 'Error al cargar la revisión de controles'); })
      .finally(() => { if (!cancelled) setIsLoading(false); });
    return () => { cancelled = true; };
  }, [analysisId]);

  // Pre-llenar objetivo para pruebas en vivo si se conoce la URL
  useEffect(() => {
    if (repo?.url) {
      setLiveTarget(repo.url);
    }
  }, [repo]);

  const familias = useMemo(() => {
    const set = new Set((review?.results || []).map((entry) => entry.familia));
    return Array.from(set).sort();
  }, [review]);

  const filtered = useMemo(() => (review?.results || []).filter((entry) => {
    if (estadoFilter !== 'todos') {
      if (estadoFilter === 'por_revisar') {
        if (!entry.requiere_revision) return false;
      } else if (entry.estado !== estadoFilter) {
        return false;
      }
    }
    if (metodoFilter !== 'todos') {
      const m = String(entry.metodo || 'repo').toLowerCase();
      if (metodoFilter === 'en_vivo') {
        if (m !== 'en_vivo' && m !== 'en vivo' && m !== 'nube') return false;
      } else if (metodoFilter === 'repo') {
        if (m !== 'repo') return false;
      } else if (metodoFilter === 'evidencia') {
        if (m !== 'evidencia') return false;
      }
    }
    if (familiaFilter !== 'todas' && entry.familia !== familiaFilter) return false;
    return true;
  }), [review, estadoFilter, metodoFilter, familiaFilter]);

  const handleReReview = async () => {
    if (!analysisId) return;
    setIsReReviewing(true);
    setError(null);
    try {
      const data = await api.reReviewControls(analysisId);
      setReview(data?.controls_review || null);
    } catch (err) {
      setError(err.message || 'Error al re-revisar los controles');
    } finally {
      setIsReReviewing(false);
    }
  };

  const handleOpenEvidenceModal = (controlEntry) => {
    setEvidenceModalControl(controlEntry);
    const existing = controlEntry?.ficha_evidencia;
    setEvidenceWho(existing?.quien_sube || 'Hugo - SecOps');
    setEvidenceDate(existing?.fecha || new Date().toISOString().slice(0, 10));
    setEvidenceNotes(existing?.notas || '');
    setEvidenceStatus(controlEntry?.estado === 'cumple' || controlEntry?.estado === 'parcial' ? controlEntry.estado : 'cumple');
  };

  const handleSaveEvidence = async (e) => {
    e.preventDefault();
    if (!evidenceModalControl || !analysisId) return;
    setIsSavingEvidence(true);
    try {
      const payload = {
        que_subir: EVIDENCE_GUIDANCE[evidenceModalControl.id] || `Ficha para ${evidenceModalControl.nombre}`,
        quien_sube: evidenceWho,
        fecha: evidenceDate,
        notas: evidenceNotes,
        estado: evidenceStatus,
      };
      const res = await api.saveControlEvidence(analysisId, evidenceModalControl.id, payload);
      // Actualizar review en memoria
      if (review && review.results) {
        const updatedResults = review.results.map((item) =>
          item.id === evidenceModalControl.id ? { ...item, ...res.control } : item
        );
        setReview({ ...review, results: updatedResults });
      }
      setEvidenceModalControl(null);
    } catch (err) {
      alert(err.message || 'Error al guardar ficha de evidencia');
    } finally {
      setIsSavingEvidence(false);
    }
  };

  const handleRunLiveVerification = async () => {
    if (!authConfirmed) {
      alert('Debe confirmar explícitamente que tiene autorización sobre el objetivo.');
      return;
    }
    setIsRunningLiveVerify(true);
    setLiveVerifyError(null);
    setLiveVerifyResults(null);
    try {
      const res = await api.runLiveVerification({
        modo: liveMode,
        target: liveTarget,
        autorizacion_confirmada: true,
      });
      setLiveVerifyResults(res.results || []);
      // Si hay resultados, actualizar controles en la tabla local
      if (review && review.results && res.results) {
        const resultMap = new Map(res.results.map((r) => [String(r.control_id), r]));
        const updated = review.results.map((item) => {
          const match = resultMap.get(String(item.id));
          if (match) {
            return {
              ...item,
              estado: match.estado,
              requiere_revision: match.estado === 'requiere evidencia',
              razonamiento: match.detalles,
              evidencia: [
                ...(item.evidencia || []),
                { archivo: `[${match.modo.toUpperCase()}] ${match.objetivo}`, linea: 1, fragmento: match.evidencia.slice(0, 150) },
              ],
            };
          }
          return item;
        });
        setReview({ ...review, results: updated });
      }
    } catch (err) {
      setLiveVerifyError(err.message || 'Error al ejecutar verificación en vivo.');
    } finally {
      setIsRunningLiveVerify(false);
    }
  };

  if (!analysisId) {
    return (
      <div className="tab-pane active">
        <section className="card">
          <div className="empty-state">
            <p>No hay ningún análisis cargado. Iniciá un análisis o cargá uno del historial para ver la revisión de controles.</p>
          </div>
        </section>
      </div>
    );
  }

  return (
    <div className="tab-pane active">
      <section className="card" style={{ padding: '20px' }}>
        {/* Encabezado de la hoja de registro */}
        <div style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '14px', marginBottom: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '10px' }}>
            <div>
              <p className="eyebrow">INVENTARIO DE CONTROLES DE SEGURIDAD V1.0 — HOJA DE REGISTRO</p>
              <h2 style={{ margin: '4px 0 0', fontSize: '18px' }}>Revisión por control y verificación en vivo</h2>
            </div>
            <div style={{ display: 'flex', gap: '10px' }}>
              <button
                type="button"
                className="btn-primary"
                onClick={() => {
                  setLiveVerifyResults(null);
                  setLiveVerifyError(null);
                  setAuthConfirmed(false);
                  setIsLiveVerifyModalOpen(true);
                }}
              >
                ⚡ Ejecutar verificación en vivo
              </button>
            </div>
          </div>
          <div style={{ display: 'flex', gap: '18px', flexWrap: 'wrap', marginTop: '10px', fontSize: '13px' }}>
            <span><strong>Aplicación:</strong> {review?.disponible ? (review.application || 'n/d') : (repo.name || repo.url || 'n/d')}</span>
            <span><strong>Fecha de revisión:</strong> {review?.reviewed_at || 'sin revisión'}</span>
            <span><strong>Revisor:</strong> {review?.disponible ? review.reviewer : 'n/d'}</span>
            <span><strong>Commit revisado:</strong> <code>{review?.commit ? String(review.commit).slice(0, 12) : (repo.commit ? String(repo.commit).slice(0, 12) : 'sin SHA')}</code></span>
          </div>
          {review?.disponible && review.llm_sdk && (
            <p className="muted" style={{ fontSize: '12px', margin: '6px 0 0' }}>
              SDK de LLM: {review.llm_sdk.detectado === true
                ? `detectado (${(review.llm_sdk.evidencia || []).map((e) => e.sdk).join(', ')}) — los controles C10-C13 aplican`
                : 'no detectado en manifiestos — C10-C13 quedan en «no aplica» justificado'}
            </p>
          )}
        </div>

        {isLoading && <div className="empty-state"><p>Cargando revisión de controles…</p></div>}

        {!isLoading && error && <div className="empty-state"><p>{error}</p></div>}

        {!isLoading && !error && (!review || !review.disponible) && (
          <div className="empty-state">
            <p>{review?.motivo || 'Sin revisión de controles disponible para este análisis.'}</p>
            <button type="button" className="btn-secondary" onClick={handleReReview} disabled={isReReviewing}>
              {isReReviewing ? 'Re-revisando…' : 'Derivar de hallazgos de scanners (solo evidencia real)'}
            </button>
          </div>
        )}

        {!isLoading && !error && review?.disponible && (
          <>
            {/* Resumen + filtros */}
            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'center', marginBottom: '14px' }}>
              <span className="ctl-badge cumple">Cumple: {review.resumen?.cumple ?? 0}</span>
              <span className="ctl-badge parcial">Parcial: {review.resumen?.parcial ?? 0}</span>
              <span className="ctl-badge no-cumple">No cumple: {review.resumen?.['no cumple'] ?? 0}</span>
              <span className="ctl-badge no-aplica">No aplica: {review.resumen?.['no aplica'] ?? 0}</span>
              <span className="ctl-badge no-evaluado">Por revisar: {(review.queue_por_revisar || []).length}</span>
              <span style={{ flex: 1 }} />
              <label style={{ fontSize: '12px' }}>
                Método:{' '}
                <select value={metodoFilter} onChange={(e) => setMetodoFilter(e.target.value)}>
                  <option value="todos">Todos</option>
                  <option value="repo">Repo</option>
                  <option value="en_vivo">En vivo</option>
                  <option value="evidencia">Evidencia</option>
                </select>
              </label>
              <label style={{ fontSize: '12px' }}>
                Estado:{' '}
                <select value={estadoFilter} onChange={(e) => setEstadoFilter(e.target.value)}>
                  <option value="todos">Todos</option>
                  <option value="cumple">Cumple</option>
                  <option value="parcial">Parcial</option>
                  <option value="no cumple">No cumple</option>
                  <option value="no aplica">No aplica</option>
                  <option value="por_revisar">Por revisar</option>
                </select>
              </label>
              <label style={{ fontSize: '12px' }}>
                Familia:{' '}
                <select value={familiaFilter} onChange={(e) => setFamiliaFilter(e.target.value)}>
                  <option value="todas">Todas</option>
                  {familias.map((familia) => <option key={familia} value={familia}>{familia}</option>)}
                </select>
              </label>
            </div>

            {/* Hoja de registro: una fila por control con columna Método */}
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Control</th>
                    <th>Método</th>
                    <th>Criticidad</th>
                    <th>Estado</th>
                    <th>Evidencia</th>
                    <th>Acción</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((entry) => {
                    const isManualControl = MANUAL_EVIDENCE_CONTROLS.includes(String(entry.id));
                    return (
                      <tr key={entry.id}>
                        <td><strong>{entry.id}</strong></td>
                        <td>
                          {entry.nombre}
                          <div className="muted" style={{ fontSize: '11px' }}>{entry.familia}</div>
                          {entry.veredicto_solo_agente && (
                            <span className="agent-only-badge" title="Veredicto emitido solo por el agente de IA, sin corroboración de scanners">solo agente</span>
                          )}
                          {entry.cobertura && (
                            <div className="muted" style={{ fontSize: '11px' }}>Cobertura: {entry.cobertura}</div>
                          )}
                        </td>
                        <td>
                          <MetodoBadge metodo={entry.metodo} />
                        </td>
                        <td>{CRITICIDAD_LABEL[entry.criticidad_referencia] || entry.criticidad_referencia}</td>
                        <td>
                          <EstadoBadge estado={entry.estado} />
                          {entry.confianza > 0 && (
                            <div className="muted" style={{ fontSize: '11px' }}>confianza {entry.confianza}</div>
                          )}
                        </td>
                        <td style={{ fontSize: '12px' }}>
                          {entry.ficha_evidencia ? (
                            <div style={{ background: 'rgba(245, 158, 11, 0.08)', padding: '6px 8px', borderRadius: '4px', border: '1px solid rgba(245, 158, 11, 0.25)', marginBottom: '4px' }}>
                              <div style={{ fontWeight: 600, color: '#f59e0b', fontSize: '11px' }}>
                                Ficha: {entry.ficha_evidencia.quien_sube} ({entry.ficha_evidencia.fecha})
                              </div>
                              <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                                {entry.ficha_evidencia.notas || entry.ficha_evidencia.que_subir}
                              </div>
                            </div>
                          ) : null}
                          {(entry.evidencia || []).length === 0
                            ? <span className="muted">{entry.ficha_evidencia ? '' : (entry.estado === 'no aplica' ? '—' : 'sin evidencia citada')}</span>
                            : (entry.evidencia || []).slice(0, 3).map((item, index) => {
                                const href = evidenceHref(repo, item);
                                return (
                                  <div key={index}>
                                    {href
                                      ? <a href={href} target="_blank" rel="noreferrer"><code>{item.archivo}:{item.linea}</code></a>
                                      : <code>{item.archivo}:{item.linea}</code>}
                                  </div>
                                );
                              })}
                          {(entry.evidencia || []).length > 3 && (
                            <div className="muted" style={{ fontSize: '11px' }}>+{(entry.evidencia || []).length - 3} más</div>
                          )}
                          {entry.razonamiento && (
                            <div className="muted" style={{ fontSize: '11px', marginTop: '4px', maxWidth: '420px' }}>{entry.razonamiento}</div>
                          )}
                        </td>
                        <td>
                          {isManualControl ? (
                            <button
                              type="button"
                              className="btn-secondary"
                              style={{ padding: '4px 8px', fontSize: '11px' }}
                              onClick={() => handleOpenEvidenceModal(entry)}
                            >
                              {entry.ficha_evidencia ? 'Editar ficha' : 'Subir evidencia'}
                            </button>
                          ) : (
                            <span className="muted" style={{ fontSize: '11px' }}>Auto</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                  {filtered.length === 0 && (
                    <tr><td colSpan={7}><div className="empty-state"><p>Ningún control coincide con los filtros seleccionados.</p></div></td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}
      </section>

      {/* MODAL: Ficha de Evidencia para controles no automatizables (4, C1, C6, C9, C12) */}
      {evidenceModalControl && (
        <div className="modal-backdrop" onClick={() => setEvidenceModalControl(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '580px', padding: '24px' }}>
            <h3 style={{ margin: '0 0 8px', fontSize: '17px' }}>
              Ficha de Evidencia: Control {evidenceModalControl.id}
            </h3>
            <p className="muted" style={{ fontSize: '13px', margin: '0 0 16px' }}>
              {evidenceModalControl.nombre}
            </p>

            <form onSubmit={handleSaveEvidence}>
              <div style={{ background: 'var(--bg-inset)', padding: '12px 14px', borderRadius: '6px', marginBottom: '16px', border: '1px solid var(--border-subtle)' }}>
                <strong style={{ fontSize: '12px', display: 'block', color: 'var(--accent)', marginBottom: '4px' }}>
                  ¿QUÉ SUBIR?
                </strong>
                <p style={{ margin: 0, fontSize: '12px', lineHeight: '1.4' }}>
                  {EVIDENCE_GUIDANCE[evidenceModalControl.id] || 'Cargar reporte técnico o comprobante de cumplimiento para este control.'}
                </p>
              </div>

              <div style={{ marginBottom: '14px' }}>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, marginBottom: '4px' }}>
                  ¿Quién lo sube? (Responsable / Rol):
                </label>
                <input
                  type="text"
                  required
                  value={evidenceWho}
                  onChange={(e) => setEvidenceWho(e.target.value)}
                  placeholder="Ej: Hugo - SecOps / Juan - DBA"
                  style={{ width: '100%', padding: '8px 10px', fontSize: '13px', borderRadius: '4px', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface)', color: 'var(--text-main)' }}
                />
              </div>

              <div style={{ marginBottom: '14px' }}>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, marginBottom: '4px' }}>
                  Fecha de la prueba o reporte:
                </label>
                <input
                  type="date"
                  required
                  value={evidenceDate}
                  onChange={(e) => setEvidenceDate(e.target.value)}
                  style={{ width: '100%', padding: '8px 10px', fontSize: '13px', borderRadius: '4px', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface)', color: 'var(--text-main)' }}
                />
              </div>

              <div style={{ marginBottom: '14px' }}>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, marginBottom: '4px' }}>
                  Estado dictaminado:
                </label>
                <select
                  value={evidenceStatus}
                  onChange={(e) => setEvidenceStatus(e.target.value)}
                  style={{ width: '100%', padding: '8px 10px', fontSize: '13px', borderRadius: '4px', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface)', color: 'var(--text-main)' }}
                >
                  <option value="cumple">Cumple (evidencia satisfactoria)</option>
                  <option value="parcial">Parcial (observaciones o mitigación parcial)</option>
                  <option value="no cumple">No cumple (evidencia fallida)</option>
                </select>
              </div>

              <div style={{ marginBottom: '18px' }}>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, marginBottom: '4px' }}>
                  Notas de evidencia / Enlace al ticket o reporte:
                </label>
                <textarea
                  rows={3}
                  value={evidenceNotes}
                  onChange={(e) => setEvidenceNotes(e.target.value)}
                  placeholder="Detallar ticket JIRA, URL de artifact de logs o resumen del simulacro..."
                  style={{ width: '100%', padding: '8px 10px', fontSize: '13px', borderRadius: '4px', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface)', color: 'var(--text-main)' }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setEvidenceModalControl(null)}
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  className="btn-primary"
                  disabled={isSavingEvidence}
                >
                  {isSavingEvidence ? 'Guardando…' : 'Guardar evidencia'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: Confirmación y Ejecución de Verificación en Vivo */}
      {isLiveVerifyModalOpen && (
        <div className="modal-backdrop" onClick={() => !isRunningLiveVerify && setIsLiveVerifyModalOpen(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '640px', padding: '24px' }}>
            <h3 style={{ margin: '0 0 8px', fontSize: '18px' }}>
              Confirmación de Verificación en Vivo y Evidencia
            </h3>
            <p className="muted" style={{ fontSize: '13px', margin: '0 0 16px' }}>
              Ejecución de pruebas directas contra el objetivo mediante solicitudes no destructivas de baja frecuencia.
            </p>

            <div style={{ marginBottom: '14px' }}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, marginBottom: '4px' }}>
                Modo de prueba:
              </label>
              <select
                value={liveMode}
                onChange={(e) => setLiveMode(e.target.value)}
                disabled={isRunningLiveVerify}
                style={{ width: '100%', padding: '8px 10px', fontSize: '13px', borderRadius: '4px', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface)', color: 'var(--text-main)' }}
              >
                <option value="http">Modo HTTP (contra URL)</option>
                <option value="nube">Modo Nube (contra cuenta/región AWS)</option>
              </select>
            </div>

            <div style={{ marginBottom: '14px' }}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, marginBottom: '4px' }}>
                {liveMode === 'http' ? 'URL Objetivo a verificar:' : 'Identificador de cuenta / Región AWS:'}
              </label>
              <input
                type="text"
                required
                value={liveTarget}
                onChange={(e) => setLiveTarget(e.target.value)}
                placeholder={liveMode === 'http' ? 'https://mi-api.example.com' : 'aws-account-123456789012/us-east-1'}
                disabled={isRunningLiveVerify}
                style={{ width: '100%', padding: '8px 10px', fontSize: '13px', borderRadius: '4px', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface)', color: 'var(--text-main)' }}
              />
            </div>

            {/* Qué se va a probar */}
            <div style={{ background: 'var(--bg-inset)', padding: '12px 14px', borderRadius: '6px', marginBottom: '16px', border: '1px solid var(--border-subtle)' }}>
              <strong style={{ fontSize: '12px', display: 'block', color: 'var(--text-main)', marginBottom: '6px' }}>
                ¿QUÉ SE VA A PROBAR?
              </strong>
              {liveMode === 'http' ? (
                <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '12px', lineHeight: '1.5' }}>
                  <li><strong>Control 1 (CORS):</strong> Comprueba origen ajeno no confiable (Access-Control-Allow-Origin).</li>
                  <li><strong>Control 10 (Cookies):</strong> Banderas Secure, HttpOnly y SameSite en cookies.</li>
                  <li><strong>Control 16 (Headers):</strong> Cabeceras HSTS, CSP, nosniff, X-Frame-Options.</li>
                  <li><strong>Control 3 (Errores):</strong> Provocación de error controlado 404 buscando ausencia de stack traces.</li>
                  <li><strong>Control 7 (Rate limit):</strong> Serie controlada de baja frecuencia verificando respuesta 429 o cabeceras.</li>
                  <li><strong>Control 14 (TLS):</strong> Rechazo de protocolos obsoletos TLS &lt; 1.2.</li>
                </ul>
              ) : (
                <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '12px', lineHeight: '1.5' }}>
                  <li><strong>Control 13 (Cifrado BD):</strong> Comprueba StorageEncrypted en instancias RDS.</li>
                  <li><strong>Control 15 (S3 público):</strong> Bloqueo de acceso público PublicAccessBlock en buckets.</li>
                  <li><strong>Control 19 (Ciclo de vida):</strong> Reglas de expiración y transición en almacenamiento.</li>
                  <li><strong>Control 18 (BD pública):</strong> Directiva PubliclyAccessible desactivada en RDS.</li>
                  <li><strong>Control 14 (TLS ALB):</strong> Políticas SSL TLS 1.2+ en balanceadores.</li>
                  <li><strong>Control C9 (CloudTrail):</strong> Pistas de auditoría multirregión activas.</li>
                  <li><strong>Control C6 (Respaldos):</strong> Período de retención de respaldos automáticos &gt; 0 días.</li>
                </ul>
              )}
              <p className="muted" style={{ margin: '8px 0 0', fontSize: '11px' }}>
                🛡️ Solicitudes no destructivas y de baja frecuencia. Nunca se envían cargas dañinas ni fuerza bruta. Toda prueba se registra en bitácora de auditoría.
              </p>
            </div>

            {/* Checkbox obligatorio de autorización */}
            <div style={{ marginBottom: '18px', padding: '10px 12px', background: 'rgba(59, 130, 246, 0.08)', borderRadius: '6px', border: '1px solid rgba(59, 130, 246, 0.25)' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', cursor: 'pointer', fontWeight: 600 }}>
                <input
                  type="checkbox"
                  checked={authConfirmed}
                  onChange={(e) => setAuthConfirmed(e.target.checked)}
                  disabled={isRunningLiveVerify}
                />
                Confirmo formalmente que tengo autorización explícita sobre el objetivo para ejecutar estas pruebas.
              </label>
            </div>

            {liveVerifyError && (
              <div style={{ color: 'var(--crimson)', background: 'var(--crimson-bg)', padding: '10px', borderRadius: '4px', fontSize: '12px', marginBottom: '14px' }}>
                {liveVerifyError}
              </div>
            )}

            {/* Resultados en tiempo real si ya corrió */}
            {liveVerifyResults && (
              <div style={{ marginBottom: '16px', maxHeight: '240px', overflowY: 'auto', border: '1px solid var(--border-subtle)', borderRadius: '4px', padding: '10px', background: 'var(--bg-inset)' }}>
                <h4 style={{ margin: '0 0 8px', fontSize: '13px' }}>Resultados de la verificación:</h4>
                {liveVerifyResults.map((r, idx) => (
                  <div key={idx} style={{ marginBottom: '8px', paddingBottom: '6px', borderBottom: '1px solid var(--border-subtle)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '12px', fontWeight: 600 }}>Control {r.control_id}: {r.nombre}</span>
                      <EstadoBadge estado={r.estado} />
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px' }}>{r.detalles}</div>
                  </div>
                ))}
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button
                type="button"
                className="btn-secondary"
                disabled={isRunningLiveVerify}
                onClick={() => setIsLiveVerifyModalOpen(false)}
              >
                {liveVerifyResults ? 'Cerrar' : 'Cancelar'}
              </button>
              <button
                type="button"
                className="btn-primary"
                disabled={!authConfirmed || !liveTarget || isRunningLiveVerify}
                onClick={handleRunLiveVerification}
              >
                {isRunningLiveVerify ? 'Ejecutando pruebas…' : (liveVerifyResults ? 'Re-ejecutar pruebas' : 'Ejecutar pruebas')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
