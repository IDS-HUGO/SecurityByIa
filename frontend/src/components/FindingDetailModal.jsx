import React, { useState } from 'react';

export default function FindingDetailModal({
  finding,
  onClose,
  onTriageDecision,
  onProposeFix,
  onReviewRemediation,
}) {
  if (!finding) return null;

  const [reason, setReason] = useState('');
  const [author, setAuthor] = useState('analista-seguridad');
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Remediation (F6) states
  const [remReason, setRemReason] = useState('');
  const [remAuthor, setRemAuthor] = useState('analista-seguridad');
  const [remError, setRemError] = useState('');
  const [remSuccessMsg, setRemSuccessMsg] = useState('');
  const [isRemSubmitting, setIsRemSubmitting] = useState(false);
  const [isProposingFix, setIsProposingFix] = useState(false);
  const [diffViewMode, setDiffViewMode] = useState('split'); // 'split' or 'unified'

  const pkg = finding.package || (finding.extra && finding.extra.package);
  const isDep = Boolean(pkg);
  const isSecret = (finding.tools || []).includes('gitleaks') ||
                   (finding.tools || []).includes('trufflehog') ||
                   Boolean(finding.verification);

  const triage = finding.triage || {};
  const triageVerdict = triage.verdict || (finding.status === 'false_positive' ? 'falso' : 'verdadero');
  const triageReason = triage.reason || '';
  const decidedBy = triage.decided_by || 'regla';
  const triageConfidence = triage.confidence !== undefined ? triage.confidence : 1.0;
  const triageAuthor = triage.author || '';
  const triageTimestamp = triage.timestamp ? new Date(triage.timestamp).toLocaleString() : '';

  const verdictClass = triageVerdict === 'verdadero' ? 'completed' : triageVerdict === 'falso' ? 'queued' : 'running';

  const handleAction = async (decision) => {
    setError('');
    setSuccessMsg('');
    const cleanReason = reason.trim();
    if (!cleanReason || cleanReason.length < 3) {
      setError('El motivo es obligatorio para registrar la decisión de triage.');
      return;
    }
    if (!onTriageDecision) return;

    setIsSubmitting(true);
    try {
      const res = await onTriageDecision(finding.id, {
        decision,
        reason: cleanReason,
        author: author.trim() || 'analista-seguridad',
      });
      const fpMsg = res?.fingerprint ? ` (huella guardada: ${res.fingerprint.slice(0, 8)}...)` : '';
      setSuccessMsg(`Decisión '${decision}' guardada exitosamente${fpMsg}.`);
      setReason('');
    } catch (err) {
      setError(err.message || 'Error al guardar la decisión de triage');
    } finally {
      setIsSubmitting(false);
    }
  };

  const remediation = finding.remediation || {};
  const remStatus = (remediation.status || 'open').toLowerCase();
  const hasDiff = Boolean(remediation.diff);

  const handleProposeFix = async () => {
    setRemError('');
    setRemSuccessMsg('');
    if (!onProposeFix) return;
    setIsProposingFix(true);
    try {
      await onProposeFix(finding.id);
      setRemSuccessMsg('Corrección automatizada propuesta y verificada.');
    } catch (err) {
      setRemError(err.message || 'Error al proponer la corrección.');
    } finally {
      setIsProposingFix(false);
    }
  };

  const handleRemediationReview = async (decision) => {
    setRemError('');
    setRemSuccessMsg('');
    const cleanReason = remReason.trim();
    if (!cleanReason || cleanReason.length < 3) {
      setRemError('El motivo es obligatorio para aprobar o rechazar el parche.');
      return;
    }
    if (!onReviewRemediation) return;
    setIsRemSubmitting(true);
    try {
      await onReviewRemediation(finding.id, {
        decision,
        reason: cleanReason,
        author: remAuthor.trim() || 'analista-seguridad',
      });
      setRemSuccessMsg(`Parche ${decision === 'approved' ? 'aprobado' : 'rechazado'} exitosamente.`);
      setRemReason('');
    } catch (err) {
      setRemError(err.message || 'Error al guardar la revisión del parche.');
    } finally {
      setIsRemSubmitting(false);
    }
  };

  const renderUnifiedDiff = (diffText) => {
    if (!diffText) return null;
    const lines = diffText.split('\n');
    return (
      <div style={{ fontFamily: 'monospace', fontSize: '0.82rem', background: '#0f172a', borderRadius: '6px', padding: '0.75rem', overflowX: 'auto', border: '1px solid #334155' }}>
        {lines.map((l, idx) => {
          let bg = 'transparent';
          let color = '#cbd5e1';
          if (l.startsWith('+') && !l.startsWith('+++')) {
            bg = 'rgba(34, 197, 94, 0.2)';
            color = '#4ade80';
          } else if (l.startsWith('-') && !l.startsWith('---')) {
            bg = 'rgba(239, 68, 68, 0.2)';
            color = '#f87171';
          } else if (l.startsWith('@@')) {
            color = '#818cf8';
          }
          return (
            <div key={idx} style={{ background: bg, color, padding: '1px 6px', whiteSpace: 'pre' }}>
              {l}
            </div>
          );
        })}
      </div>
    );
  };

  const renderSideBySideDiff = (diffText) => {
    if (!diffText) return null;
    const lines = diffText.split('\n');
    const origLines = [];
    const patchedLines = [];

    lines.forEach((l) => {
      if (l.startsWith('---') || l.startsWith('+++') || l.startsWith('@@')) return;
      if (l.startsWith('-')) {
        origLines.push({ text: l.slice(1), type: 'del' });
      } else if (l.startsWith('+')) {
        patchedLines.push({ text: l.slice(1), type: 'add' });
      } else {
        const text = l.startsWith(' ') ? l.slice(1) : l;
        origLines.push({ text, type: 'same' });
        patchedLines.push({ text, type: 'same' });
      }
    });

    return (
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontFamily: 'monospace', fontSize: '0.82rem', background: '#0f172a', borderRadius: '6px', padding: '0.75rem', overflowX: 'auto', border: '1px solid #334155' }}>
        <div>
          <div style={{ fontWeight: 600, color: '#f87171', borderBottom: '1px solid #334155', paddingBottom: '0.3rem', marginBottom: '0.4rem' }}>
            Original (Con hallazgo)
          </div>
          {origLines.map((item, idx) => (
            <div key={idx} style={{ background: item.type === 'del' ? 'rgba(239, 68, 68, 0.25)' : 'transparent', color: item.type === 'del' ? '#fca5a5' : '#cbd5e1', padding: '1px 4px', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {item.text || ' '}
            </div>
          ))}
        </div>
        <div>
          <div style={{ fontWeight: 600, color: '#4ade80', borderBottom: '1px solid #334155', paddingBottom: '0.3rem', marginBottom: '0.4rem' }}>
            Modificado (Parche propuesto)
          </div>
          {patchedLines.map((item, idx) => (
            <div key={idx} style={{ background: item.type === 'add' ? 'rgba(34, 197, 94, 0.25)' : 'transparent', color: item.type === 'add' ? '#86efac' : '#cbd5e1', padding: '1px 4px', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {item.text || ' '}
            </div>
          ))}
        </div>
      </div>
    );
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div>
            <span className="eyebrow">DETALLE DEL HALLAZGO #{finding.id}</span>
            <h2 style={{ margin: '0.25rem 0', fontSize: '1.25rem' }}>{finding.title || finding.rule}</h2>
          </div>
          <button type="button" className="btn-close" onClick={onClose} aria-label="Cerrar">
            ✕
          </button>
        </div>

        <div className="modal-body">
          {/* Severity & SLA Bar */}
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap' }}>
            <span className={`sev-badge ${finding.severity}`}>
              {finding.severity?.toUpperCase()}
            </span>
            {finding.remediation_deadline && (
              <span className="deadline-badge">
                Plazo: {finding.remediation_deadline}
              </span>
            )}
            {finding.tools && finding.tools.map((t) => (
              <span key={t} className="tool-tag">{t}</span>
            ))}
          </div>

          {/* Severity Reason callout */}
          {finding.severity_reason && (
            <div className="reason-callout">
              <strong>Motivo del cálculo:</strong> {finding.severity_reason}
            </div>
          )}

          {/* Dependency information block */}
          {isDep && (
            <div className="dependency-block">
              <h4 style={{ margin: '0 0 0.5rem', fontSize: '0.9rem', color: 'var(--text-color)' }}>
                Información de Dependencia Vulnerable
              </h4>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '0.75rem' }}>
                <div>
                  <span className="detail-meta-label">Paquete</span>
                  <strong>{pkg.name || '—'}</strong>
                </div>
                <div>
                  <span className="detail-meta-label">Versión instalada</span>
                  <code>{pkg.version || '—'}</code>
                </div>
                <div>
                  <span className="detail-meta-label">Versión corregida</span>
                  <strong style={{ color: 'var(--success-color)' }}>{pkg.fixed_version || 'No reportada'}</strong>
                </div>
              </div>
            </div>
          )}

          {/* Secret verification block */}
          {isSecret && (
            <div style={{ background: 'var(--card-bg-subtle)', padding: '0.75rem 1rem', borderRadius: '6px', marginBottom: '1rem', border: '1px solid var(--border-color)' }}>
              <span className="detail-meta-label">Estado de Verificación del Secreto</span>
              <strong style={{ color: finding.verification === 'VALID' ? 'var(--critical-color)' : finding.verification === 'INVALID' ? 'var(--muted-color)' : 'var(--warning-color)' }}>
                {finding.verification === 'VALID' ? 'VERIFICADO Y ACTIVO (VALID)' : finding.verification === 'INVALID' ? 'INVÁLIDO / DE PRUEBA (INVALID)' : 'NO VERIFICADO (UNVERIFIED)'}
              </strong>
            </div>
          )}

          {/* Metadata Grid */}
          <div className="detail-grid" style={{ marginBottom: '1rem' }}>
            <div>
              <span className="detail-meta-label">Ubicación</span>
              <code>{finding.file}:{finding.line || '?'}</code>
            </div>
            <div>
              <span className="detail-meta-label">Regla de detección</span>
              <code>{finding.rule}</code>
            </div>
            <div>
              <span className="detail-meta-label">Categoría OWASP</span>
              <span>{finding.owasp || 'A05:2021 - Security Misconfiguration'}</span>
            </div>
            <div>
              <span className="detail-meta-label">CWEs Asociados</span>
              <span>
                {Array.isArray(finding.cwe) ? finding.cwe.join(', ') : finding.cwe || 'CWE-Other'}
              </span>
            </div>
          </div>

          {/* Problem */}
          <div style={{ marginBottom: '1rem' }}>
            <span className="detail-meta-label">Descripción del Problema</span>
            <p style={{ margin: '0.25rem 0', color: 'var(--text-color)', lineHeight: 1.5 }}>
              {finding.problem}
            </p>
          </div>

          {/* Recommendation */}
          <div style={{ marginBottom: '1rem' }}>
            <span className="detail-meta-label">Solución Recomendada</span>
            <p style={{ margin: '0.25rem 0', color: 'var(--text-color)', lineHeight: 1.5 }}>
              {finding.solution}
            </p>
          </div>

          {/* Triage Status & Human Review Panel (Feature 5) */}
          <div className="triage-panel" style={{ background: 'var(--card-bg-subtle, #1e293b)', padding: '1rem 1.25rem', borderRadius: '8px', marginBottom: '1.25rem', border: '1px solid var(--border-color, #334155)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
              <div>
                <span className="eyebrow" style={{ color: 'var(--primary, #6366f1)' }}>TRIAGE & CLASIFICACIÓN (F5)</span>
                <h4 style={{ margin: '0.2rem 0', fontSize: '1rem', color: 'var(--text-color)' }}>
                  Veredicto: {' '}
                  <span className={`status status-${verdictClass}`} style={{ textTransform: 'uppercase', fontWeight: 600 }}>
                    {triageVerdict}
                  </span>
                </h4>
              </div>
              <div style={{ fontSize: '0.8rem', color: 'var(--muted-color)' }}>
                Decidido por: <strong style={{ color: 'var(--text-color)' }}>{decidedBy}</strong>
                {triageConfidence !== null && ` (${(triageConfidence * 100).toFixed(0)}% confianza)`}
              </div>
            </div>

            {triageReason && (
              <p style={{ margin: '0 0 0.75rem', fontSize: '0.875rem', color: 'var(--text-color)', lineHeight: 1.5, background: 'rgba(0,0,0,0.2)', padding: '0.5rem 0.75rem', borderRadius: '4px' }}>
                <strong>Motivo actual:</strong> {triageReason}
              </p>
            )}

            {triageAuthor && (
              <div style={{ fontSize: '0.78rem', color: 'var(--muted-color)', marginBottom: '0.75rem' }}>
                Registrado por: <code>{triageAuthor}</code> en <span>{triageTimestamp}</span>
                {finding.triage?.fingerprint && (
                  <span style={{ marginLeft: '0.5rem', fontFamily: 'monospace' }}>
                    [Huella: {finding.triage.fingerprint.slice(0, 10)}...]
                  </span>
                )}
              </div>
            )}

            {/* Human Triage Action Controls */}
            {onTriageDecision && (
              <div style={{ marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid var(--border-color, #334155)' }}>
                <h5 style={{ margin: '0 0 0.5rem', fontSize: '0.875rem', color: 'var(--text-color)' }}>
                  Revisión Humana / Cambiar Decisión (motivo obligatorio):
                </h5>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '0.5rem', marginBottom: '0.75rem' }}>
                  <textarea
                    placeholder="Escribí el motivo detallado de tu decisión (obligatorio)..."
                    value={reason}
                    onChange={(e) => { setReason(e.target.value); setError(''); }}
                    rows={2}
                    style={{ width: '100%', padding: '0.5rem', borderRadius: '4px', border: '1px solid var(--border-color)', background: 'var(--input-bg)', color: 'var(--text-color)', fontSize: '0.85rem' }}
                  />
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ fontSize: '0.8rem', color: 'var(--muted-color)' }}>Analista:</span>
                    <input
                      type="text"
                      value={author}
                      onChange={(e) => setAuthor(e.target.value)}
                      style={{ padding: '0.25rem 0.5rem', borderRadius: '4px', border: '1px solid var(--border-color)', background: 'var(--input-bg)', color: 'var(--text-color)', fontSize: '0.8rem', width: '180px' }}
                    />
                  </div>
                </div>

                {error && <p style={{ color: 'var(--critical-color, #ef4444)', fontSize: '0.8rem', margin: '0 0 0.5rem' }}>{error}</p>}
                {successMsg && <p style={{ color: 'var(--success-color, #22c55e)', fontSize: '0.8rem', margin: '0 0 0.5rem' }}>{successMsg}</p>}

                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    className="btn-primary"
                    style={{ background: '#16a34a', borderColor: '#16a34a', fontSize: '0.8rem', padding: '0.35rem 0.75rem' }}
                    disabled={isSubmitting}
                    onClick={() => handleAction('verdadero')}
                  >
                    Confirmar (Verdadero)
                  </button>
                  <button
                    type="button"
                    className="btn-primary"
                    style={{ background: '#dc2626', borderColor: '#dc2626', fontSize: '0.8rem', padding: '0.35rem 0.75rem' }}
                    disabled={isSubmitting}
                    onClick={() => handleAction('falso')}
                  >
                    Falso positivo (Guardar huella)
                  </button>
                  <button
                    type="button"
                    className="btn-primary"
                    style={{ background: '#d97706', borderColor: '#d97706', fontSize: '0.8rem', padding: '0.35rem 0.75rem' }}
                    disabled={isSubmitting}
                    onClick={() => handleAction('incierto')}
                  >
                    Incierto (Por revisar)
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Feature 6: Corrección Asistida y Verificación (Patch Review View) */}
          <div className="remediation-panel" style={{ background: 'var(--card-bg-subtle, #1e293b)', padding: '1rem 1.25rem', borderRadius: '8px', marginBottom: '1.25rem', border: '1px solid var(--border-color, #334155)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
              <div>
                <span className="eyebrow" style={{ color: '#10b981' }}>CORRECCIÓN ASISTIDA Y VERIFICACIÓN (F6)</span>
                <h4 style={{ margin: '0.2rem 0', fontSize: '1rem', color: 'var(--text-color)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span>Estado del hallazgo:</span>
                  <span style={{
                    padding: '0.15rem 0.6rem',
                    borderRadius: '4px',
                    fontSize: '0.8rem',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    background:
                      remStatus === 'verified' ? '#166534' :
                      remStatus === 'approved' ? '#065f46' :
                      remStatus === 'discarded' ? '#991b1b' :
                      remStatus === 'rejected' ? '#881337' :
                      remStatus === 'patch_proposed' ? '#854d0e' : '#334155',
                    color: '#fff',
                  }}>
                    {remStatus === 'verified' ? 'Verificado' :
                     remStatus === 'approved' ? 'Aprobado' :
                     remStatus === 'discarded' ? 'Descartado' :
                     remStatus === 'rejected' ? 'Rechazado' :
                     remStatus === 'patch_proposed' ? 'Parche propuesto' : 'Abierto'}
                  </span>
                </h4>
              </div>

              {/* Button to propose fix if not proposed or if open */}
              {onProposeFix && (!hasDiff || remStatus === 'open') && (
                <button
                  type="button"
                  className="btn-primary"
                  style={{ background: '#0284c7', borderColor: '#0284c7', fontSize: '0.82rem', padding: '0.4rem 0.85rem' }}
                  disabled={isProposingFix}
                  onClick={handleProposeFix}
                >
                  {isProposingFix ? 'Generando corrección...' : '⚡ Proponer Corrección Asistida'}
                </button>
              )}
            </div>

            {/* Explanation */}
            {remediation.explanation && (
              <p style={{ margin: '0 0 0.75rem', fontSize: '0.85rem', color: '#cbd5e1', lineHeight: 1.5, background: 'rgba(0,0,0,0.2)', padding: '0.5rem 0.75rem', borderRadius: '4px' }}>
                <strong>Explicación:</strong> {remediation.explanation}
              </p>
            )}

            {/* Verification result callout */}
            {remediation.verification && (
              <div style={{
                background: remediation.verification.verified ? 'rgba(34, 197, 94, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                border: `1px solid ${remediation.verification.verified ? '#22c55e' : '#ef4444'}`,
                color: remediation.verification.verified ? '#86efac' : '#fca5a5',
                padding: '0.6rem 0.85rem',
                borderRadius: '6px',
                fontSize: '0.85rem',
                marginBottom: '0.75rem',
              }}>
                <strong>{remediation.verification.verified ? '✓ Re-verificación exitosa: ' : '✕ Verificación descartada: '}</strong>
                {remediation.verification.message}
                {remediation.verification.new_findings && remediation.verification.new_findings.length > 0 && (
                  <ul style={{ margin: '0.3rem 0 0', paddingLeft: '1.25rem' }}>
                    {remediation.verification.new_findings.map((nf, i) => (
                      <li key={i}>{nf.rule} (Línea {nf.line}): {nf.message}</li>
                    ))}
                  </ul>
                )}
              </div>
            )}

            {/* Human review audit info if reviewed */}
            {remediation.reviewed_by && (
              <div style={{ fontSize: '0.8rem', color: 'var(--muted-color)', marginBottom: '0.75rem', background: 'rgba(0,0,0,0.15)', padding: '0.5rem 0.75rem', borderRadius: '4px' }}>
                Revisión humana: <strong style={{ color: remStatus === 'approved' ? '#4ade80' : '#f87171' }}>{remStatus.toUpperCase()}</strong> por <code>{remediation.reviewer}</code> en {new Date(remediation.review_timestamp).toLocaleString()}
                <br />
                <span style={{ color: 'var(--text-color)' }}>Motivo: "{remediation.review_reason}"</span>
              </div>
            )}

            {/* Diff View (Side-by-side or Unified) */}
            {hasDiff && (
              <div style={{ marginTop: '0.75rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                  <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-color)' }}>
                    Revisión del Parche ({remediation.touched_files?.join(', ') || finding.file}):
                  </span>
                  <div style={{ display: 'flex', gap: '0.25rem' }}>
                    <button
                      type="button"
                      className={`btn-secondary ${diffViewMode === 'split' ? 'active-filter' : ''}`}
                      style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem' }}
                      onClick={() => setDiffViewMode('split')}
                    >
                      Lado a Lado
                    </button>
                    <button
                      type="button"
                      className={`btn-secondary ${diffViewMode === 'unified' ? 'active-filter' : ''}`}
                      style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem' }}
                      onClick={() => setDiffViewMode('unified')}
                    >
                      Unificado
                    </button>
                  </div>
                </div>

                {diffViewMode === 'split' ? renderSideBySideDiff(remediation.diff) : renderUnifiedDiff(remediation.diff)}
              </div>
            )}

            {/* Patch Review Actions (Aprobar / Rechazar con motivo obligatorio) */}
            {hasDiff && onReviewRemediation && (
              <div style={{ marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid var(--border-color, #334155)' }}>
                <h5 style={{ margin: '0 0 0.5rem', fontSize: '0.875rem', color: 'var(--text-color)' }}>
                  Aprobar o Rechazar Parche (motivo obligatorio):
                </h5>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '0.5rem', marginBottom: '0.75rem' }}>
                  <textarea
                    placeholder="Escribí el motivo técnico para aprobar o rechazar este parche (obligatorio)..."
                    value={remReason}
                    onChange={(e) => { setRemReason(e.target.value); setRemError(''); }}
                    rows={2}
                    style={{ width: '100%', padding: '0.5rem', borderRadius: '4px', border: '1px solid var(--border-color)', background: 'var(--input-bg)', color: 'var(--text-color)', fontSize: '0.85rem' }}
                  />
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ fontSize: '0.8rem', color: 'var(--muted-color)' }}>Revisor:</span>
                    <input
                      type="text"
                      value={remAuthor}
                      onChange={(e) => setRemAuthor(e.target.value)}
                      style={{ padding: '0.25rem 0.5rem', borderRadius: '4px', border: '1px solid var(--border-color)', background: 'var(--input-bg)', color: 'var(--text-color)', fontSize: '0.8rem', width: '180px' }}
                    />
                  </div>
                </div>

                {remError && <p style={{ color: 'var(--critical-color, #ef4444)', fontSize: '0.8rem', margin: '0 0 0.5rem' }}>{remError}</p>}
                {remSuccessMsg && <p style={{ color: 'var(--success-color, #22c55e)', fontSize: '0.8rem', margin: '0 0 0.5rem' }}>{remSuccessMsg}</p>}

                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    className="btn-primary"
                    style={{ background: '#16a34a', borderColor: '#16a34a', fontSize: '0.8rem', padding: '0.35rem 0.85rem' }}
                    disabled={isRemSubmitting}
                    onClick={() => handleRemediationReview('approved')}
                  >
                    ✓ Aprobar Parche
                  </button>
                  <button
                    type="button"
                    className="btn-primary"
                    style={{ background: '#dc2626', borderColor: '#dc2626', fontSize: '0.8rem', padding: '0.35rem 0.85rem' }}
                    disabled={isRemSubmitting}
                    onClick={() => handleRemediationReview('rejected')}
                  >
                    ✕ Rechazar Parche
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Code excerpt / context */}
          {finding.code_context && finding.code_context.length > 0 && (
            <div>
              <span className="detail-meta-label">Contexto de Código</span>
              <pre className="code-box">
                {finding.code_context.map((ctx) => (
                  <div key={ctx.line} style={{ display: 'flex', gap: '1rem' }}>
                    <span style={{ color: 'var(--muted-color)', userSelect: 'none', width: '2.5rem', textAlign: 'right' }}>
                      {ctx.line}
                    </span>
                    <span>{ctx.text}</span>
                  </div>
                ))}
              </pre>
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button type="button" className="btn-secondary" onClick={onClose}>
            Cerrar
          </button>
        </div>
      </div>
    </div>
  );
}
