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
      <div className="diff-viewer">
        {lines.map((l, idx) => {
          let bg = 'transparent';
          let color = '#e2e8f0';
          if (l.startsWith('+') && !l.startsWith('+++')) {
            bg = 'rgba(22, 101, 52, 0.4)';
            color = '#86efac';
          } else if (l.startsWith('-') && !l.startsWith('---')) {
            bg = 'rgba(153, 27, 27, 0.4)';
            color = '#fca5a5';
          } else if (l.startsWith('@@')) {
            color = '#38bdf8';
          }
          return (
            <div key={idx} style={{ background: bg, color, padding: '2px 8px', whiteSpace: 'pre', fontFamily: 'var(--font-mono)' }}>
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
      <div className="diff-viewer-grid">
        <div>
          <div style={{ fontWeight: 700, color: '#f87171', borderBottom: '1px solid #334155', paddingBottom: '6px', marginBottom: '6px' }}>
            Original (Con hallazgo)
          </div>
          {origLines.map((item, idx) => (
            <div key={idx} style={{ background: item.type === 'del' ? 'rgba(220, 38, 38, 0.35)' : 'transparent', color: item.type === 'del' ? '#fca5a5' : '#e2e8f0', padding: '2px 6px', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {item.text || ' '}
            </div>
          ))}
        </div>
        <div>
          <div style={{ fontWeight: 700, color: '#4ade80', borderBottom: '1px solid #334155', paddingBottom: '6px', marginBottom: '6px' }}>
            Modificado (Parche propuesto)
          </div>
          {patchedLines.map((item, idx) => (
            <div key={idx} style={{ background: item.type === 'add' ? 'rgba(22, 163, 74, 0.35)' : 'transparent', color: item.type === 'add' ? '#86efac' : '#e2e8f0', padding: '2px 6px', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
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
            <h2>{finding.title || finding.rule}</h2>
          </div>
          <button type="button" className="btn-close" onClick={onClose} aria-label="Cerrar">
            ✕
          </button>
        </div>

        <div className="modal-body">
          {/* Severity & SLA Bar */}
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap' }}>
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
              <h4 style={{ margin: '0 0 8px 0', fontSize: '13px', color: 'var(--text-main)' }}>
                Información de Dependencia Vulnerable
              </h4>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '12px' }}>
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
                  <strong style={{ color: 'var(--emerald)' }}>{pkg.fixed_version || 'No reportada'}</strong>
                </div>
              </div>
            </div>
          )}

          {/* Secret verification block */}
          {isSecret && (
            <div style={{ background: 'var(--bg-surface)', padding: '12px 16px', borderRadius: '6px', marginBottom: '16px', border: '1px solid var(--border-medium)' }}>
              <span className="detail-meta-label">Estado de Verificación del Secreto</span>
              <strong style={{ color: finding.verification === 'VALID' ? 'var(--crimson)' : finding.verification === 'INVALID' ? 'var(--text-muted)' : 'var(--amber)' }}>
                {finding.verification === 'VALID' ? 'VERIFICADO Y ACTIVO (VALID)' : finding.verification === 'INVALID' ? 'INVÁLIDO / DE PRUEBA (INVALID)' : 'NO VERIFICADO (UNVERIFIED)'}
              </strong>
            </div>
          )}

          {/* Metadata Grid */}
          <div className="detail-grid" style={{ marginBottom: '16px' }}>
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
          <div style={{ marginBottom: '16px' }}>
            <span className="detail-meta-label">Descripción del Problema</span>
            <p style={{ margin: '4px 0 0', color: 'var(--text-main)', lineHeight: 1.5 }}>
              {finding.problem}
            </p>
          </div>

          {/* Recommendation */}
          <div style={{ marginBottom: '16px' }}>
            <span className="detail-meta-label">Solución Recomendada</span>
            <p style={{ margin: '4px 0 0', color: 'var(--text-main)', lineHeight: 1.5 }}>
              {finding.solution}
            </p>
          </div>

          {/* Triage Status & Human Review Panel (Feature 5) */}
          <div className="triage-panel">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
              <div>
                <span className="eyebrow" style={{ color: 'var(--accent)' }}>TRIAGE ASISTIDO POR IA</span>
                <h4 style={{ margin: '2px 0 0', fontSize: '14px', color: 'var(--text-main)' }}>
                  Veredicto:{' '}
                  <span className={`status status-${verdictClass}`} style={{ textTransform: 'uppercase', fontWeight: 700 }}>
                    {triageVerdict}
                  </span>
                </h4>
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                Decidido por: <strong style={{ color: 'var(--text-main)' }}>{decidedBy}</strong>
                {triageConfidence !== null && ` (${(triageConfidence * 100).toFixed(0)}% confianza)`}
              </div>
            </div>

            {triageReason && (
              <p style={{ margin: '0 0 12px', fontSize: '13px', color: 'var(--text-main)', lineHeight: 1.5, background: 'var(--bg-inset)', padding: '8px 12px', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <strong>Motivo actual:</strong> {triageReason}
              </p>
            )}

            {triageAuthor && (
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '12px' }}>
                Registrado por: <code>{triageAuthor}</code> en <span>{triageTimestamp}</span>
                {finding.triage?.fingerprint && (
                  <span style={{ marginLeft: '8px', fontFamily: 'var(--font-mono)' }}>
                    [Huella: {finding.triage.fingerprint.slice(0, 10)}...]
                  </span>
                )}
              </div>
            )}

            {/* Human Triage Action Controls */}
            {onTriageDecision && (
              <div style={{ marginTop: '14px', paddingTop: '14px', borderTop: '1px solid var(--border-subtle)' }}>
                <h5 style={{ margin: '0 0 8px', fontSize: '13px', color: 'var(--text-main)' }}>
                  Revisión Humana / Cambiar Decisión (motivo obligatorio):
                </h5>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '8px', marginBottom: '12px' }}>
                  <textarea
                    placeholder="Escribí el motivo detallado de tu decisión (obligatorio)..."
                    value={reason}
                    onChange={(e) => { setReason(e.target.value); setError(''); }}
                    rows={2}
                  />
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Analista:</span>
                    <input
                      type="text"
                      value={author}
                      onChange={(e) => setAuthor(e.target.value)}
                      style={{ width: '200px' }}
                    />
                  </div>
                </div>

                {error && <p style={{ color: 'var(--crimson)', fontSize: '12px', margin: '0 0 8px', fontWeight: 600 }}>{error}</p>}
                {successMsg && <p style={{ color: 'var(--emerald)', fontSize: '12px', margin: '0 0 8px', fontWeight: 600 }}>{successMsg}</p>}

                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    className="btn-success"
                    disabled={isSubmitting}
                    onClick={() => handleAction('verdadero')}
                  >
                    Confirmar (Verdadero)
                  </button>
                  <button
                    type="button"
                    className="btn-danger"
                    disabled={isSubmitting}
                    onClick={() => handleAction('falso')}
                  >
                    Falso positivo (Guardar huella)
                  </button>
                  <button
                    type="button"
                    className="btn-secondary"
                    style={{ borderColor: 'var(--amber)', color: 'var(--amber)' }}
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
          <div className="remediation-panel">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
              <div>
                <span className="eyebrow" style={{ color: 'var(--emerald)' }}>CORRECCIÓN ASISTIDA Y VERIFICACIÓN AUTOMATIZADA</span>
                <h4 style={{ margin: '2px 0 0', fontSize: '14px', color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span>Estado del hallazgo:</span>
                  <span style={{
                    padding: '2px 8px',
                    borderRadius: '4px',
                    fontSize: '11px',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    background:
                      remStatus === 'verified' ? 'var(--emerald-bg)' :
                      remStatus === 'approved' ? 'var(--emerald-bg)' :
                      remStatus === 'discarded' ? 'var(--crimson-bg)' :
                      remStatus === 'rejected' ? 'var(--crimson-bg)' :
                      remStatus === 'patch_proposed' ? 'var(--amber-bg)' : 'var(--bg-inset)',
                    color:
                      remStatus === 'verified' ? 'var(--emerald)' :
                      remStatus === 'approved' ? 'var(--emerald)' :
                      remStatus === 'discarded' ? 'var(--crimson)' :
                      remStatus === 'rejected' ? 'var(--crimson)' :
                      remStatus === 'patch_proposed' ? 'var(--amber)' : 'var(--text-secondary)',
                    border: `1px solid ${
                      remStatus === 'verified' ? 'var(--emerald-border)' :
                      remStatus === 'approved' ? 'var(--emerald-border)' :
                      remStatus === 'discarded' ? 'var(--crimson-border)' :
                      remStatus === 'rejected' ? 'var(--crimson-border)' :
                      remStatus === 'patch_proposed' ? 'var(--amber-border)' : 'var(--border-medium)'
                    }`,
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
                  disabled={isProposingFix}
                  onClick={handleProposeFix}
                >
                  {isProposingFix ? 'Generando corrección...' : '⚡ Proponer Corrección Asistida'}
                </button>
              )}
            </div>

            {/* Explanation */}
            {remediation.explanation && (
              <p style={{ margin: '0 0 12px', fontSize: '13px', color: 'var(--text-main)', lineHeight: 1.5, background: 'var(--bg-inset)', padding: '8px 12px', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <strong>Explicación:</strong> {remediation.explanation}
              </p>
            )}

            {/* Verification result callout */}
            {remediation.verification && (
              <div style={{
                background: remediation.verification.verified ? 'var(--emerald-bg)' : 'var(--crimson-bg)',
                border: `1px solid ${remediation.verification.verified ? 'var(--emerald-border)' : 'var(--crimson-border)'}`,
                color: remediation.verification.verified ? 'var(--emerald)' : 'var(--crimson)',
                padding: '10px 14px',
                borderRadius: '6px',
                fontSize: '13px',
                marginBottom: '12px',
                fontWeight: 500,
              }}>
                <strong>{remediation.verification.verified ? '✓ Re-verificación exitosa: ' : '✕ Verificación descartada: '}</strong>
                {remediation.verification.message}
                {remediation.verification.new_findings && remediation.verification.new_findings.length > 0 && (
                  <ul style={{ margin: '6px 0 0', paddingLeft: '20px' }}>
                    {remediation.verification.new_findings.map((nf, i) => (
                      <li key={i}>{nf.rule} (Línea {nf.line}): {nf.message}</li>
                    ))}
                  </ul>
                )}
              </div>
            )}

            {/* Human review audit info if reviewed */}
            {remediation.reviewed_by && (
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '12px', background: 'var(--bg-inset)', padding: '8px 12px', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                Revisión humana: <strong style={{ color: remStatus === 'approved' ? 'var(--emerald)' : 'var(--crimson)' }}>{remStatus.toUpperCase()}</strong> por <code>{remediation.reviewer}</code> en {new Date(remediation.review_timestamp).toLocaleString()}
                <br />
                <span style={{ color: 'var(--text-main)' }}>Motivo: "{remediation.review_reason}"</span>
              </div>
            )}

            {/* Diff View (Side-by-side or Unified) */}
            {hasDiff && (
              <div style={{ marginTop: '12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-main)' }}>
                    Revisión del Parche ({remediation.touched_files?.join(', ') || finding.file}):
                  </span>
                  <div style={{ display: 'flex', gap: '4px' }}>
                    <button
                      type="button"
                      className={`btn-secondary ${diffViewMode === 'split' ? 'active-filter' : ''}`}
                      style={{ height: '28px', padding: '0 10px', fontSize: '11px' }}
                      onClick={() => setDiffViewMode('split')}
                    >
                      Lado a Lado
                    </button>
                    <button
                      type="button"
                      className={`btn-secondary ${diffViewMode === 'unified' ? 'active-filter' : ''}`}
                      style={{ height: '28px', padding: '0 10px', fontSize: '11px' }}
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
              <div style={{ marginTop: '14px', paddingTop: '14px', borderTop: '1px solid var(--border-subtle)' }}>
                <h5 style={{ margin: '0 0 8px', fontSize: '13px', color: 'var(--text-main)' }}>
                  Aprobar o Rechazar Parche (motivo obligatorio):
                </h5>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '8px', marginBottom: '12px' }}>
                  <textarea
                    placeholder="Escribí el motivo técnico para aprobar o rechazar este parche (obligatorio)..."
                    value={remReason}
                    onChange={(e) => { setRemReason(e.target.value); setRemError(''); }}
                    rows={2}
                  />
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Revisor:</span>
                    <input
                      type="text"
                      value={remAuthor}
                      onChange={(e) => setRemAuthor(e.target.value)}
                      style={{ width: '200px' }}
                    />
                  </div>
                </div>

                {remError && <p style={{ color: 'var(--crimson)', fontSize: '12px', margin: '0 0 8px', fontWeight: 600 }}>{remError}</p>}
                {remSuccessMsg && <p style={{ color: 'var(--emerald)', fontSize: '12px', margin: '0 0 8px', fontWeight: 600 }}>{remSuccessMsg}</p>}

                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    className="btn-success"
                    disabled={isRemSubmitting}
                    onClick={() => handleRemediationReview('approved')}
                  >
                    ✓ Aprobar Parche
                  </button>
                  <button
                    type="button"
                    className="btn-danger"
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
                  <div key={ctx.line} style={{ display: 'flex', gap: '16px' }}>
                    <span style={{ color: '#64748b', userSelect: 'none', width: '32px', textAlign: 'right', fontFamily: 'var(--font-mono)' }}>
                      {ctx.line}
                    </span>
                    <span style={{ color: '#f8fafc' }}>{ctx.text}</span>
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
