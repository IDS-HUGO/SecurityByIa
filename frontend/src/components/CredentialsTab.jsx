import React, { useState, useEffect } from 'react';
import api from '../api/client';

export default function CredentialsTab() {
  const [activeSubTab, setActiveSubTab] = useState('sites'); // 'sites', 'approvals', 'sessions', 'audit'
  const [sites, setSites] = useState([]);
  const [approvals, setApprovals] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [audit, setAudit] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  // Modal para agregar credencial
  const [showAddModal, setShowAddModal] = useState(false);
  const [formStep, setFormStep] = useState(1);
  const [showPassword, setShowPassword] = useState(false);
  const [formData, setFormData] = useState({
    site_id: '',
    allowed_origin: '',
    username: '',
    password: '',
    totp_seed: '',
    require_approval: 'always',
    max_ttl_seconds: 1800,
    owner: 'analista@neurotry.local',
    description: '',
  });

  // Modal de acción sobre aprobación
  const [approvalModal, setApprovalModal] = useState(null); // { req, action: 'approve' | 'reject' }
  const [approvalReason, setApprovalReason] = useState('');

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [sitesRes, approvalsRes, sessionsRes, auditRes] = await Promise.all([
        api.listCredentialSites().catch(() => ({ sites: [] })),
        api.listCredentialApprovals().catch(() => ({ approvals: [] })),
        api.listCredentialSessions().catch(() => ({ sessions: [] })),
        api.getCredentialAudit(50).catch(() => ({ audit: [] })),
      ]);
      setSites(sitesRes.sites || []);
      setApprovals(approvalsRes.approvals || []);
      setSessions(sessionsRes.sessions || []);
      setAudit(auditRes.audit || []);
    } catch (err) {
      setError('Error al sincronizar datos del Credential Broker: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 15000); // Polling suave cada 15s
    return () => clearInterval(interval);
  }, []);

  const handleCreateSite = async (e) => {
    e.preventDefault();
    if (!formData.site_id || !formData.allowed_origin || !formData.username || !formData.password) {
      setError('Por favor complete todos los campos obligatorios del sitio y credencial.');
      return;
    }
    setLoading(true);
    try {
      await api.registerCredentialSite(formData);
      setSuccessMsg(`Sitio '${formData.site_id}' integrado exitosamente en la bóveda segura.`);
      setShowAddModal(false);
      setFormData({
        site_id: '',
        allowed_origin: '',
        username: '',
        password: '',
        totp_seed: '',
        require_approval: 'always',
        max_ttl_seconds: 1800,
        owner: 'analista@neurotry.local',
        description: '',
      });
      setFormStep(1);
      await loadData();
    } catch (err) {
      setError('Error al guardar credencial en la bóveda: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleApprovalAction = async (requestId, action, reason) => {
    try {
      await api.actOnCredentialApproval(requestId, {
        action,
        reviewer: 'analista_operador',
        reason: reason || (action === 'approve' ? 'Acceso autorizado' : 'Acceso denegado'),
      });
      setSuccessMsg(`Solicitud ${action === 'approve' ? 'aprobada' : 'rechazada'} correctamente.`);
      setApprovalModal(null);
      setApprovalReason('');
      await loadData();
    } catch (err) {
      setError('No se pudo procesar la solicitud: ' + err.message);
    }
  };

  const handleRevokeSession = async (sessionId) => {
    if (!window.confirm('¿Está seguro de revocar inmediatamente esta sesión delegada? El agente perderá acceso al instante.')) {
      return;
    }
    try {
      await api.revokeCredentialSession(sessionId);
      setSuccessMsg(`Sesión delegada revocada inmediatamente.`);
      await loadData();
    } catch (err) {
      setError('Error al revocar sesión: ' + err.message);
    }
  };

  const pendingApprovals = approvals.filter((a) => a.status === 'pending');

  return (
    <div className="tab-pane credentials-tab">
      {/* Encabezado y resumen de seguridad */}
      <div className="section-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.25rem' }}>
            <h2 style={{ margin: 0 }}>Acceso Web Delegado y Credenciales (F12)</h2>
            <span className="badge" style={{ background: 'rgba(34, 197, 94, 0.15)', color: '#22c55e', border: '1px solid rgba(34, 197, 94, 0.3)', padding: '0.2rem 0.6rem', borderRadius: '4px', fontSize: '0.75rem', fontWeight: 600 }}>
              🔒 Zero LLM Exposure
            </span>
          </div>
          <p className="section-desc" style={{ maxWidth: '850px', margin: 0 }}>
            Permite que agentes de IA auditen y naveguen aplicaciones con cuentas privadas sin conocer jamás contraseñas, semillas TOTP ni tokens en su contexto. Toda credencial se custodia en bóveda protegida (0600) y se inyecta por el worker de confianza.
          </p>
        </div>

        <button
          className="btn btn-primary"
          onClick={() => { setShowAddModal(true); setFormStep(1); }}
          style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.65rem 1.25rem', fontWeight: 600 }}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M12 5v14M5 12h14"/></svg>
          Integrar Nueva Credencial
        </button>
      </div>

      {/* Alertas informativas */}
      {error && (
        <div className="alert alert-danger" style={{ marginTop: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>{error}</span>
          <button className="btn-close" onClick={() => setError(null)}>✕</button>
        </div>
      )}
      {successMsg && (
        <div className="alert alert-success" style={{ marginTop: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>{successMsg}</span>
          <button className="btn-close" onClick={() => setSuccessMsg(null)}>✕</button>
        </div>
      )}

      {/* KPIs Rápidos */}
      <div className="kpi-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem', margin: '1.5rem 0' }}>
        <div className="kpi-card" style={{ padding: '1.25rem', background: 'var(--card-bg, #1e293b)', borderRadius: '8px', border: '1px solid var(--border-color, #334155)' }}>
          <div style={{ color: 'var(--text-muted, #94a3b8)', fontSize: '0.85rem' }}>Sitios en Bóveda</div>
          <div style={{ fontSize: '1.8rem', fontWeight: 700, marginTop: '0.25rem' }}>{sites.length}</div>
          <div style={{ fontSize: '0.75rem', color: '#22c55e', marginTop: '0.25rem' }}>Cifrados con permisos 0600</div>
        </div>

        <div className="kpi-card" style={{ padding: '1.25rem', background: pendingApprovals.length > 0 ? 'rgba(234, 179, 8, 0.08)' : 'var(--card-bg, #1e293b)', borderRadius: '8px', border: pendingApprovals.length > 0 ? '1px solid rgba(234, 179, 8, 0.4)' : '1px solid var(--border-color, #334155)' }}>
          <div style={{ color: 'var(--text-muted, #94a3b8)', fontSize: '0.85rem' }}>Aprobaciones Pendientes</div>
          <div style={{ fontSize: '1.8rem', fontWeight: 700, marginTop: '0.25rem', color: pendingApprovals.length > 0 ? '#eab308' : 'inherit' }}>
            {pendingApprovals.length}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted, #94a3b8)', marginTop: '0.25rem' }}>
            {pendingApprovals.length > 0 ? 'Requieren intervención humana' : 'Sin solicitudes pendientes'}
          </div>
        </div>

        <div className="kpi-card" style={{ padding: '1.25rem', background: 'var(--card-bg, #1e293b)', borderRadius: '8px', border: '1px solid var(--border-color, #334155)' }}>
          <div style={{ color: 'var(--text-muted, #94a3b8)', fontSize: '0.85rem' }}>Sesiones Activas</div>
          <div style={{ fontSize: '1.8rem', fontWeight: 700, marginTop: '0.25rem', color: sessions.length > 0 ? '#38bdf8' : 'inherit' }}>
            {sessions.length}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted, #94a3b8)', marginTop: '0.25rem' }}>Tokens opacos efímeros</div>
        </div>

        <div className="kpi-card" style={{ padding: '1.25rem', background: 'var(--card-bg, #1e293b)', borderRadius: '8px', border: '1px solid var(--border-color, #334155)' }}>
          <div style={{ color: 'var(--text-muted, #94a3b8)', fontSize: '0.85rem' }}>Eventos Auditados</div>
          <div style={{ fontSize: '1.8rem', fontWeight: 700, marginTop: '0.25rem' }}>{audit.length}</div>
          <div style={{ fontSize: '0.75rem', color: '#a855f7', marginTop: '0.25rem' }}>Bitácora inmutable sin secretos</div>
        </div>
      </div>

      {/* Subnavegación */}
      <div className="tab-nav" style={{ display: 'flex', gap: '0.5rem', borderBottom: '1px solid var(--border-color, #334155)', marginBottom: '1.5rem' }}>
        <button
          className={`tab-btn ${activeSubTab === 'sites' ? 'active' : ''}`}
          onClick={() => setActiveSubTab('sites')}
          style={{ padding: '0.75rem 1.25rem', background: 'none', border: 'none', borderBottom: activeSubTab === 'sites' ? '2px solid #38bdf8' : '2px solid transparent', color: activeSubTab === 'sites' ? '#38bdf8' : 'var(--text-muted, #94a3b8)', fontWeight: 600, cursor: 'pointer' }}
        >
          Sitios y Bóveda ({sites.length})
        </button>
        <button
          className={`tab-btn ${activeSubTab === 'approvals' ? 'active' : ''}`}
          onClick={() => setActiveSubTab('approvals')}
          style={{ padding: '0.75rem 1.25rem', background: 'none', border: 'none', borderBottom: activeSubTab === 'approvals' ? '2px solid #38bdf8' : '2px solid transparent', color: activeSubTab === 'approvals' ? '#38bdf8' : 'var(--text-muted, #94a3b8)', fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.5rem' }}
        >
          Bandeja de Aprobación
          {pendingApprovals.length > 0 && (
            <span style={{ background: '#eab308', color: '#000', fontSize: '0.7rem', padding: '0.1rem 0.45rem', borderRadius: '10px', fontWeight: 700 }}>
              {pendingApprovals.length}
            </span>
          )}
        </button>
        <button
          className={`tab-btn ${activeSubTab === 'sessions' ? 'active' : ''}`}
          onClick={() => setActiveSubTab('sessions')}
          style={{ padding: '0.75rem 1.25rem', background: 'none', border: 'none', borderBottom: activeSubTab === 'sessions' ? '2px solid #38bdf8' : '2px solid transparent', color: activeSubTab === 'sessions' ? '#38bdf8' : 'var(--text-muted, #94a3b8)', fontWeight: 600, cursor: 'pointer' }}
        >
          Sesiones Concedidas ({sessions.length})
        </button>
        <button
          className={`tab-btn ${activeSubTab === 'audit' ? 'active' : ''}`}
          onClick={() => setActiveSubTab('audit')}
          style={{ padding: '0.75rem 1.25rem', background: 'none', border: 'none', borderBottom: activeSubTab === 'audit' ? '2px solid #38bdf8' : '2px solid transparent', color: activeSubTab === 'audit' ? '#38bdf8' : 'var(--text-muted, #94a3b8)', fontWeight: 600, cursor: 'pointer' }}
        >
          Auditoría de Acceso
        </button>
      </div>

      {/* VISTA 1: SITIOS Y BÓVEDA */}
      {activeSubTab === 'sites' && (
        <div>
          {sites.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '3rem', background: 'var(--card-bg, #1e293b)', borderRadius: '8px', border: '1px dashed var(--border-color, #334155)' }}>
              <div style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>🔐</div>
              <h3 style={{ margin: '0 0 0.5rem 0' }}>No hay sitios integrados todavía</h3>
              <p style={{ color: 'var(--text-muted, #94a3b8)', maxWidth: '500px', margin: '0 auto 1.5rem auto' }}>
                Integre las credenciales de las aplicaciones internas o servicios a auditar para que los agentes puedan realizar verificaciones delegadas sin ver la contraseña.
              </p>
              <button className="btn btn-primary" onClick={() => setShowAddModal(true)}>
                + Integrar Primer Sitio
              </button>
            </div>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: '1.25rem' }}>
              {sites.map((site) => (
                <div key={site.site_id} style={{ background: 'var(--card-bg, #1e293b)', borderRadius: '8px', border: '1px solid var(--border-color, #334155)', padding: '1.25rem', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
                      <h4 style={{ margin: 0, fontSize: '1.1rem', color: '#f8fafc' }}>{site.site_id}</h4>
                      <span className="badge" style={{ background: site.require_approval === 'always' ? 'rgba(234, 179, 8, 0.2)' : 'rgba(56, 189, 248, 0.2)', color: site.require_approval === 'always' ? '#eab308' : '#38bdf8', fontSize: '0.7rem', padding: '0.2rem 0.5rem', borderRadius: '4px' }}>
                        {site.require_approval === 'always' ? 'Aprobación Estricta' : site.require_approval === 'once' ? 'Aprobación Única' : 'Auto'}
                      </span>
                    </div>

                    <div style={{ fontSize: '0.85rem', color: '#38bdf8', fontFamily: 'monospace', wordBreak: 'break-all', marginBottom: '0.75rem' }}>
                      🌐 {site.allowed_origin}
                    </div>

                    {site.description && (
                      <p style={{ fontSize: '0.85rem', color: 'var(--text-muted, #94a3b8)', margin: '0 0 0.75rem 0' }}>
                        {site.description}
                      </p>
                    )}

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.8rem', color: 'var(--text-muted, #94a3b8)', borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '0.75rem' }}>
                      <div>👤 <strong>Usuario:</strong> {site.username || 'N/A'}</div>
                      <div>🔑 <strong>MFA / TOTP:</strong> {site.has_totp ? '✅ Configurado en bóveda' : '❌ No configurado'}</div>
                      <div>⏱️ <strong>TTL Máximo:</strong> {Math.round(site.max_ttl_seconds / 60)} minutos</div>
                      <div>🛡️ <strong>Responsable:</strong> {site.owner}</div>
                    </div>
                  </div>

                  <div style={{ marginTop: '1rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border-color, #334155)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '0.75rem', color: '#22c55e' }}>● Bóveda protegida (0600)</span>
                    <button
                      className="btn btn-sm btn-outline"
                      onClick={() => {
                        alert(`Configuración de política para ${site.site_id}:\nOrigen exacto: ${site.allowed_origin}\nAcciones prohibidas: ${site.forbidden_actions?.join(', ') || 'Ninguna'}`);
                      }}
                      style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem' }}
                    >
                      Ver Política
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* VISTA 2: BANDEJA DE APROBACIONES */}
      {activeSubTab === 'approvals' && (
        <div>
          {approvals.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '3rem', background: 'var(--card-bg, #1e293b)', borderRadius: '8px' }}>
              <p style={{ color: 'var(--text-muted, #94a3b8)', margin: 0 }}>No hay solicitudes de aprobación registradas.</p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {approvals.map((req) => (
                <div
                  key={req.request_id}
                  style={{
                    padding: '1.25rem',
                    background: req.status === 'pending' ? 'rgba(234, 179, 8, 0.05)' : 'var(--card-bg, #1e293b)',
                    borderRadius: '8px',
                    border: req.status === 'pending' ? '1px solid rgba(234, 179, 8, 0.4)' : '1px solid var(--border-color, #334155)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    flexWrap: 'wrap',
                    gap: '1rem'
                  }}
                >
                  <div style={{ maxWidth: '650px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                      <strong style={{ fontSize: '1rem' }}>{req.site_id}</strong>
                      <span className="badge" style={{
                        background: req.status === 'pending' ? '#eab308' : req.status === 'approved' ? '#22c55e' : '#ef4444',
                        color: '#000',
                        fontSize: '0.7rem',
                        fontWeight: 700,
                        padding: '0.15rem 0.5rem',
                        borderRadius: '4px'
                      }}>
                        {req.status.toUpperCase()}
                      </span>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted, #94a3b8)', fontFamily: 'monospace' }}>
                        ID: {req.request_id}
                      </span>
                    </div>

                    <div style={{ fontSize: '0.85rem', color: 'var(--text-muted, #94a3b8)', marginBottom: '0.35rem' }}>
                      🤖 <strong>Agente:</strong> {req.agent_id} | 🎯 <strong>Propósito:</strong> {req.task_purpose}
                    </div>

                    <div style={{ fontSize: '0.8rem', color: '#38bdf8', fontFamily: 'monospace' }}>
                      🌐 Origen: {req.target_origin} | ⏱️ Duración: {Math.round(req.requested_ttl_seconds / 60)} min
                    </div>

                    {req.decided_by && (
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted, #94a3b8)', marginTop: '0.35rem' }}>
                        Decisión por: <strong>{req.decided_by}</strong> ({req.decision_reason})
                      </div>
                    )}
                  </div>

                  {req.status === 'pending' && (
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <button
                        className="btn btn-sm"
                        onClick={() => setApprovalModal({ req, action: 'approve' })}
                        style={{ background: '#22c55e', color: '#000', fontWeight: 600, padding: '0.5rem 1rem', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
                      >
                        ✓ Aprobar Acceso
                      </button>
                      <button
                        className="btn btn-sm"
                        onClick={() => setApprovalModal({ req, action: 'reject' })}
                        style={{ background: '#ef4444', color: '#fff', fontWeight: 600, padding: '0.5rem 1rem', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
                      >
                        ✕ Denegar
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* VISTA 3: SESIONES ACTIVAS */}
      {activeSubTab === 'sessions' && (
        <div>
          {sessions.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '3rem', background: 'var(--card-bg, #1e293b)', borderRadius: '8px' }}>
              <p style={{ color: 'var(--text-muted, #94a3b8)', margin: 0 }}>No hay sesiones delegadas activas en este momento.</p>
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table" style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-color, #334155)', color: 'var(--text-muted, #94a3b8)', fontSize: '0.85rem' }}>
                    <th style={{ padding: '0.75rem' }}>Session ID</th>
                    <th style={{ padding: '0.75rem' }}>Sitio</th>
                    <th style={{ padding: '0.75rem' }}>Agente</th>
                    <th style={{ padding: '0.75rem' }}>Origen Autorizado</th>
                    <th style={{ padding: '0.75rem' }}>Expira en</th>
                    <th style={{ padding: '0.75rem', textAlign: 'right' }}>Acción</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((sess) => {
                    const timeLeftSec = Math.max(0, Math.round(sess.expires_at - Date.now() / 1000));
                    const timeLeftMin = Math.round(timeLeftSec / 60);
                    return (
                      <tr key={sess.session_id} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)', fontSize: '0.85rem' }}>
                        <td style={{ padding: '0.75rem', fontFamily: 'monospace', color: '#38bdf8' }}>{sess.session_id}</td>
                        <td style={{ padding: '0.75rem', fontWeight: 600 }}>{sess.site_id}</td>
                        <td style={{ padding: '0.75rem' }}>{sess.agent_id}</td>
                        <td style={{ padding: '0.75rem', fontFamily: 'monospace', color: 'var(--text-muted, #94a3b8)' }}>{sess.allowed_origin}</td>
                        <td style={{ padding: '0.75rem' }}>
                          <span style={{ color: timeLeftMin < 5 ? '#ef4444' : '#22c55e', fontWeight: 600 }}>
                            {timeLeftMin} min ({timeLeftSec}s)
                          </span>
                        </td>
                        <td style={{ padding: '0.75rem', textAlign: 'right' }}>
                          <button
                            className="btn btn-sm"
                            onClick={() => handleRevokeSession(sess.session_id)}
                            style={{ background: 'rgba(239, 68, 68, 0.2)', color: '#ef4444', border: '1px solid rgba(239, 68, 68, 0.4)', padding: '0.35rem 0.75rem', borderRadius: '4px', cursor: 'pointer', fontWeight: 600 }}
                          >
                            Revocar
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* VISTA 4: AUDITORÍA */}
      {activeSubTab === 'audit' && (
        <div>
          <div style={{ marginBottom: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.85rem', color: 'var(--text-muted, #94a3b8)' }}>
              Últimos registros de auditoría del broker de credenciales (cero secretos garantizados).
            </span>
            <button className="btn btn-sm btn-outline" onClick={loadData}>
              Actualizar Bitácora
            </button>
          </div>

          {audit.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '3rem', background: 'var(--card-bg, #1e293b)', borderRadius: '8px' }}>
              <p style={{ color: 'var(--text-muted, #94a3b8)', margin: 0 }}>Sin registros de auditoría.</p>
            </div>
          ) : (
            <div style={{ overflowX: 'auto', background: 'var(--card-bg, #1e293b)', borderRadius: '8px', border: '1px solid var(--border-color, #334155)' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-color, #334155)', color: 'var(--text-muted, #94a3b8)' }}>
                    <th style={{ padding: '0.75rem' }}>Fecha/Hora (UTC)</th>
                    <th style={{ padding: '0.75rem' }}>Evento</th>
                    <th style={{ padding: '0.75rem' }}>Sitio</th>
                    <th style={{ padding: '0.75rem' }}>Agente / Operador</th>
                    <th style={{ padding: '0.75rem' }}>Estado</th>
                    <th style={{ padding: '0.75rem' }}>Detalles (Sanitizados)</th>
                  </tr>
                </thead>
                <tbody>
                  {audit.map((entry, idx) => (
                    <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                      <td style={{ padding: '0.65rem 0.75rem', fontFamily: 'monospace', color: 'var(--text-muted, #94a3b8)' }}>
                        {entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : 'N/A'}
                      </td>
                      <td style={{ padding: '0.65rem 0.75rem', fontWeight: 600 }}>{entry.event_type}</td>
                      <td style={{ padding: '0.65rem 0.75rem' }}>{entry.site_id}</td>
                      <td style={{ padding: '0.65rem 0.75rem' }}>{entry.agent_id}</td>
                      <td style={{ padding: '0.65rem 0.75rem' }}>
                        <span style={{
                          color: entry.status.includes('block') || entry.status.includes('fail') ? '#ef4444' : '#22c55e',
                          fontWeight: 600
                        }}>
                          {entry.status}
                        </span>
                      </td>
                      <td style={{ padding: '0.65rem 0.75rem', fontFamily: 'monospace', color: 'var(--text-muted, #94a3b8)', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {JSON.stringify(entry.details || {})}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* MODAL INTUITIVO: INTEGRAR NUEVA CREDENCIAL */}
      {showAddModal && (
        <div className="modal-backdrop" style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '1rem' }}>
          <div className="modal-content" style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '12px', width: '100%', maxWidth: '640px', maxHeight: '90vh', overflowY: 'auto', padding: '1.75rem', boxShadow: '0 20px 25px -5px rgba(0,0,0,0.5)' }}>
            
            {/* Header del Modal */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', borderBottom: '1px solid #334155', pb: '1rem' }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '1.25rem' }}>Integrar Credencial a Bóveda Segura</h3>
                <small style={{ color: '#94a3b8' }}>Paso {formStep} de 2 — Configuración y Políticas</small>
              </div>
              <button
                onClick={() => setShowAddModal(false)}
                style={{ background: 'none', border: 'none', color: '#94a3b8', fontSize: '1.5rem', cursor: 'pointer' }}
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateSite}>
              {formStep === 1 && (
                <div>
                  <div style={{ background: 'rgba(56, 189, 248, 0.08)', border: '1px solid rgba(56, 189, 248, 0.3)', borderRadius: '8px', padding: '0.85rem', marginBottom: '1.25rem', fontSize: '0.85rem', color: '#bae6fd' }}>
                    💡 <strong>Protección de origen estricta:</strong> El agente solo podrá autenticarse en el origen exacto configurado. Si una página maliciosa intenta redirigir el login a otro dominio, el broker detendrá la operación de inmediato.
                  </div>

                  <div className="form-group" style={{ marginBottom: '1rem' }}>
                    <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.35rem' }}>
                      Identificador del Sitio / Sistema *
                    </label>
                    <input
                      type="text"
                      className="form-control"
                      placeholder="ej. portal-finanzas-interno"
                      value={formData.site_id}
                      onChange={(e) => setFormData({ ...formData, site_id: e.target.value })}
                      required
                      style={{ width: '100%', padding: '0.6rem', borderRadius: '6px', background: '#0f172a', border: '1px solid #334155', color: '#fff' }}
                    />
                  </div>

                  <div className="form-group" style={{ marginBottom: '1rem' }}>
                    <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.35rem' }}>
                      Origen Exacto Permitido (Protocolo + Host + Puerto) *
                    </label>
                    <input
                      type="url"
                      className="form-control"
                      placeholder="https://intranet.miempresa.com o http://127.0.0.1:5050"
                      value={formData.allowed_origin}
                      onChange={(e) => setFormData({ ...formData, allowed_origin: e.target.value })}
                      required
                      style={{ width: '100%', padding: '0.6rem', borderRadius: '6px', background: '#0f172a', border: '1px solid #334155', color: '#fff' }}
                    />
                    <small style={{ color: '#94a3b8', fontSize: '0.75rem' }}>Sin rutas posteriores ni comodines. Ejemplo: https://intranet.local:8443</small>
                  </div>

                  <div className="form-group" style={{ marginBottom: '1rem' }}>
                    <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.35rem' }}>
                      Descripción o Propósito
                    </label>
                    <input
                      type="text"
                      className="form-control"
                      placeholder="ej. Portal administrativo para verificación de controles RBAC"
                      value={formData.description}
                      onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                      style={{ width: '100%', padding: '0.6rem', borderRadius: '6px', background: '#0f172a', border: '1px solid #334155', color: '#fff' }}
                    />
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '1.5rem' }}>
                    <button
                      type="button"
                      className="btn btn-primary"
                      onClick={() => {
                        if (!formData.site_id || !formData.allowed_origin) {
                          alert('Por favor ingrese el ID del sitio y el origen exacto.');
                          return;
                        }
                        setFormStep(2);
                      }}
                      style={{ padding: '0.65rem 1.25rem', fontWeight: 600 }}
                    >
                      Siguiente: Credenciales y Políticas →
                    </button>
                  </div>
                </div>
              )}

              {formStep === 2 && (
                <div>
                  <div className="form-group" style={{ marginBottom: '1rem' }}>
                    <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.35rem' }}>
                      Usuario / Cuenta de Servicio del Agente *
                    </label>
                    <input
                      type="text"
                      className="form-control"
                      placeholder="ej. sec_agent_service"
                      value={formData.username}
                      onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                      required
                      style={{ width: '100%', padding: '0.6rem', borderRadius: '6px', background: '#0f172a', border: '1px solid #334155', color: '#fff' }}
                    />
                  </div>

                  <div className="form-group" style={{ marginBottom: '1rem' }}>
                    <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.35rem' }}>
                      Contraseña / Secreto *
                    </label>
                    <div style={{ position: 'relative' }}>
                      <input
                        type={showPassword ? 'text' : 'password'}
                        className="form-control"
                        placeholder="Contraseña del servicio"
                        value={formData.password}
                        onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                        required
                        style={{ width: '100%', padding: '0.6rem 2.5rem 0.6rem 0.6rem', borderRadius: '6px', background: '#0f172a', border: '1px solid #334155', color: '#fff' }}
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        style={{ position: 'absolute', right: '0.6rem', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer' }}
                      >
                        {showPassword ? '👁️' : '🙈'}
                      </button>
                    </div>
                    <small style={{ color: '#22c55e', fontSize: '0.75rem' }}>
                      ✓ Se cifra en la bóveda con permisos 0600. Jamás se comparte con el LLM.
                    </small>
                  </div>

                  <div className="form-group" style={{ marginBottom: '1rem' }}>
                    <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.35rem' }}>
                      Semilla TOTP / MFA (Opcional, Base32)
                    </label>
                    <input
                      type="text"
                      className="form-control"
                      placeholder="ej. JBSWY3DPEHPK3PXP"
                      value={formData.totp_seed}
                      onChange={(e) => setFormData({ ...formData, totp_seed: e.target.value.toUpperCase() })}
                      style={{ width: '100%', padding: '0.6rem', borderRadius: '6px', background: '#0f172a', border: '1px solid #334155', color: '#fff', fontFamily: 'monospace' }}
                    />
                    <small style={{ color: '#94a3b8', fontSize: '0.75rem' }}>Si la cuenta exige 2FA, el worker de confianza generará el código TOTP internamente.</small>
                  </div>

                  <div className="form-group" style={{ marginBottom: '1.25rem' }}>
                    <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.35rem' }}>
                      Política de Aprobación Humana
                    </label>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                      <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: '#0f172a', padding: '0.6rem', borderRadius: '6px', border: formData.require_approval === 'always' ? '1px solid #38bdf8' : '1px solid #334155', cursor: 'pointer' }}>
                        <input
                          type="radio"
                          name="approval"
                          value="always"
                          checked={formData.require_approval === 'always'}
                          onChange={() => setFormData({ ...formData, require_approval: 'always' })}
                        />
                        <span style={{ fontSize: '0.8rem' }}>Exigir siempre (Recomendado)</span>
                      </label>
                      <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: '#0f172a', padding: '0.6rem', borderRadius: '6px', border: formData.require_approval === 'none' ? '1px solid #38bdf8' : '1px solid #334155', cursor: 'pointer' }}>
                        <input
                          type="radio"
                          name="approval"
                          value="none"
                          checked={formData.require_approval === 'none'}
                          onChange={() => setFormData({ ...formData, require_approval: 'none' })}
                        />
                        <span style={{ fontSize: '0.8rem' }}>Automatizado (Sin bloqueo)</span>
                      </label>
                    </div>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '1.5rem' }}>
                    <button
                      type="button"
                      className="btn btn-outline"
                      onClick={() => setFormStep(1)}
                    >
                      ← Volver
                    </button>
                    <button
                      type="submit"
                      className="btn btn-primary"
                      disabled={loading}
                      style={{ padding: '0.65rem 1.5rem', fontWeight: 600 }}
                    >
                      {loading ? 'Guardando...' : 'Guardar e Integrar en Bóveda'}
                    </button>
                  </div>
                </div>
              )}
            </form>
          </div>
        </div>
      )}

      {/* MODAL DECISIÓN DE APROBACIÓN */}
      {approvalModal && (
        <div className="modal-backdrop" style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '1rem' }}>
          <div className="modal-content" style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '12px', width: '100%', maxWidth: '480px', padding: '1.5rem' }}>
            <h3 style={{ margin: '0 0 1rem 0' }}>
              {approvalModal.action === 'approve' ? 'Autorizar Acceso de Agente' : 'Rechazar Acceso de Agente'}
            </h3>
            <p style={{ fontSize: '0.9rem', color: '#94a3b8' }}>
              El agente <strong>{approvalModal.req.agent_id}</strong> solicita acceso para <em>"{approvalModal.req.task_purpose}"</em> sobre el sitio <strong>{approvalModal.req.site_id}</strong> ({approvalModal.req.target_origin}).
            </p>
            <div className="form-group" style={{ margin: '1rem 0' }}>
              <label style={{ display: 'block', fontSize: '0.85rem', marginBottom: '0.35rem' }}>Motivo de la Decisión:</label>
              <input
                type="text"
                className="form-control"
                placeholder="Razón o ticket de autorización"
                value={approvalReason}
                onChange={(e) => setApprovalReason(e.target.value)}
                style={{ width: '100%', padding: '0.6rem', borderRadius: '6px', background: '#0f172a', border: '1px solid #334155', color: '#fff' }}
              />
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
              <button className="btn btn-outline" onClick={() => setApprovalModal(null)}>Cancelar</button>
              <button
                className="btn"
                style={{
                  background: approvalModal.action === 'approve' ? '#22c55e' : '#ef4444',
                  color: approvalModal.action === 'approve' ? '#000' : '#fff',
                  fontWeight: 600,
                  padding: '0.5rem 1rem',
                  border: 'none',
                  borderRadius: '4px'
                }}
                onClick={() => handleApprovalAction(approvalModal.req.request_id, approvalModal.action, approvalReason)}
              >
                Confirmar {approvalModal.action === 'approve' ? 'Aprobación' : 'Rechazo'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
