import React, { useCallback, useEffect, useState } from 'react';
import api from '../api/client';

/**
 * Vista mínima de auditoría del proxy de secretos (F8):
 * indicador de estado + tabla de auditoría (fecha, servicio, ruta, resultado
 * y token). Nunca se muestran valores secretos ni cuerpos: el backend no los
 * expone y esta vista solo renderiza los campos de la auditoría.
 */

const STATUS_LABELS = {
  ok: { text: 'Proxy operativo', color: '#10b981' },
  down: { text: 'Proxy caído (fail-closed)', color: '#ef4444' },
  unconfigured: { text: 'Proxy no configurado (clave directa)', color: '#f59e0b' },
};

const RESULT_LABELS = {
  allowed: 'Permitida',
};

function resultLabel(entry) {
  const result = String(entry.result || '');
  if (RESULT_LABELS[result]) return RESULT_LABELS[result];
  if (result.startsWith('denied:')) {
    const reason = result.slice('denied:'.length).replace(/-/g, ' ');
    return `Denegada (${reason})`;
  }
  return result || '—';
}

export default function ProxyTab() {
  const [status, setStatus] = useState(null);
  const [audit, setAudit] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [statusData, auditData] = await Promise.all([
        api.getProxyStatus(),
        api.getProxyAudit(50),
      ]);
      setStatus(statusData || {});
      setAudit(Array.isArray(auditData) ? auditData : []);
    } catch (err) {
      setError(err.message || 'No se pudo consultar el proxy.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const statusInfo = STATUS_LABELS[status?.status] || STATUS_LABELS.unconfigured;

  return (
    <div className="tab-pane active">
      <section className="card">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">F8 · PROXY DE SECRETOS Y APIs</p>
            <h2>Auditoría del Proxy</h2>
          </div>
          <button type="button" className="btn-secondary" onClick={load}>
            Actualizar
          </button>
        </div>

        <div style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '12px 16px', borderRadius: 10,
          border: `1px solid ${statusInfo.color}55`,
          background: `${statusInfo.color}14`,
          margin: '0 0 16px 0',
        }}>
          <span style={{
            width: 10, height: 10, borderRadius: '50%',
            background: statusInfo.color, display: 'inline-block',
          }} />
          <strong style={{ color: statusInfo.color }}>{statusInfo.text}</strong>
          {status?.providers?.length > 0 && (
            <span className="muted">· Lista blanca: {status.providers.join(', ')}</span>
          )}
          {status && typeof status.token_configured === 'boolean' && (
            <span className="muted">
              · Token del demo: {status.token_configured ? 'configurado' : 'sin configurar'}
            </span>
          )}
        </div>

        {loading && (
          <div className="empty-state">
            <p className="muted">Cargando auditoría del proxy…</p>
          </div>
        )}

        {!loading && error && (
          <div className="error-banner" role="alert">{error}</div>
        )}

        {!loading && !error && audit.length === 0 && (
          <div className="empty-state">
            <p className="muted">
              Sin llamadas registradas todavía. La auditoría se llena cuando los
              agentes llaman a los proveedores a través del proxy.
            </p>
          </div>
        )}

        {!loading && !error && audit.length > 0 && (
          <div className="table-wrap">
            <table className="findings-table">
              <thead>
                <tr>
                  <th>Fecha (UTC)</th>
                  <th>Servicio</th>
                  <th>Ruta</th>
                  <th>Resultado</th>
                  <th>Token</th>
                  <th style={{ textAlign: 'right' }}>HTTP</th>
                  <th style={{ textAlign: 'right' }}>Duración</th>
                </tr>
              </thead>
              <tbody>
                {audit.map((entry, index) => (
                  <tr key={`${entry.timestamp}-${index}`}>
                    <td className="text-muted" style={{ fontFamily: 'var(--font-mono, monospace)', fontSize: 11 }}>
                      {String(entry.timestamp || '').replace('T', ' ').slice(0, 19)}
                    </td>
                    <td>{entry.service || '—'}</td>
                    <td style={{ fontFamily: 'var(--font-mono, monospace)', fontSize: 11 }}>
                      {entry.route || '—'}
                    </td>
                    <td>{resultLabel(entry)}</td>
                    <td style={{ fontFamily: 'var(--font-mono, monospace)', fontSize: 11 }}>
                      {entry.token_id || '—'}
                    </td>
                    <td style={{ textAlign: 'right' }}>{entry.status_code ?? '—'}</td>
                    <td style={{ textAlign: 'right' }}>{entry.duration_ms ?? '—'} ms</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="muted" style={{ fontSize: 11, padding: '8px 4px' }}>
              La auditoría nunca registra valores secretos ni cuerpos de petición o respuesta.
            </p>
          </div>
        )}
      </section>
    </div>
  );
}
