import React, { useState } from 'react';

export default function ScanCard({ onStartScan, isScanning }) {
  const [url, setUrl] = useState('');
  const [enableAiTriage, setEnableAiTriage] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    setError('');
    const trimmed = url.trim();
    if (!trimmed) {
      setError('Por favor ingresá una URL.');
      return;
    }
    if (!/^https?:\/\/github\.com\/[^/\s]+\/[^/\s]+(?:\.git)?\/?$/.test(trimmed)) {
      setError('Ingresá una URL válida de repositorio público de GitHub (https://github.com/org/repo).');
      return;
    }
    onStartScan(trimmed, enableAiTriage);
  };

  return (
    <section className="card scan-card">
      <div className="scan-card-header">
        <div className="scan-icon">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="m9 18 6-6-6-6"/>
          </svg>
        </div>
        <div>
          <p className="eyebrow">ESCANEO DE REPOSITORIO</p>
          <h2>Analizar repositorio de GitHub</h2>
          <p className="muted">Ejecuta análisis estático SAST, detección de secretos y clasificación asistida.</p>
        </div>
      </div>
      <form className="scan-form" onSubmit={handleSubmit}>
        <div className="input-group">
          <svg className="input-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/>
          </svg>
          <input
            type="url"
            placeholder="https://github.com/organizacion/repositorio"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={isScanning}
            required
          />
          <button type="submit" className="btn-primary" disabled={isScanning}>
            <span>{isScanning ? 'Analizando...' : 'Iniciar Análisis'}</span>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <path d="M5 12h14"/>
              <path d="m12 5 7 7-7 7"/>
            </svg>
          </button>
        </div>

        <div style={{ marginTop: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.875rem' }}>
          <label style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', color: 'var(--text-secondary, #94a3b8)' }}>
            <input
              type="checkbox"
              id="enable-ai-triage-checkbox"
              checked={enableAiTriage}
              onChange={(e) => setEnableAiTriage(e.target.checked)}
              disabled={isScanning}
              style={{ width: '16px', height: '16px', accentColor: 'var(--primary, #6366f1)', cursor: 'pointer' }}
            />
            <span>
              Habilitar <strong>Triage con IA</strong> (opt-in explícito: envía 20 líneas de contexto con secretos redactados al modelo)
            </span>
          </label>
        </div>

        {error && <p className="error-msg" role="alert">{error}</p>}
      </form>
    </section>
  );
}
