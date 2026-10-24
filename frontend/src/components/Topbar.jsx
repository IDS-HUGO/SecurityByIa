import React from 'react';

const TAB_TITLES = {
  overview: 'Panel de Control & Análisis SAST',
  findings: 'Hallazgos de Seguridad & Remediaciones',
  benchmark: 'Benchmark de Precisión & Regresión SAST',
  proxy: 'Proxy Seguro de Secretos & Auditoría de APIs',
  report: 'Reporte Técnico & Entregable de Auditoría',
  executive: 'Resumen Ejecutivo & Auditoría Imprimible',
  history: 'Historial de Análisis & Comparativa de Cambios',
  controls: 'Inventario de Controles de Seguridad & Verificación en Vivo',
};

export default function Topbar({ activeTab, onRefresh }) {
  const title = TAB_TITLES[activeTab] || 'Security Control Center';

  return (
    <header className="topbar">
      <div>
        <p className="eyebrow">APPLICATION SECURITY PLATFORM</p>
        <h1>{title}</h1>
      </div>
      <div className="topbar-actions">
        <span className="system-badge">
          <i className="status-dot online"></i> Sistema Operativo
        </span>
        <button
          className="btn-icon"
          title="Refrescar estado"
          type="button"
          onClick={onRefresh}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/>
            <path d="M3 3v5h5"/>
            <path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/>
            <path d="M16 21h5v-5"/>
          </svg>
        </button>
      </div>
    </header>
  );
}
