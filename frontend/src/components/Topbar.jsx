import React from 'react';

const TAB_TITLES = {
  overview: 'Panel de Control & Análisis SAST',
  findings: 'Hallazgos de Seguridad & Remediaciones',
  benchmark: 'Benchmark de Precisión & Regresión SAST',
  tools: 'Catálogo & Benchmark de Herramientas Políglotas',
  credentials: 'Bóveda de Credenciales, Proxy Seguro & Auditoría de Tráfico',
  proxy: 'Bóveda de Credenciales, Proxy Seguro & Auditoría de Tráfico',
  report: 'Reporte Técnico & Entregable de Auditoría',
  executive: 'Resumen Ejecutivo & Auditoría Imprimible',
  history: 'Historial de Análisis & Comparativa de Cambios',
  controls: 'Inventario de Controles de Seguridad & Verificación en Vivo',
};

export default function Topbar({ activeTab, onRefresh, theme, onToggleTheme }) {
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
          title={theme === 'dark' ? 'Cambiar a Tema Claro' : 'Cambiar a Tema Oscuro'}
          type="button"
          onClick={onToggleTheme}
        >
          {theme === 'dark' ? (
            /* Sun Icon */
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="5"/>
              <line x1="12" y1="1" x2="12" y2="3"/>
              <line x1="12" y1="21" x2="12" y2="23"/>
              <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
              <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
              <line x1="1" y1="12" x2="3" y2="12"/>
              <line x1="21" y1="12" x2="23" y2="12"/>
              <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
              <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
            </svg>
          ) : (
            /* Moon Icon */
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
            </svg>
          )}
        </button>
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
