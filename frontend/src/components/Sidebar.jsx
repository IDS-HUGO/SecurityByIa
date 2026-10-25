import React from 'react';

export default function Sidebar({ activeTab, onTabChange, findingsCount }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="m9 12 2 2 4-4"/>
          </svg>
        </div>
        <div className="brand-text">
          <span className="brand-title">Neurotry</span>
          <span className="brand-sub">Security Control</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        <a
          href="#overview"
          className={`nav-item ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={(e) => { e.preventDefault(); onTabChange('overview'); }}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/></svg>
          <span>Overview</span>
        </a>
        <a
          href="#findings"
          className={`nav-item ${activeTab === 'findings' ? 'active' : ''}`}
          onClick={(e) => { e.preventDefault(); onTabChange('findings'); }}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" x2="12" y1="9" y2="13"/><line x1="12" x2="12.01" y1="17" y2="17"/></svg>
          <span>Hallazgos</span>
          {findingsCount > 0 && (
            <span className="nav-badge">{findingsCount}</span>
          )}
        </a>
        <a
          href="#benchmark"
          className={`nav-item ${activeTab === 'benchmark' ? 'active' : ''}`}
          onClick={(e) => { e.preventDefault(); onTabChange('benchmark'); }}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polygon points="12 6 12 12 16 14"/></svg>
          <span>Benchmark</span>
          <span className="nav-pill">Métricas</span>
        </a>
        <a
          href="#tools"
          className={`nav-item ${activeTab === 'tools' ? 'active' : ''}`}
          onClick={(e) => { e.preventDefault(); onTabChange('tools'); }}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>
          <span>Herramientas</span>
          <span className="nav-pill">F13</span>
        </a>
        <a
          href="#proxy"
          className={`nav-item ${activeTab === 'proxy' ? 'active' : ''}`}
          onClick={(e) => { e.preventDefault(); onTabChange('proxy'); }}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          <span>Proxy</span>
          <span className="nav-pill">Seguro</span>
        </a>
        <a
          href="#credentials"
          className={`nav-item ${activeTab === 'credentials' ? 'active' : ''}`}
          onClick={(e) => { e.preventDefault(); onTabChange('credentials'); }}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg>
          <span>Credenciales</span>
          <span className="nav-pill" style={{ color: '#22c55e', borderColor: 'rgba(34, 197, 94, 0.4)' }}>F12</span>
        </a>
        <a
          href="#report"
          className={`nav-item ${activeTab === 'report' ? 'active' : ''}`}
          onClick={(e) => { e.preventDefault(); onTabChange('report'); }}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><line x1="16" x2="8" y1="13" y2="13"/><line x1="16" x2="8" y1="17" y2="17"/></svg>
          <span>Reporte</span>
        </a>
        <a
          href="#executive"
          className={`nav-item ${activeTab === 'executive' ? 'active' : ''}`}
          onClick={(e) => { e.preventDefault(); onTabChange('executive'); }}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M6 8a2 2 0 0 1 2-2h1"/><path d="M6 16a2 2 0 0 0 2 2h1"/><path d="M18 8a2 2 0 0 0-2-2h-1"/><path d="M18 16a2 2 0 0 1-2 2h-1"/><line x1="12" x2="12" y1="6" y2="18"/></svg>
          <span>Resumen Ejecutivo</span>
          <span className="nav-pill">PDF</span>
        </a>
        <a
          href="#controls"
          className={`nav-item ${activeTab === 'controls' ? 'active' : ''}`}
          onClick={(e) => { e.preventDefault(); onTabChange('controls'); }}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/></svg>
          <span>Controles</span>
          <span className="nav-pill">Audit</span>
        </a>
        <a
          href="#history"
          className={`nav-item ${activeTab === 'history' ? 'active' : ''}`}
          onClick={(e) => { e.preventDefault(); onTabChange('history'); }}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M12 7v5l4 2"/></svg>
          <span>Historial</span>
          <span className="nav-pill">Δ</span>
        </a>
      </nav>

      <div className="sidebar-foot">
        <div className="status-indicator-box">
          <span className="status-dot online"></span>
          <div>
            <strong className="foot-title">Motor SAST + IA</strong>
            <small className="foot-sub">OWASP Top 10 & Benchmark</small>
          </div>
        </div>
      </div>
    </aside>
  );
}
