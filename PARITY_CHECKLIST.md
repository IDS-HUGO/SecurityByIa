# Lista de Paridad: static/ vs frontend/ (React + Vite)

Verificación completa de paridad funcional y visual entre la interfaz clásica (`static/`) y la nueva aplicación en React (`frontend/`).

| Módulo / Característica | static/ (Vanilla JS) | frontend/ (React + Vite) | Estado |
| :--- | :--- | :--- | :--- |
| **Barra Lateral (Sidebar)** | `aside.sidebar` | `Sidebar.jsx` |  Idéntico |
| Navegación por pestañas | `#overview`, `#findings`, `#benchmark`, `#report` | `Sidebar.jsx` con sincronización de `window.location.hash` |  Idéntico |
| Indicador de estado del motor | Punto verde online + texto | `Sidebar.jsx` |  Idéntico |
| Contador de hallazgos en pestaña | `#nav-findings-badge` | Badge dinámico en enlace `Hallazgos` |  Idéntico |
| **Barra Superior (Topbar)** | `header.topbar` | `Topbar.jsx` |  Idéntico |
| Título dinámico por pestaña | Actualizado según tab activa | `Topbar.jsx` con diccionario reactivo |  Idéntico |
| Botón de refresco global | `#theme-refresh` | Botón con llamada a `handleRefresh` |  Idéntico |
| **Formulario de Análisis** | `form#scan-form` | `ScanCard.jsx` |  Idéntico |
| Validación de URL GitHub | Regex https://github.com/org/repo | Regex con mensaje accionable en español |  Idéntico |
| Estado de carga en botón | "Iniciar Análisis" / "Analizando..." | Deshabilitación y estado en botón |  Idéntico |
| **Panel de Progreso** | `#progress-panel` | `ProgressPanel.jsx` |  Idéntico |
| Barra de progreso y porcentaje | `#progress-bar` | Barra reactiva `style={{ width: `${progress}%` }}` |  Idéntico |
| Metadatos de commit/rama/repo | `#result-meta` con SHA truncado a 7 chars | `ProgressPanel.jsx` con formato exacto |  Idéntico |
| Banners de error en fallo | `#actionable-error` / `#technical-error` | `error-banner` con alerta reactiva |  Idéntico |
| **Pestaña Overview** | `#tab-overview` | `OverviewTab.jsx` |  Idéntico |
| KPIs de Severidad | Total, Crítico, Alto, Medio, Bajo | 5 tarjetas con iconos y colores idénticos |  Idéntico |
| Historial de Análisis Recientes | Tabla con últimos 20 análisis | Tabla con fecha, estado, badges y botón "Ver análisis" |  Idéntico |
| **Pestaña Hallazgos** | `#tab-findings` | `FindingsTab.jsx` |  Idéntico |
| Resumen Clicable de Severidad | Contadores con filtro instantáneo | Botones interactivos con clase `.active-filter` |  Idéntico |
| Resumen Clicable OWASP 2021 | Contadores A01-A10 con filtro | Botones interactivos por categoría |  Idéntico |
| Filtro por Herramienta | Select con herramientas detectadas | `<select id="tool-filter">` reactivo |  Idéntico |
| Filtro por Tipo | Código, Dependencia, Secreto | `<select id="type-filter">` reactivo |  Idéntico |
| Botón limpiar filtros | `#btn-clear-filters` | Botón con restablecimiento total de filtros |  Idéntico |
| Tabla de Hallazgos | Columnas: Severidad, Problema, Archivo, CWE, OWASP, Detectado por, Estado, Acciones | Columnas y etiquetas idénticas |  Idéntico |
| Insignias con contraste AA | CRÍTICO, ALTO, MEDIO, BAJO | Mismas clases CSS `.sev-badge` |  Idéntico |
| Modal de Detalle | Drawer/Modal con código y recomendación | `FindingDetailModal.jsx` |  Idéntico |
| Detalle de Dependencia | Paquete, Versión instalada, Versión corregida | Bloque `.dependency-block` idéntico |  Idéntico |
| Verificación de Secreto | VALID / INVALID / UNVERIFIED | Bloque con colores de verificación |  Idéntico |
| Motivo y SLA | `severity_reason` y `remediation_deadline` | Callouts idénticos |  Idéntico |
| **Pestaña Benchmark** | `#tab-benchmark` | `BenchmarkTab.jsx` |  Idéntico |
| Formulario de Corrida | Nombre de feature y checkbox de baseline | `BenchmarkTab.jsx` con formulario controlado |  Idéntico |
| Métricas Globales con Deltas | TPR, FPR, Precisión, F1 con deltas en puntos (▲/▼) | `formatDelta` idéntico |  Idéntico |
| Tarjetas por Repo de Referencia | Juice Shop, BenchmarkPython, etc. | Grid de tarjetas con métricas por repo |  Idéntico |
| Tabla de Categorías CWE | Matriz completa de ground truth y detecciones | Tabla con TP, FP, FN, TPR, FPR, Precisión, F1 |  Idéntico |
| Tabla de Herramientas Individuales | Rendimiento aislado por herramienta | Tabla idéntica |  Idéntico |
| Tabla de Pares de Escáneres | Cobertura combinada de herramientas | Tabla idéntica con etiquetas combinadas |  Idéntico |
| **Pestaña Reporte** | `#tab-report` | `ReportTab.jsx` |  Idéntico |
| Descarga Markdown (.md) | Genera y descarga archivo `.md` | Blob URL de descarga directa |  Idéntico |
| Descarga JSON (.json) | Genera y descarga archivo `.json` | Blob URL de descarga directa |  Idéntico |
| Vista previa del Reporte | Preformateado con tipografía mono | Bloque `.report-preview` idéntico |  Idéntico |
| **Capa de API** | Llamadas `fetch` directas en `app.js` | `api/client.js` configurable con `VITE_API_BASE_URL` |  Mejorado |
