# [AGENTS.md](http://AGENTS.md) — Malla de Agentes y Arquitectura del Proyecto

Este documento define la estructura multiagente, las guías de contribución y el estado del sistema para el ecosistema **OpenCode / Orca**.

---

## Malla Multiagente Configurada

| Agente | Alias | Rol / Enfoque | Alcance de Acción |

| :--- | :--- | :--- | :--- |

| **Planeador** | `@planner` | Arquitectura, estrategia de seguridad, diseño de Blueprints | **Solo Lectura / Diseño**: Diseña soluciones, evalúa escalabilidad y genera Blueprints. No escribe código final. |

| **Constructor** | `@builder` | Implementación Python, pruebas, modificación de archivos | **Escritura / Ejecución**: Lee Blueprints del `@planner` y aplica los cambios físicos en disco ([`analyzer.py`](http://analyzer.py), utilidades, etc.). |

---

## Quick Setup

- **Python Version**: 3.7+

- **Instalación de Dependencias**: `pip install -r requirements.txt`

- **Variables de Entorno Requeridas**:

  - `GEMINI_API_KEY`: Clave de acceso a la API de Google Gemini (el script se detiene si no existe).

- **Herramientas de Sistema Requeridas**:

  - `git`: Disponible en el `PATH` para la clonación de repositorios.

  - `semgrep`: Disponible en el `PATH` para análisis estático SAST.

---

## Arquitectura Completa del Proyecto (Full Stack)

### Backend (Python)

#### 1. **analyzer.py** - Motor de Análisis SAST + IA
- Función `analyze_repo(url, progress_callback=None) → Dict`
- Retorna estructura JSON estructurada:
  ```python
  {
    "status": "completed|incomplete|error",
    "findings": [
      {
        "id": int,
        "regla": str,
        "archivo": str,
        "false_positive": str,
        "severity": "Crítico|Alto|Medio|Bajo",
        "problema": str,
        "solucion": str
      },
      ...
    ],
    "markdown_report": str,
    "total_findings": int,
    "error_message": str (opcional)
  }
  ```
- Soporta callback de progreso: `callback(stage, percentage, status)`
- Stages: `cloning`, `analyzing`, `processing_ai`, `parsing`, `completed`

#### 2. **api_server.py** - REST API + WebSocket Server
- Framework: Flask + Socket.IO
- Puerto: 5000
- Endpoints REST:
  - `GET /` → Sirve `static/index.html`
  - `POST /api/analyze` → Inicia análisis (requiere `{"url": "..."}`)
  - `GET /api/analysis/<id>` → Recupera resultado en JSON
  - `GET /api/analyses` → Lista análisis anteriores
  - `WS /ws/<id>` → WebSocket para actualizaciones de progreso en tiempo real

- Validación: URL debe cumplir patrón `^https?://github\.com/[^/]+/[^/]+(\.git)?/?$`
- Almacenamiento: `/storage/analyses/{analysis_id}.json`
- Errores HTTP:
  - 400: URL inválida
  - 404: Análisis no encontrado
  - 500: Error interno
  - 504: Timeout

### Frontend (HTML5 + CSS3 + JavaScript)

#### 1. **static/index.html** - Interfaz Principal
- Estructura semántica HTML5
- Secciones:
  1. **Header**: Branding + logo
  2. **Sidebar**: Documentación OWASP Top 10 (10 items)
  3. **Main Content**:
     - Formulario de ingreso (URL + botón Analizar + dropdown histórico)
     - Monitor de progreso (barra % + estado)
     - Filtros (por severidad + por archivo)
     - Tabla de vulnerabilidades (ID, Archivo, Línea, Regla, Severidad, ¿FP?)
     - Modal de detalles (click en fila)
- Bootstrap 5 CDN + CSS custom
- Responsive (mobile-first)

#### 2. **static/css/styles.css** - Estilos
- Colores por severidad:
  - Crítico: `#d32f2f` (rojo)
  - Alto: `#f57c00` (naranja)
  - Medio: `#fbc02d` (amarillo)
  - Bajo: `#1976d2` (azul)
- Grid layout
- Media queries para tabletas y móviles
- Fuente: Segoe UI / Roboto / sans-serif

#### 3. **static/js/app.js** - Lógica Interactiva
- Socket.IO para WebSocket real-time
- Validación de URL con regex
- Fetch API para HTTP requests
- Renderizado dinámico de tabla sin `innerHTML` (XSS prevention)
- Filtrado en cliente (severidad + archivo)
- LocalStorage para persistencia de análisis previos
- Escapado de HTML con `textContent`

### Storage

- **storage/analyses/**: Directorio de almacenamiento persistente
  - Archivos: `{analysis_id}.json`
  - Formato: JSON estructurado con findings completos

---

## Comandos de Ejecución

### 1. Instalar Dependencias

```bash
pip install -r requirements.txt
```

Dependencias requeridas:
- `semgrep>=1.60.0`
- `google-generativeai>=0.4.0`
- `flask>=2.3.0`
- `python-socketio>=5.9.0`
- `python-engineio>=4.8.0`

### 2. Ejecutar Servidor Web + API

```bash
export GEMINI_API_KEY="your_gemini_api_key"
python api_server.py
```

Servidor activo en: `http://localhost:5000`

### 3. Ejecutar Análisis desde CLI (sin UI)

```bash
export GEMINI_API_KEY="your_gemini_api_key"
python analyzer.py --url "https://github.com/user/repo"
```

Genera:
- `reporte_seguridad.md` (Markdown con hallazgos)
- `reporte_seguridad.json` (JSON estructurado)

### 4. Probar API REST (curl)

```bash
# Iniciar análisis
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://github.com/juice-sh/juice-shop"}'

# Respuesta esperada:
# {
#   "analysis_id": "550e8400-e29b-41d4-a716-446655440000",
#   "status": "processing",
#   "message": "Analysis started"
# }

# Recuperar resultados
curl http://localhost:5000/api/analysis/550e8400-e29b-41d4-a716-446655440000

# Listar análisis anteriores
curl http://localhost:5000/api/analyses
```

---

## Flujo de Uso (User Journey)

1. **Usuario abre navegador** → `http://localhost:5000`
2. **Ingresa URL de GitHub** → Valida formato en cliente
3. **Hace clic en "Analizar"** → POST a `/api/analyze`
4. **Recibe `analysis_id`** → Se suscribe a WebSocket
5. **Observa barra de progreso** → Eventos cada 5-10 seg:
   - 0-20%: 📦 Clonando repositorio
   - 20-60%: 🔍 Ejecutando Semgrep
   - 60-90%: 🤖 Procesando con IA
   - 90-100%: ✅ Guardando resultados
6. **Al completar** → Tabla se llena con vulnerabilidades
7. **Click en hallazgo** → Modal muestra detalles completos
8. **Recarga página** → LocalStorage recupera análisis previos
9. **Dropdown histórico** → Carga análisis anterior sin re-analizar

---

## Estructura de Archivos

```
/work/
├── analyzer.py              # Motor SAST + IA (310 líneas)
├── api_server.py            # REST API + WebSocket (263 líneas)
├── requirements.txt         # Dependencias Python
├── static/
│   ├── index.html          # Interfaz web (246 líneas)
│   ├── css/
│   │   └── styles.css      # Estilos (464 líneas)
│   └── js/
│       └── app.js          # Lógica client (461 líneas)
├── storage/
│   └── analyses/           # Almacenamiento de resultados
├── reporte_seguridad.md    # Reporte Markdown (CLI)
└── reporte_seguridad.json  # Reporte JSON (CLI)
```

---

## Características de Seguridad Implementadas

1. **XSS Prevention**:
   - Uso de `textContent` en lugar de `innerHTML`
   - Escapado de HTML en `escapeHtml()`
   - Sanitización de datos de usuario

2. **Input Validation**:
   - Validación de URL en cliente (regex)
   - Validación de URL en servidor (mismo regex)
   - Máxima seguridad en ambos extremos

3. **SAST Integration**:
   - Semgrep con ruleset OWASP Top 10
   - Salida JSON parseable
   - Hallazgos deduplicated y normalizados

4. **Error Handling**:
   - Timeouts en git clone (300 seg)
   - Timeouts en Semgrep (600 seg)
   - Fallback si Gemini API falla
   - Mensajes de error claros

5. **UTF-8 Normalization**:
   - `encoding='utf-8', errors='replace'` en subprocess
   - `ensure_ascii=False` en JSON dumps
   - Soporte completo de caracteres especiales

---

## Testing & Validación

### Test 1: Análisis Simple (Sin vulnerabilidades)

```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://github.com/octocat/Hello-World"}'
```

Esperado: Status 202, analysis_id generado, progreso en 0-100%

### Test 2: URL Inválida

```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://not-github.com/invalid"}'
```

Esperado: Status 400, error message con formato esperado

### Test 3: Recuperar Análisis Anterior

```bash
curl http://localhost:5000/api/analyses
```

Esperado: Array JSON con análisis completados

---

## Notas de Implementación

- Los análisis se ejecutan en **threads background** para no bloquear la API
- WebSocket emite progreso en tiempo real
- Resultados se persisten en `/storage/analyses/` 
- LocalStorage en navegador almacena últimos 20 análisis
- Modal de detalles muestra problema + solución expandida
- Filtros aplican en cliente (sin re-fetch)
- Responsive design testeado en:
  - Desktop (1200px+)
  - Tablet (768px - 1199px)
  - Mobile (< 768px)

---

## Próximas Mejoras (Roadmap)

- [ ] Autenticación de usuarios
- [ ] Dashboard con estadísticas
- [ ] Exportación a PDF/CSV
- [ ] Notificaciones por email
- [ ] Integración con GitHub Actions
- [ ] Base de datos persistente (SQLite/PostgreSQL)
- [ ] Rate limiting y caché
- [ ] Multi-language support (i18n)