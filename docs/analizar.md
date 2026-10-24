# Guía: cómo correr un análisis

Esta guía explica cómo ejecutar un análisis de seguridad sobre un repositorio,
por CLI y por API, y qué produce cada camino.

---

## 1. Requisitos

- Python 3.11+ con las dependencias de `backend/requirements.txt`
  (`pip install -r backend/requirements.txt` dentro de un venv).
- `git` en el PATH. `semgrep` y `gitleaks` instalados (o sus rutas en
  `SEMGREP_PATH` / `GITLEAKS_PATH`). El resto de escáneres (osv-scanner, bandit,
  checkov, trivy, etc.) son opcionales: si falta un binario, `analysis.tools`
  lo marca `"unavailable"` y el análisis sigue.

---

## 2. CLI

```bash
cd backend
python analyzer.py --url https://github.com/org/repo
```

Flags (backend/analyzer.py:877-904):

| Flag | Efecto |
| :--- | :--- |
| `--url` (obligatorio) | URL pública del repositorio. Solo https. |
| `--full-history` | Sin `--depth 1`: clona el historial completo de la rama por defecto y escanea secretos en el historial con Gitleaks (sin `--no-git`). |
| `--enable-ai-triage` | Habilita el agente de triage con IA (opt-in explícito; requiere clave o proxy). |

Salida en el directorio actual:

- `reporte_seguridad.json` — resultado completo (hallazgos, herramientas, summary).
- `reporte_seguridad.md` — reporte técnico embebido en el JSON.
- `reporte_seguridad.sarif` — exportación SARIF 2.1.0 (F9).

El último renglón de stdout imprime el `summary` JSON.

---

## 3. API (dashboard)

```bash
POST /api/analyze          {"url": "https://github.com/org/repo", "enable_ai_triage": false}
→ 202 {"analysis_id": "..."}
GET  /api/analysis/<id>    # estado y resultado completo
GET  /api/analyses         # últimos 20 análisis persistidos
```

- Cola con `MAX_CONCURRENT_ANALYSES` workers (default 2): los pedidos extra
  quedan en `stage: "queued"` hasta liberar un worker.
- Límite por IP: `RATE_LIMIT_PER_MINUTE` (default 30/min) → 429.
- Cada análisis persiste en `backend/storage/analyses/<analysis_id>.json`.

---

## 4. Qué hace el motor (flujo interno)

`analyze_repo(url, progress_callback, full_history, enable_ai_triage)`:

1. **Validación**: solo URLs https (`_validate_https_url`).
2. **Clon endurecido** a un directorio temporal: `git clone --no-tags
   --single-branch [--depth 1]` con `protocol.file.allow=never`, límite de
   tamaño (`SECURITY_MAX_REPO_MB`, default 200 MB), timeout de clon
   (`SECURITY_CLONE_TIMEOUT`, 300 s) y presupuesto total
   (`SECURITY_TOTAL_TIMEOUT`, 1200 s). Limpieza garantizada en `finally`.
3. **Escaneo** (`analyze_directory`): Semgrep con las reglas locales
   `backend/rules/security-rules.yml` + el registry `p/owasp-top-ten`; Gitleaks
   para secretos; escáneres opcionales multi-herramienta
   (`scanner_tools.run_tools`) según el stack detectado; fusión de
   detecciones repetidas (`merge_tool_findings`, tolerancia ±2 líneas);
   deduplicación y clasificación de severidad (`severity_engine`).
4. **Triage / remediación / enriquecimiento** (opcionales): triage IA con
   contexto acotado y secretos redactados; parches deterministas con
   verificación (F6); enriquecimiento Gemini con payload redactado (fail-open).
5. **Registro**: `result.repository.{commit,branch}` (SHA y rama analizadas).
   El código analizado nunca se ejecuta: solo se lee.

---

## 5. Seguridad operativa

- Solo se analizan repositorios públicos/clonables; el clon vive en un
  directorio temporal que se borra siempre.
- Los proveedores de IA se acceden (si hay opt-in) a través del proxy de
  secretos (F8) o con la clave del entorno; nunca se envían secretos del repo
  escaneado (payload redactado).
- Variables relacionadas: ver la tabla de env de `AGENTS.md`.
