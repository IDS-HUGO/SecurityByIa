# 🛡️ Security Control Center & Benchmark Suite

> **Plataforma de Análisis de Seguridad SAST y Evaluación Continua de Precisión (Benchmark)**  
> Desarrollado para el proyecto: *Seguridad de aplicaciones asistida por IA* en **Neurotry (Bioprevento Fundadores)**.

---

## 📌 Visión General

**Security Control Center** es una plataforma integral de ciberseguridad diseñada para analizar repositorios de código, identificar vulnerabilidades basadas en el **OWASP Top 10** y secretos expuestos, y evaluar cuantitativamente la precisión del motor de análisis mediante una suite de **Benchmarking continuo**.

La plataforma combina:
1. **Motor SAST y Secret Scanning:** Integración de reglas estáticas Semgrep y escaneo de credenciales con Gitleaks.
2. **Dashboard Cyber-Moderno (UI/UX):** Interfaz rediseñada en paleta Obsidian & Electric Cyan con visualización en tiempo real de hallazgos, contexto de código, severidades y filtros.
3. **Módulo de Benchmarking y Regresión:** Medición objetiva de **Recall (True Positive Rate - TPR)** y **False Positive Rate (FPR)** frente a *Ground Truth* de referencia, desglose por categoría CWE y comparativa en puntos respecto a la corrida anterior y al `baseline.json`.

Para instalar, configurar `.env`, levantar Docker, ejecutar el primer análisis y correr las
pruebas, consulta la [Guía de ejecución](docs/ejecucion.md).

---

## 🚀 Nuevas Características y Mejoras Implementadas

### 1. Pestaña de Benchmark en el Dashboard
- **Tarjetas por repositorio de referencia:** Cada dataset (`Tiny Vulnerable App`, `OWASP Web Benchmark`, `OWASP Juice Shop Sample`, `API & Authentication Benchmark`) cuenta con su tarjeta indicando Recall (TPR), FPR, desglose de TP/FP/FN y comparativa en puntos.
- **Tabla de Precisión por Categoría CWE:** Desglose detallado de vulnerabilidades (CWE-78 Command Injection, CWE-89 SQLi, CWE-798 Hardcoded Secrets, CWE-327 Broken Crypto, CWE-502 Deserialization, CWE-22 Path Traversal, CWE-94 Code Injection, etc.) comparando Ground Truth vs Detecciones y delta en puntos frente a la corrida previa.
- **Comparativa en Puntos (Δ deltas):** Seguimiento cuantitativo de mejoras o regresiones en puntos porcentuales (ej. `▲ +5.0 pts` en Recall o `▼ -2.5 pts` en FPR).
- **Manejo de Estados Integrado:**
  - **Cargando (Loading):** Animación de radar y barra porcentual en tiempo real mientras el motor analiza las referencias.
  - **Vacío (Empty State):** Pantalla guiada para ejecutar la primera corrida cuando no existen datos previos.
  - **Error (Error State):** Alerta estilizada con descripción del fallo y botón de reintento.

### 2. Endpoints de Benchmark en la API
- **`GET /api/bench`:** Devuelve el estado del motor (`idle`, `running`, `completed`, `error`), progreso, última corrida (`latest_run`), baseline activo, resumen global y lista histórica.
- **`POST /api/bench/run`:**
  - Reutiliza el motor de análisis (`analyzer.analyze_directory`).
  - **Concurrencia única garantizada:** Bloqueo por mutex que retorna `409 Conflict` si ya hay una corrida en curso.
  - Salida JSON estable con métricas normalizadas, desglose por CWE y deltas calculados.
  - Marcado automático de cada corrida con timestamp ISO, fecha legible y la **feature recién integrada** (detectada desde git o suministrada en el body `{"feature": "..."}`).
  - Generación y almacenamiento automático de `baseline.json` en la primera corrida o cuando se marque `{"save_as_baseline": true}`.
- **`GET /api/bench/baseline`:** Consulta directa del reporte de baseline guardado.
- **`GET /api/bench/history`:** Listado de corridas históricas.
- **`GET /api/bench/run/<run_id>`:** Consulta detallada de una corrida específica por ID.

### 3. Rediseño Total de UI/UX
- Paleta oscura profesional: Fondos `#080c14` y `#0f1627`, tarjetas elevadas `#131d31`, acentos en cian neón (`#00f0ff`), esmeralda (`#10b981`), ámbar y carmesí.
- Navegación lateral limpia por pestañas: **Overview**, **Hallazgos**, **Benchmark** y **Reporte**.
- Tipografía moderna con soporte monoespaciado (`JetBrains Mono` y `Outfit`).

### 4. Triage con IA que sí ve el Código (Feature 5)
- **Contexto Acotado y Seguro:** Extracción de 20 líneas de código fuente centradas en el hallazgo, con redacción exhaustiva de secretos (`[REDACTED_SECRET]`) y delimitación estricta `<BOUNDED_CODE_EXCERPT_DATA>`.
- **Activación Opt-in Estricta:** El código nunca sale a un modelo externo sin consentimiento explícito (variable `ENABLE_AI_TRIAGE=true` o casilla en el formulario de escaneo).
- **Esquema Validado y Fail-Open:** Respuestas JSON validadas (`verdadero`, `falso`, `incierto`). Cualquier fallo o ambigüedad cae en *fail-open* enviando el hallazgo a revisión humana.
- **Cola "Por revisar":** Vista priorizada que filtra y ordena los hallazgos inciertos de mayor a menor severidad (`Crítico` > `Alto` > `Medio` > `Bajo`).
- **Decisiones Humanas con Huella Persistente:** Botones de acción (*Confirmar*, *Falso Positivo*, *Incierto*) con justificación obligatoria. Los falsos positivos confirmados generan una huella SHA256 (`storage/known_false_positives.json`) que los suprime automáticamente en futuros análisis.
- **Comparativa Multi-Modelo en Benchmark:** Evaluación comparativa del impacto en la tasa de falsos positivos (FPR) evaluando Gemini, OpenAI y Claude con el mismo prompt estandarizado.

### 5. Corrección Asistida con Verificación (Feature 6)
- **Agente Fixer con Diffs Unificados Mínimos:** Genera un diff unificado estándar para cada hallazgo utilizando plantillas seguras deterministas sin IA (`yaml.safe_load`, `verify=True`, actualización de dependencias vulnerables en `requirements.txt` y `package.json`, desactivación de `DEBUG=True` y mitigación de `shell=True`).
- **Bucle de Verificación en Rama Temporal Aislada:** Aplica el parche con `git apply` en una rama temporal aislada (`patch-verify-<uuid>`) y re-escanea con Semgrep únicamente los archivos tocados.
- **Descarte Automático de Parches Inseguros:** Si el hallazgo persiste o se introduce una nueva alerta de seguridad, el parche se descarta automáticamente (`status: "discarded"`). Si se resuelve limpiamente sin nuevos hallazgos, queda marcado como verificado (`status: "verified"`).
- **Protección Estricta del Repositorio:** El fixer **nunca hace push a la rama principal** (`main` o `master`).
- **Pruebas del Proyecto en Sandbox sin Red:** Las pruebas del proyecto analizado se ejecutan únicamente con opt-in explícito en repositorios propios y dentro de un contenedor Docker aislado sin acceso a red (`docker run --network none`).
- **Ciclo de Vida Visible del Hallazgo:** Estados visibles en la tabla y detalle: `abierto`, `parche propuesto`, `verificado`, `descartado`, `aprobado`, `rechazado`.

### 6. Acceso Web Delegado y Credenciales de Agentes (Feature 12)
- **Zero LLM Exposure:** Garantía de que contraseñas, semillas TOTP y tokens de sesión jamás ingresan al prompt ni al contexto del modelo ni del agente.
- **Bóveda Cifrada Segura:** Custodia de secretos en `EncryptedFileVault` con permisos Unix `0600` y adaptadores desacoplados para Bitwarden y 1Password CLI.
- **Validación Estricta de Origen:** Protección contra phishing y prompt injection; si la navegación intenta desviarse a un dominio o iframe ajeno, el broker aborta de inmediato (`OriginMismatchError`).
- **Interfaz Intuitiva de Integración:** Vista guiada paso a paso para dar de alta sitios con políticas de aprobación, bandeja de autorización humana interactiva, y control de sesiones activas con botón de revocación instantánea.
- **Worker de Confianza:** Handshake seguro en el navegador, resolución interna de TOTP (RFC 6238) y limpieza forzada de inputs si la autenticación falla.

### 7. Benchmark por Herramienta (Feature 13)
- **Evaluación Empírica por Escáner:** Medición cuantitativa e independiente para Semgrep, Bandit, Gitleaks, TruffleHog, OSV-Scanner, Checkov, Trivy, hadolint, zizmor, Syft, ScanCode y Scorecard.
- **Emparejamiento Riguroso:** Tolerancia de $\pm 3$ líneas o caso/CWE, normalización de alias de avisos SCA (CVE, GHSA, OSV) y cálculo honesto de métricas (FPR solo en datasets con negativos verificados).
- **Configuración Automática (`defaults.yml`):** Clasificación empírica de herramientas como recomendadas, opcionales o desactivadas según umbrales de precisión y fallos.
- **Pestaña Herramientas en Frontend:** Dashboard interactivo con filtros por categoría y lenguaje, tiempos medianos y celdas con evidencia JSON.

### 8. Cobertura Políglota y Cobertura Declarada (Feature 14)
- **Detección sin Ejecución (`detect_stack_v2`):** Conteo de archivos y volumen en bytes para más de 8 lenguajes (Python, JS/TS, Go, Java, Kotlin, Ruby, PHP, Rust, C#, C/C++, Dart, Elixir), lockfiles, frameworks y monorepos con múltiples subproyectos.
- **Registro Modular de Herramientas (`ToolRegistry`):** Catálogo extensible con diagnóstico `secai doctor` y endpoint `GET /api/tools`.
- **Principio de Cobertura Declarada:** Si un lenguaje detectado no cuenta con escáner SAST activo, el análisis finaliza en `completed_with_gaps` con bloque `coverage` detallado, alerta amigable en la interfaz y sugerencia de revisión asistida con IA.


## 🏗️ Arquitectura del Sistema

```text
                                  +---------------------------------------+
                                  |      Dashboard Web (SPA Moderna)      |
                                  |   Overview | Hallazgos | Benchmark    |
                                  +-------------------+-------------------+
                                                      |
                                                      | HTTP REST
                                                      v
                                  +---------------------------------------+
                                  |        Servidor Flask (API)           |
                                  |  /api/analyze  |  /api/bench(/run)    |
                                  +---------+-------------------+---------+
                                            |                   |
                     Escaneo de Repositorio |                   | Ejecución de Benchmark
                                            v                   v
+-------------------------------------------+---+   +-----------+-------------------------------+
|             analyzer.py                       |   |         benchmark_service.py              |
|  - git clone temporal                         |   |  - Carga refs.yml y datasets locales      |
|  - Semgrep SAST (reglas locales + OWASP)      |   |  - Reutiliza analyzer.analyze_directory   |
|  - Gitleaks (detección de credenciales)       |   |  - Matcher contra Ground Truth (TP/FP/FN) |
|  - Deduplicación & clasificación severidad    |   |  - Métricas Recall/TPR, FPR, F1, CWE map  |
|  - Enriquecimiento opcional con IA (Gemini)   |   |  - Cálculo de deltas vs anterior/baseline |
+-----------------------------------------------+   +-------------------------------------------+
                        |                                                 |
                        v                                                 v
         storage/analyses/{id}.json                       storage/benchmark/
                                                          ├── baseline.json
                                                          ├── latest.json
                                                          ├── history.json
                                                          └── runs/{run_id}.json
```

---

## ⚙️ Estructura del Proyecto (F4B)

```
demo-seguridad/
├── backend/                  # Servicio exclusivo de API REST y motor de análisis
│   ├── api_server.py         # Servidor Flask (solo JSON, CORS configurable, sin HTML)
│   ├── analyzer.py           # Motor principal de análisis SAST y escaneo de secretos
│   ├── benchmark_service.py  # Servicio de benchmark de precisión y regresión
│   ├── scanner_tools.py      # Adaptadores multi-herramienta y detección de stack
│   ├── severity_engine.py    # Motor de severidad contextual, OWASP 2021 y SLA Control 6
│   ├── triage_agent.py       # Agente de triage IA, contexto acotado y huella de falsos positivos (F5)
│   ├── openapi.yaml          # Contrato formal OpenAPI 3.0 de la API
│   ├── requirements.txt      # Dependencias de Python
│   ├── Dockerfile            # Imagen backend independiente
│   ├── rules/                # Reglas Semgrep personalizadas
│   ├── data/                 # cwe_owasp_2021.json y controls_inventory.json
│   ├── storage/              # Almacenamiento de análisis y benchmark
│   ├── bench/                # Scripts y datasets de referencia
│   └── tests/                # Suite de pruebas unitarias, CORS y contrato OpenAPI
├── frontend/                 # Aplicación SPA en React con Vite
│   ├── package.json          # Dependencias de React
│   ├── vite.config.js        # Configuración de Vite con proxy a /api
│   ├── nginx.conf            # Servidor web Nginx y reverse proxy de producción
│   ├── Dockerfile            # Imagen multi-stage (builder -> nginx)
│   └── src/
│       ├── api/client.js     # Capa única de acceso a la API (VITE_API_BASE_URL)
│       ├── components/       # Componentes: Sidebar, Topbar, ScanCard, Tabs, Modals
│       ├── App.jsx           # Aplicación principal y gestión de estado
│       └── index.css         # Estilos cyber-modernos (Obsidian & Cyan)
├── docker-compose.yml        # Orquestación de backend (:5000) y frontend (:80)
└── .env.example              # Variables de entorno y configuración local
```

---

## 💻 Instalación y Puesta en Marcha

### Opción A: Desarrollo Local (dos terminales)

**Terminal 1 — Backend (Flask):**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
python backend/api_server.py
```
*API escuchando en `http://127.0.0.1:5000`*.

**Terminal 2 — Frontend (React + Vite):**
```bash
cd frontend
npm install
npm run dev
```
*Frontend disponible en `http://localhost:5173` con proxy automático a `/api`*.

### Opción B: Producción con Docker Compose

```bash
docker compose up --build
```
*Frontend en `http://localhost` (puerto 80) conectado con el backend a través de Nginx*.

---

## 📡 Referencia de la API y Contrato OpenAPI

El contrato completo está formalizado en `backend/openapi.yaml` y disponible en `GET /openapi.yaml`.

| Método | Ruta | Descripción |
| :--- | :--- | :--- |
| `POST` | `/api/analyze` | Inicia análisis asíncrono de un repositorio de GitHub (`{"url": "..."}`). |
| `GET` | `/api/analysis/<id>` | Consulta progreso y resultados del análisis. |
| `GET` | `/api/analyses` | Lista los análisis realizados recientemente. |
| `GET` | `/api/bench` | Estado actual, última corrida (`latest_run`), baseline y resumen de repos. |
| `POST` | `/api/bench/run` | Dispara corrida de benchmark (`{"feature": "...", "save_as_baseline": false}`). Concurrencia única (409 si está ocupado). |
| `GET` | `/api/bench/baseline` | Obtiene el reporte de referencia fijado como `baseline.json`. |
| `GET` | `/api/bench/history` | Historial de corridas anteriores. |
| `GET` | `/api/bench/run/<id>` | Detalle completo de una corrida específica por ID. |

### CLI de Benchmark

```bash
python backend/bench/benchmark.py                                    # todas las referencias
python backend/bench/benchmark.py --repo-ids repo-juice-sample       # solo un subconjunto
python backend/bench/benchmark.py --save-as-baseline --feature "fx"  # fijar baseline.json
python backend/bench/test_tiny.py                                    # ejemplo pequeño (smoke test)
```

### Pruebas

Para correr la suite completa (pruebas unitarias, análisis, CORS, contrato OpenAPI y paridad):

```bash
.venv/bin/pytest backend/tests/ -v
```

---

## 🧪 Métricas Calculadas en el Benchmark

- **True Positives (TP):** Vulnerabilidades reales detectadas correctamente según el Ground Truth.
- **False Positives (FP):** Hallazgos reportados por el scanner que no corresponden a vulnerabilidades reales en el dataset.
- **False Negatives (FN):** Vulnerabilidades reales del Ground Truth omitidas por el scanner.
- **Recall / TPR (True Positive Rate):**
  $$\text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}}$$
  Porcentaje de vulnerabilidades reales detectadas.
- **False Positive Rate (FPR):**
  $$\text{FPR} = \frac{\text{FP}}{\text{TP} + \text{FP}}$$
  Tasa de falsas alarmas sobre el total de detecciones generadas.
- **F1-Score:**
  $$\text{F1} = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$$
  Balance armónico entre precisión y cobertura.
- **Diferencia en Puntos (pts):**
  $$\Delta = (\text{Métrica}_{\text{actual}} - \text{Métrica}_{\text{anterior}}) \times 100$$
