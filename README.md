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

---

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

## ⚙️ Estructura del Proyecto

```
demo-seguridad/
├── analyzer.py               # Motor principal de análisis SAST, Semgrep y Gitleaks
├── api_server.py             # API Flask con endpoints de análisis y benchmark
├── benchmark_service.py      # Servicio de benchmark, matching de ground truth y métricas
├── requirements.txt          # Dependencias de Python (Flask, Semgrep, PyYAML, etc.)
├── reporte_seguridad.md      # Reporte auditable de referencia
├── rules/
│   └── security-rules.yml    # Reglas SAST personalizadas (CWE-78, 89, 94, 327, 798, etc.)
├── bench/
│   ├── refs.yml              # Configuración de repositorios de referencia para benchmark
│   ├── benchmark.py          # CLI de benchmark (clona, analiza, compara y persiste)
│   ├── test_tiny.py          # Corrida de ejemplo pequeño (smoke test)
│   ├── results/              # Resultados serializados de benchmark
│   └── examples/             # Datasets de referencia con ground truth
│       ├── juice-shop-sample/      # vulnerabilidades.json (vuln_code_snippet + vuln_line)
│       ├── benchmark-python/       # expectedresults-0.1.csv (caso + CWE)
│       ├── tiny-vuln-app/
│       ├── owasp-web-bench/
│       └── api-auth-bench/
├── tests/
│   └── test_benchmark.py     # Suite unittest del benchmark (ejemplo pequeño autónomo)
├── static/
│   ├── index.html            # Dashboard web con pestañas Overview, Hallazgos y Benchmark
│   ├── css/styles.css        # Estilos cyber-modernos (Obsidian & Cyan)
│   └── js/app.js             # Lógica cliente, navegación de tabs y polling
└── storage/
    ├── analyses/             # Historial de análisis de repositorios externos
    └── benchmark/            # Almacenamiento de baseline.json, latest.json y corridas
```

---

## 💻 Instalación y Puesta en Marcha

### Requisitos Previos
- Python 3.10 o superior.
- Git en el `PATH`.
- Semgrep instalado (`pip install semgrep`).
- Gitleaks (opcional para secret scanning local).

### 1. Clonar y configurar entorno virtual

```bash
# En Linux / macOS:
python3 -m venv .venv
source .venv/bin/activate

# En Windows (PowerShell):
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 3. Ejecutar la aplicación

```bash
python api_server.py
```

Abre en tu navegador: **`http://localhost:5000`**

---

## 📡 Referencia de la API

### Endpoints de Análisis SAST

| Método | Ruta | Descripción |
| :--- | :--- | :--- |
| `POST` | `/api/analyze` | Inicia análisis asíncrono de un repositorio de GitHub (`{"url": "..."}`). |
| `GET` | `/api/analysis/<id>` | Consulta progreso y resultados del análisis. |
| `GET` | `/api/analyses` | Lista los análisis realizados recientemente. |

### Endpoints de Benchmarking

| Método | Ruta | Descripción |
| :--- | :--- | :--- |
| `GET` | `/api/bench` | Estado actual, última corrida (`latest_run`), baseline y resumen de repos. |
| `POST` | `/api/bench/run` | Dispara corrida de benchmark (`{"feature": "...", "save_as_baseline": false}`). Concurrencia única (409 si está ocupado). |
| `GET` | `/api/bench/baseline` | Obtiene el reporte de referencia fijado como `baseline.json`. |
| `GET` | `/api/bench/history` | Historial de corridas anteriores. |
| `GET` | `/api/bench/run/<id>` | Detalle completo de una corrida específica por ID. |

### CLI de Benchmark

La misma suite está disponible como script (clona/copía cada referencia a una carpeta ignorada por git, ejecuta el motor `analyzer.analyze_directory` —el mismo pipeline de `analyzer.analyze_repo`—, compara contra el ground truth y guarda la corrida en `bench/results/` con la versión de Semgrep, las reglas aplicadas y los commits evaluados):

```bash
python bench/benchmark.py                                    # todas las referencias
python bench/benchmark.py --repo-ids repo-juice-sample       # solo un subconjunto
python bench/benchmark.py --save-as-baseline --feature "fx"  # fijar baseline.json
python bench/test_tiny.py                                    # ejemplo pequeño (smoke test)
```

### Pruebas

Suite autónoma (unittest, sin dependencias nuevas) con un ejemplo pequeño:

```bash
python -m unittest discover -s tests -v
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
