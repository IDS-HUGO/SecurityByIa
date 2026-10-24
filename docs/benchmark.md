# Guía: cómo medir contra los repos de referencia (benchmark)

El benchmark mide la precisión del motor SAST contra repositorios con
verdad de terreno (ground truth). La lógica vive en
`backend/benchmark_service.py`; los **datos** en `backend/bench/`.

---

## 1. Declara los repos: `bench/refs.yml`

Lista `repositories` con `id`, `url` (ruta local relativa o URL git), `name`,
`type`, `format` y `description`. El motor nunca conoce los nombres: los ids de
`refs.yml` son solo datos (regla 7 de AGENTS.md).

---

## 2. Formatos de ground truth aceptados

| Formato (`format`) | Archivo | Campos |
| :--- | :--- | :--- |
| `vuln-markers` | `vulnerabilities.json` (en `data/static/`, raíz o `data/`) | `vuln_code_snippet` (archivo), `vuln_line`, `cwe`, `name` |
| `csv-expected-results` | `expectedresults-0.1.csv` (rglob) | `TestCaseNumber`, `CWE`, `Result` (solo Result=1 cuenta; archivo derivado `src/test_<num>.py`) |

Ejemplos reales en `backend/bench/examples/`.

---

## 3. Matching y métricas

- `match_findings`: cruza hallazgos del análisis con el ground truth por
  archivo + CWE + tolerancia de línea ≤3 (score: file+line 1.0−diff/10;
  file+CWE 0.75; CWE+line 0.70; umbral ≥0.6). Resultado: TP / FP / FN.
- `calculate_metrics_dict`: recall, TPR, FPR, precisión y F1, globales y por
  categoría CWE (`aggregate_cwe_table`).
- `compare_metrics`: deltas en puntos contra la corrida previa y la baseline.

---

## 4. Correr el benchmark

```bash
cd backend
# Todos los repos de refs.yml:
python bench/benchmark.py
# Un subconjunto y guardar como baseline:
python bench/benchmark.py --repo-ids repo-a repo-b --save-as-baseline --feature mi-feature
# Smoke test rápido del ejemplo pequeño:
python bench/test_tiny.py
```

Cada corrida analiza los repos con `analyzer.analyze_directory` (sin IA),
matchea y persiste en:

- `backend/storage/benchmark/runs/<run_id>.json` (y espejo en `bench/results/`),
- `backend/storage/benchmark/latest.json` e índice `history.json` (tope 30),
- `baseline.json` (la primera corrida se vuelve baseline automáticamente).

Metadata registrada por corrida: versión de Semgrep, reglas aplicadas
(`get_rules_metadata` lee `rules/security-rules.yml`) y commits evaluados.

---

## 5. Interpretar

El reporte en stdout (`print_report`) muestra métricas globales, tabla por CWE
y deltas contra la corrida previa. Un FPR que baja sin perder recall es una
mejora real; un recall que baja es regresión — el delta contra la baseline lo
hace visible. El dashboard muestra lo mismo en la pestaña Benchmark.
