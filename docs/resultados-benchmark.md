# Resultados del Benchmark de Precisión (Baseline)

Este documento registra la **línea base oficial (baseline)** del motor SAST contra
repositorios de referencia reales con commits inmutables, conforme a la regla 7 de
`AGENTS.md` y los requerimientos de evaluación objetiva de precisión.

---

## 1. Metodología y repositorios evaluados

Para garantizar que el benchmark sea una medición honesta e imparcial y no un sobreajuste
sobre ejemplos de juguete:

1. **Repositorio reservado (Holdout / Test ciego)**:
   - **Nombre**: `OWASP Benchmark for Python` (`repo-owasp-benchmark-python`)
   - **URL**: [https://github.com/OWASP-Benchmark/BenchmarkPython](https://github.com/OWASP-Benchmark/BenchmarkPython)
   - **Commit evaluado**: `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`
   - **Ground Truth**: `expectedresults-0.1.csv` (1,230 casos de prueba en `testcode/`, con casos vulnerables y seguros).
   - **Política de reserva**: Este repositorio está estrictamente reservado como conjunto
     de prueba ciega. Las reglas del proyecto **nunca** se diseñaron ni ajustaron
     inspeccionando sus archivos, garantizando que el recall medido refleje capacidad
     de generalización real.

2. **Repositorio de prueba de humo / ruido real**:
   - **Nombre**: `OWASP Juice Shop` (`repo-juice-shop-real`)
   - **URL**: [https://github.com/juice-shop/juice-shop](https://github.com/juice-shop/juice-shop)
   - **Commit evaluado**: `717f5efa886b0417eeecb52378b03cf10567b7e2`
   - **Tipo**: Aplicación web completa intencionalmente vulnerable (Node.js/TypeScript).
   - **Formato**: `fpr-smoke`. Al no proveer un mapeo granular de archivo+línea en su código,
     no se calculan TPR/FPR sintéticos inventados; se utiliza como corrida de humo para medir
     volumen de hallazgos y resistencia a ruido en proyectos del mundo real.

3. **Herramientas y versiones**:
   - **Semgrep**: `1.182.1`
   - **Rulesets ejecutados**: Reglas locales del proyecto (`backend/rules/security-rules.yml`),
     reglas por control (`backend/rules/semgrep/`) y copia versionada OWASP Top 10
     (`backend/rules/vendor/owasp-top-ten.json`).
   - **Commit de la herramienta**: `a7e1e923732d05d4de906b42799fc3de99ed85bf`
   - **ID de la corrida de baseline**: `bench_20261024_160402_297e7e`
   - **Fecha**: 24 de octubre de 2026, 16:04:02 UTC
   - **Archivo fuente**: `backend/bench/results/baseline.json`

---

## 2. Resumen Global (Baseline contra BenchmarkPython)

| Métrica | Valor | Detalle |
| :--- | :--- | :--- |
| **Repositorios medidos** | 1 | `OWASP Benchmark for Python` (holdout real) |
| **Casos Ground Truth (Vulnerabilidades reales)** | **452** | Casos positivos reales etiquetados en `expectedresults-0.1.csv` |
| **Hallazgos detectados por el motor** | **595** | Total de alertas reportadas en `testcode/` |
| **Verdaderos Positivos (TP)** | **47** | Aciertos comprobados con tolerancia de línea y CWE |
| **Falsos Positivos (FP)** | **548** | Alertas sobre casos seguros o disparos sin coincidencia |
| **Falsos Negativos (FN)** | **405** | Vulnerabilidades reales del ground truth no detectadas |
| **Recall global (TPR)** | **10.4%** (`0.104`) | Proporción de vulnerabilidades reales detectadas |
| **Tasa de Falsos Positivos (FPR)** | **92.1%** (`0.921`) | Proporción de falsos positivos en las detecciones |
| **Precisión global** | **7.9%** (`0.079`) | `TP / (TP + FP)` |
| **F1-Score global** | **0.090** | Media armónica entre precisión y recall |

> [!NOTE]
> En repositorios sintéticos pequeños construidos a mano el recall parecía cercano al 80–100%
> debido a reglas adaptadas a esos casos. Al evaluar contra el benchmark oficial de OWASP
> (1,230 casos con variantes complejas de sintaxis y flujo de datos), se observa la verdadera
> línea base de herramientas SAST basadas en patrones sin análisis estático profundo o triage IA.

---

## 3. Desglose de Precisión por Categoría CWE

A continuación se detalla el comportamiento del motor por cada categoría de vulnerabilidad:

| CWE | Nombre de Vulnerabilidad | GT | Det | TP | FP | FN | TPR (Recall) | FPR | Precisión | F1-Score |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **CWE-502** | Deserialization of Untrusted Data | 18 | 30 | 18 | 12 | 0 | **100.0%** | **40.0%** | 60.0% | 0.750 |
| **CWE-94** | Code Injection (eval / exec) | 20 | 53 | 20 | 33 | 0 | **100.0%** | **62.3%** | 37.7% | 0.548 |
| **CWE-78** | OS Command Injection | 13 | 14 | 7 | 7 | 6 | **53.8%** | **50.0%** | 50.0% | 0.518 |
| **CWE-22** | Path Traversal | 65 | 261 | 2 | 259 | 63 | **3.1%** | **99.2%** | 0.8% | 0.012 |
| **CWE-89** | SQL Injection | 5 | 82 | 0 | 82 | 5 | **0.0%** | **100.0%** | 0.0% | 0.000 |
| **CWE-79** | Cross-Site Scripting (XSS) | 31 | 16 | 0 | 16 | 31 | **0.0%** | **100.0%** | 0.0% | 0.000 |
| **CWE-611** | XML External Entity (XXE) | 8 | 57 | 0 | 57 | 8 | **0.0%** | **100.0%** | 0.0% | 0.000 |
| **CWE-327** | Broken Cryptographic Algorithm | 0 | 54 | 0 | 54 | 0 | — | 100.0% | 0.0% | 0.000 |
| **CWE-328** | Reversible One-Way Hash | 71 | 0 | 0 | 0 | 71 | **0.0%** | 0.0% | — | — |
| **CWE-330** | Insufficient Random Values | 99 | 0 | 0 | 0 | 99 | **0.0%** | 0.0% | — | — |
| **CWE-643** | XPath Injection | 51 | 0 | 0 | 0 | 51 | **0.0%** | 0.0% | — | — |
| **CWE-614** | Insecure Cookie without Secure Flag | 24 | 0 | 0 | 0 | 24 | **0.0%** | 0.0% | — | — |
| **CWE-501** | Trust Boundary Violation | 18 | 0 | 0 | 0 | 18 | **0.0%** | 0.0% | — | — |
| **CWE-90** | LDAP Injection | 16 | 0 | 0 | 0 | 16 | **0.0%** | 0.0% | — | — |
| **CWE-601** | Open Redirect (URL Redirection) | 13 | 0 | 0 | 0 | 13 | **0.0%** | 0.0% | — | — |

---

## 4. Análisis de Resultados y Oportunidades de Mejora

1. **Fortalezas comprobadas**:
   - **Deserialización (CWE-502)**: Recall perfecto (100.0%) con 18 aciertos de 18 casos. Las reglas locales de detección de `pickle.loads`, `yaml.load` y módulos no seguros capturaron todas las instancias vulnerables.
   - **Inyección de Código (CWE-94)**: Recall perfecto (100.0%) con 20 aciertos de 20 casos en invocaciones peligrosas de `eval` y `exec`.
   - **Inyección de Comandos (CWE-78)**: Recall del 53.8% con precisión balanceada del 50.0%.

2. **Fuentes principales de ruido (Falsos Positivos)**:
   - **Path Traversal (CWE-22)**: Genera 259 falsos positivos en el benchmark porque los patrones de Semgrep marcan aperturas de archivos (`open(...)`, `os.path.join`) que en los casos de prueba seguros ya sanitizaban la ruta.
   - **Inyección SQL (CWE-89)**: 82 falsos positivos provenientes de reglas genéricas del registro OWASP que alertan sobre strings SQL construidas con parámetros seguros o consultas parametrizadas.

3. **El rol del Agente de Triage con IA (F5)**:
   - El benchmark multi-modelo documentado en `storage/benchmark/` demuestra que la activación del agente de triage acotado reduce la tasa de falsos positivos en un **~35% a 48%** en estas categorías ruidosas, sin descartar los verdaderos positivos.

---

## 5. Cómo reproducir estos resultados

Desde la raíz del proyecto con el entorno virtual activado:

```bash
cd backend

# Ejecutar el benchmark contra el repo reservado y guardar como baseline:
python bench/benchmark.py \
  --repo-ids repo-owasp-benchmark-python \
  --save-as-baseline \
  --feature p0-3-real-benchmark

# Ejecutar la corrida completa incluyendo Juice Shop (humo) y BenchmarkPython:
python bench/benchmark.py --save-as-baseline
```

Los resultados se persisten en `backend/bench/results/baseline.json` y se pueden consultar
desde la API en `GET /api/bench` o en la pestaña **Benchmark** del Dashboard.
