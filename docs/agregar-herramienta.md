# Guía: cómo agregar una herramienta de escaneo

Todas las herramientas opcionales viven en `backend/scanner_tools.py`. El
principio: si el binario no está, la herramienta se marca `"unavailable"` y el
análisis **sigue** — nunca rompe el escaneo.

---

## 1. Patrón de una herramienta

Tres piezas:

1. **Detección del binario**: `_tool_bin(nombre, env_var)` — primero respeta la
   variable de entorno `<HERRAMIENTA>_PATH` (p. ej. `OSV_SCANNER_PATH`), si no
   busca en el PATH con `shutil.which`. Si no existe, devuelve `None`.
2. **Ejecución**: helper `_run_process(args, timeout)` que devuelve
   `(stdout, returncode, status)`. Los escáneres que salen con exit 1 cuando
   encuentran issues se aceptan (`code in (0, 1)`).
3. **Hallazgo normalizado**: `_make_finding(tool, rule, severity, file, line,
   title, problem, solution, cwe, owasp, references, extra)` sella cada
   detección con `sources` (procedencia) y `tools` (qué herramienta la vio).

Ejemplo completo integrado: `_run_osv` + `_finding_from_osv` (OSV-Scanner para
dependencias: parsea JSON, calcula severidad desde CVSS y arma el hallazgo).

---

## 2. Pasos concretos

1. Escribí `_run_<herramienta>(root, timeout) -> (findings, status)` siguiendo
   el patrón del punto 1: `_tool_bin("...", "<HERRAMIENTA>_PATH")`, correr el
   binario con salida JSON si la tiene, y parsear a hallazgos con
   `_make_finding` (o un `_finding_from_<herramienta>` si necesita lógica
   propia).
2. Conectala en `run_tools(root, stack, scan_git_history, timeout_budget)` con
   los helpers `run_findings(nombre, fn, condición)` o
   `run_report(nombre, key, fn, condición)`; elegí la condición según el stack
   detectado (p. ej. osv-scanner corre solo si hay archivos de dependencias;
   checkov/trivy solo con IaC).
3. Declará la variable de entorno `<HERRAMIENTA>_PATH` en la tabla de
   `AGENTS.md` (todas son opcionales).
4. Agregá pruebas en `backend/tests/test_scanner_tools.py`: caso binario
   presente (stub con salida realista) y caso ausente (`unavailable`).

---

## 3. Fusión multi-herramienta

Las detecciones repetidas entre herramientas se fusionan en
`merge_tool_findings` con `_same_issue` (mismo archivo + CWE + líneas ±2, o
identidad de dependencia): se conserva la **severidad más alta** y se unen los
campos `tools`/`sources`. Tu parser no necesita deduplicar: la fusión es
central.

---

## 4. Restricciones

- La herramienta lee el repo, no lo ejecuta: nada de hooks de post-install ni
  scripts del proyecto analizado.
- Timeout acotado por el presupuesto total (`SECURITY_TOTAL_TIMEOUT`).
- Salida siempre JSON cuando exista el formato; nunca parses HTML.
