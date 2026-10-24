# Informe de seguridad — tiny-vuln-app

- **Repositorio:** https://github.com/vulnerable-org/tiny-vuln-app
- **Rama:** main
- **Commit (SHA):** 9c2d1e4a7b5e3f1c8a0d9e8b7a6c5d4e3f2a1b0c
- **Fecha de análisis:** 2026-10-24T16:34:52.218496+00:00
- **ID de análisis:** analysis-terceros-tiny-vuln-app
- **Estado:** completed: estado.

## Resumen por severidad

Total de hallazgos: **7**.

| Severidad | Cantidad |
| :--- | :--- |
| critical | 5 |
| high | 1 |
| medium | 1 |
| low | 0 |

## Estado de remediación

- `open`: 4
- `patch_proposed`: 1
- `verified`: 1
- `discarded`: 0
- `approved`: 1
- `rejected`: 0

Los estados distintos de `open` provienen del bucle de remediación asistida (F6).

## Hallazgos

### [1] Detected potential OS command injection via unvalidated system execution. — app.py:8

- Hallazgo 1 — severidad crítica — app.py:8.
- ¿Qué es? Detected potential OS command injection via unvalidated system execution..
- Detalle: Detected potential OS command injection via unvalidated system execution.
- ¿Por qué tiene esta severidad? Severidad critical: inyección crítica o ejecución remota de comandos en ruta HTTP o controlador expuesto, asociado al Control 4: Validación y Sanitización de Entradas e Inyecciones.
- Clasificación: CWE-78.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: verified.

### [2] Detected SQL injection risk: dynamic SQL query constructed via concatenation. — app.py:14

- Hallazgo 2 — severidad crítica — app.py:14.
- ¿Qué es? Detected SQL injection risk: dynamic SQL query constructed via concatenation..
- Detalle: Detected SQL injection risk: dynamic SQL query constructed via concatenation.
- ¿Por qué tiene esta severidad? Severidad critical: inyección crítica o ejecución remota de comandos en ruta HTTP o controlador expuesto, asociado al Control 4: Validación y Sanitización de Entradas e Inyecciones.
- Clasificación: CWE-89.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: approved.

### [3] Detected arbitrary code execution via eval() or exec(). — app.py:20

- Hallazgo 3 — severidad crítica — app.py:20.
- ¿Qué es? Detected arbitrary code execution via eval() or exec()..
- Detalle: Detected arbitrary code execution via eval() or exec().
- ¿Por qué tiene esta severidad? Severidad critical: inyección crítica o ejecución remota de comandos en ruta HTTP o controlador expuesto, asociado al Control 4: Validación y Sanitización de Entradas e Inyecciones.
- Clasificación: CWE-94.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: patch_proposed.

### [4] Detected possible hardcoded credentials or secret in source code. — app.py:26

- Hallazgo 4 — severidad crítica — app.py:26.
- ¿Qué es? Detected possible hardcoded credentials or secret in source code..
- Detalle: Detected possible hardcoded credentials or secret in source code.
- ¿Por qué tiene esta severidad? Severidad critical: secreto o credencial expuesta en ruta HTTP o controlador expuesto, asociado al Control 1: Gestión de Identidades, Credenciales y Autenticación.
- Clasificación: CWE-798.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [5] Detected broken or weak cryptographic hash function (MD5/SHA1). — app.py:27

- Hallazgo 5 — severidad alta — app.py:27.
- ¿Qué es? Detected broken or weak cryptographic hash function (MD5/SHA1)..
- Detalle: Detected broken or weak cryptographic hash function (MD5/SHA1).
- ¿Por qué tiene esta severidad? Severidad high: vulnerabilidad en código en ruta HTTP o controlador expuesto, asociado al Control 3: Protección Criptográfica de Datos en Tránsito y Reposo.
- Clasificación: CWE-327.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [6] Detected possible hardcoded credentials or secret in source code. — app.py:32

- Hallazgo 6 — severidad crítica — app.py:32.
- ¿Qué es? Detected possible hardcoded credentials or secret in source code..
- Detalle: Detected possible hardcoded credentials or secret in source code.
- ¿Por qué tiene esta severidad? Severidad critical: secreto o credencial expuesta en ruta HTTP o controlador expuesto, asociado al Control 1: Gestión de Identidades, Credenciales y Autenticación.
- Clasificación: CWE-798.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [7] Dependabot no está configurado — .github/dependabot.yml

- Hallazgo 7 — severidad media — .github/dependabot.yml.
- ¿Qué es? Dependabot no está configurado.
- Detalle: El repositorio no configura Dependabot: las dependencias no reciben actualizaciones automáticas de seguridad.
- ¿Por qué tiene esta severidad? Severidad medium: dependencia vulnerable en archivo de configuración de infraestructura, asociado al Control 6: Gestión de Vulnerabilidades y Parcheo de Dependencias.
- Clasificación: CWE-1104.
- Cómo corregirlo: Agregá .github/dependabot.yml con un bloque 'package-ecosystem' y 'schedule' por cada gestor detectado.
- Estado de remediación: open.

## Guía de buenas prácticas (agente redactor)

> Cada sección proviene exclusivamente de hallazgos reales de este análisis.

### A03:2021 - Injection — 3 hallazgo(s)

- Review the finding and apply the secure coding guidance for this rule.

### A07:2021 - Identification and Authentication Failures — 2 hallazgo(s)

- Review the finding and apply the secure coding guidance for this rule.

### A02:2021 - Cryptographic Failures — 1 hallazgo(s)

- Review the finding and apply the secure coding guidance for this rule.

### A06:2021 - Vulnerable and Outdated Components — 1 hallazgo(s)

- Agregá .github/dependabot.yml con un bloque 'package-ecosystem' y 'schedule' por cada gestor detectado.

## Datos faltantes declarados

- `finding 7` → falta `line`.
