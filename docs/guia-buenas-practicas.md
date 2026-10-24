# Guía de Buenas Prácticas y Mantenimiento de la Plataforma (Entregable 5)

Esta guía documenta los procedimientos operativos estándar para el mantenimiento,
actualización de reglas, ejecución de benchmarks, rotación de credenciales, integración
de nuevos escáneres y gestión de SLAs de remediación en **Security Control Center**.

---

## 1. Actualización de Reglas de Seguridad

La plataforma combina tres capas de reglas SAST deterministas:

### A. Reglas locales del proyecto (`backend/rules/security-rules.yml`)
- Contiene patrones Semgrep para vulnerabilidades comunes (SQLi, Command Injection, Insecure Deserialization, eval/exec, Hardcoded Secrets).
- Para agregar una regla nueva:
  1. Define un identificador único con prefijo de lenguaje (ej. `py-sqli-orm-bypass`).
  2. Asigna la severidad contextual (`CRITICO`, `ALTO`, `MEDIO`, `BAJO`) en `metadata.criticidad`.
  3. Mapea el CWE oficial (`metadata.cwe: "CWE-89"`) y la categoría OWASP (`metadata.owasp: "A03:2021 - Injection"`).
  4. Agrega un mensaje claro con la solución segura recomendada.

### B. Reglas por control (`backend/rules/semgrep/<control>/`)
- Implementan los 35 controles del inventario v1.0 (CORS comodín con credenciales, cookies sin Secure/HttpOnly, SSRF, JWT sin verificación, etc.).
- Cada regla debe incluir pruebas en su subdirectorio (`<regla>.test.<ext>` con casos detectables y casos seguros).
- Verificar que la regla no genere falsos positivos antes de commitear:
  ```bash
  semgrep --test backend/rules/semgrep/<control>/
  ```

### C. Copia versionada de reglas OWASP Top 10 (`backend/rules/vendor/`)
- Mantiene una instantánea reproducible y funcional sin red en [`backend/rules/vendor/owasp-top-ten.json`](file:///home/productdeath/Documentos/UNIVERSAL/UNI/ESTADIA/HUGO/NEUROTRY/demo-seguridad/backend/rules/vendor/owasp-top-ten.json).
- Para actualizar el ruleset versionado desde el registro de Semgrep:
  ```bash
  semgrep --config=p/owasp-top-ten --dump-config > backend/rules/vendor/owasp-top-ten.json
  ```
- Documentar en [`owasp-top-ten.meta.json`](file:///home/productdeath/Documentos/UNIVERSAL/UNI/ESTADIA/HUGO/NEUROTRY/demo-seguridad/backend/rules/vendor/owasp-top-ten.meta.json) la fecha de extracción, versión de Semgrep y SHA256 del archivo.

---

## 2. Ejecución y Evaluación del Benchmark

El benchmark evalúa objetivamente la tasa de verdaderos positivos (Recall/TPR) y falsos positivos (FPR) contra repositorios de referencia reales declarados en [`backend/bench/refs.yml`](file:///home/productdeath/Documentos/UNIVERSAL/UNI/ESTADIA/HUGO/NEUROTRY/demo-seguridad/backend/bench/refs.yml).

### Comandos de ejecución

```bash
cd backend

# 1. Smoke test rápido en desarrollo (ejemplo pequeño de 5 vulnerabilidades):
python bench/test_tiny.py

# 2. Corrida sobre el repositorio reservado holdout (OWASP BenchmarkPython real):
python bench/benchmark.py --repo-ids repo-owasp-benchmark-python --feature ajuste-reglas

# 3. Guardar corrida como nueva línea base (baseline):
python bench/benchmark.py --repo-ids repo-owasp-benchmark-python --save-as-baseline --feature release-v1.1
```

### Criterios de evaluación
- **Delta Recall**: Un recall que desciende respecto a la baseline indica una regresión inaceptable en detección.
- **Delta FPR**: Una disminución de FPR manteniendo el recall representa una mejora genuina de precisión.
- **Repositorio reservado (Holdout)**: Nunca ajuste reglas observando directamente el código de `repo-owasp-benchmark-python`. Las reglas solo deben afinarse contra especificaciones de controles y ejemplos propios.

---

## 3. Rotación de Tokens en el Proxy de Secretos (F8)

El proxy intermedio garantiza que ningún agente de IA acceda a claves de proveedores directos. La autenticación utiliza tokens con hash criptográfico SHA-256.

### Procedimiento de rotación sin interrupción

1. **Generar un nuevo token aleatorio de alta entropía y su hash SHA-256**:
   ```bash
   python -c "import hashlib, secrets; t='sec-'+secrets.token_urlsafe(24); print('NUEVO TOKEN:', t); print('HASH SHA256:', hashlib.sha256(t.encode()).hexdigest())"
   ```

2. **Actualizar el archivo de tokens (`backend/proxy/tokens.json`)**:
   Añade la nueva entrada al array conservando temporalmente la anterior durante la ventana de corte:
   ```json
   [
     {
       "id": "agent-triage-v2",
       "token_sha256": "<hash-del-nuevo-token>",
       "providers": ["gemini", "openai"],
       "rate_limit_per_minute": 150
     }
   ]
   ```

3. **Actualizar la variable de entorno en el cliente**:
   ```bash
   export SECURITY_PROXY_TOKEN="sec-<nuevo-token-generado>"
   ```

4. **Revocación inmediata**: Al eliminar la entrada del token anterior de `tokens.json`, el token revocado queda invalidado de forma instantánea (falla cerrada con HTTP 401).

---

## 4. Incorporación de Nuevos Escáneres (`backend/scanner_tools.py`)

Para integrar un nuevo analizador estático o de dependencias (ej. `npm audit`, `trivy`, `bandit`, `checkov`):

1. **Detección de stack**:
   En `scanner_tools.detect_stack()`, añadir la regla de presencia de manifiestos (ej. `Cargo.toml`, `go.mod`, `pom.xml`).
2. **Función del escáner con presupuesto de tiempo y modo offline**:
   Implementar `_run_<herramienta>(target_dir, timeout_budget)` respetando `check=False` y captura de excepciones.
3. **Normalización al esquema unificado**:
   Cada hallazgo debe transformarse al esquema universal de la plataforma:
   ```python
   {
       "rule": "herramienta.id-regla",
       "severity": "critical|high|medium|low",
       "file": "ruta/relativa.ext",
       "line": 42,
       "problem": "Descripción concisa del riesgo",
       "solution": "Acción correctiva específica",
       "cwe": ["CWE-XXX"],
       "owasp": "AXX:2021 - Categoría",
       "tools": ["nombre_herramienta"]
   }
   ```
4. **Fusión y deduplicación**:
   La función `merge_findings()` fusiona alertas repetidas entre escáneres sobre el mismo archivo y línea, reteniendo la severidad máxima y agregando todas las herramientas que lo detectaron.

---

## 5. Plazos de Remediación por Severidad (SLA - Control 6)

El motor contextual de severidad asigna automáticamente los plazos máximos de remediación requeridos por la política de seguridad institucional:

| Severidad | Plazo Máximo de Remediación (SLA) | Criterio y Ejemplos |
| :--- | :---: | :--- |
| 🔴 **Critical** | **7 días corridos** | Ejecución remota de código (RCE), SQLi en endpoints expuestos, credenciales de producción filtradas, deshabilitación de TLS. Bloquea CI/CD. |
| 🟠 **High** | **30 días corridos** | XSS almacenado, SSRF en servicios internos, falta de autorización RBAC/IDOR, deserialización insegura. |
| 🟡 **Medium** | **90 días corridos** | Cookies sin flags `Secure`/`HttpOnly`, falta de rate limiting, cabeceras de seguridad ausentes (CSP, HSTS), DEBUG activo en desarrollo. |
| 🔵 **Low** | **180 días corridos** | Divulgación menor de versiones en cabeceras HTTP, configuraciones subóptimas de linter, observaciones de arquitectura. |

---

## 6. Buenas Prácticas Derivadas del Agente Redactor (F9)

A partir del análisis realizado sobre el código fuente de la plataforma con el agente redactor determinista ([`backend/writer_agent.py`](file:///home/productdeath/Documentos/UNIVERSAL/UNI/ESTADIA/HUGO/NEUROTRY/demo-seguridad/backend/writer_agent.py)), se establecen las siguientes reglas de desarrollo seguro:

### A01:2021 — Broken Access Control
- **Principio de menor privilegio en tokens de CI/CD**: Desactive `persist-credentials` en GitHub Actions (`persist-credentials: false`) y restrinja los permisos del flujo a `contents: read`.
- **Validación de rutas y orígenes**: En endpoints API, aplique allowlists estrictas de orígenes CORS (`CORS_ALLOWED_ORIGINS`) evitando comodines `*` asociados a credenciales.

### A02:2021 — Cryptographic Failures
- **Aislamiento de credenciales**: Nunca almacene claves privadas ni tokens de proveedores de IA en variables de entorno accesibles por los procesos de análisis. Utilice exclusivamente el proxy F8 con hashes SHA-256.
- **Redacción previa**: Antes de enviar cualquier fragmento a modelos de lenguaje o bitácoras de auditoría, procese el texto mediante máscaras `[REDACTED_SECRET]`.

### A03:2021 — Injection
- **Subprocesos seguros**: Prohíba terminantemente el uso de `shell=True` en llamadas a `subprocess.run()`. Pase los comandos como listas de argumentos validados.
- **Consultas parametrizadas**: Nunca concatene cadenas de texto en consultas a bases de datos o en la construcción de comandos del sistema operativo.

### A05:2021 — Security Misconfiguration
- **Entornos de producción endurecidos**: Compruebe que `DEBUG = False` en servidores web y desactive páginas de traza de errores detalladas con stack traces en clientes HTTP.
- **Falla cerrada en seguridad**: Si un componente de seguridad (escáner o proxy) presenta una condición de error, aborte el proceso o degrade de forma segura advirtiendo al usuario; nunca simule una salida limpia ante fallos no controlados.
