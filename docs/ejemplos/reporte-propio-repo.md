# Informe de seguridad — demo-seguridad

- **Repositorio:** https://github.com/empresa/demo-seguridad
- **Rama:** main
- **Commit (SHA):** a7e1e923732d05d4de906b42799fc3de99ed85bf
- **Fecha de análisis:** 2026-10-24T16:34:45.385102+00:00
- **ID de análisis:** analysis-demo-seguridad-propio
- **Estado:** completed: estado.

## Resumen por severidad

Total de hallazgos: **93**.

| Severidad | Cantidad |
| :--- | :--- |
| critical | 9 |
| high | 36 |
| medium | 36 |
| low | 12 |

## Estado de remediación

- `open`: 85
- `patch_proposed`: 1
- `verified`: 6
- `discarded`: 0
- `approved`: 1
- `rejected`: 0

Los estados distintos de `open` provienen del bucle de remediación asistida (F6).

## Hallazgos

### [1] GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`. — .github/workflows/security-scan.yml:29

- Hallazgo 1 — severidad media — .github/workflows/security-scan.yml:29.
- ¿Qué es? GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`..
- Detalle: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en archivo de configuración de infraestructura.
- Clasificación: CWE-1357.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: verified.

### [2] GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`. — .github/workflows/security-scan.yml:33

- Hallazgo 2 — severidad media — .github/workflows/security-scan.yml:33.
- ¿Qué es? GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`..
- Detalle: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en archivo de configuración de infraestructura.
- Clasificación: CWE-1357.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: approved.

### [3] GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`. — .github/workflows/security-scan.yml:49

- Hallazgo 3 — severidad media — .github/workflows/security-scan.yml:49.
- ¿Qué es? GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`..
- Detalle: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en archivo de configuración de infraestructura.
- Clasificación: CWE-1357.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: patch_proposed.

### [4] GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`. — .github/workflows/security-scan.yml:62

- Hallazgo 4 — severidad media — .github/workflows/security-scan.yml:62.
- ¿Qué es? GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`..
- Detalle: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en archivo de configuración de infraestructura.
- Clasificación: CWE-1357.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [5] GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`. — .github/workflows/security-scan.yml:78

- Hallazgo 5 — severidad media — .github/workflows/security-scan.yml:78.
- ¿Qué es? GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`..
- Detalle: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en archivo de configuración de infraestructura.
- Clasificación: CWE-1357.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [6] Control 7 (ALTO): endpoint costoso sin decorador/dependencia de rate limiting; agregá límites por IP y por usuario según el costo del endpoint. — backend/api_server.py:277

- Hallazgo 6 — severidad media — backend/api_server.py:277.
- ¿Qué es? Control 7 (ALTO): endpoint costoso sin decorador/dependencia de rate limiting; agregá límites por IP y por usuario según el costo del endpoint..
- Detalle: Control 7 (ALTO): endpoint costoso sin decorador/dependencia de rate limiting; agregá límites por IP y por usuario según el costo del endpoint.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en código base.
- Clasificación: CWE-770.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [7] Control 7 (ALTO): endpoint costoso sin decorador/dependencia de rate limiting; agregá límites por IP y por usuario según el costo del endpoint. — backend/api_server.py:287

- Hallazgo 7 — severidad media — backend/api_server.py:287.
- ¿Qué es? Control 7 (ALTO): endpoint costoso sin decorador/dependencia de rate limiting; agregá límites por IP y por usuario según el costo del endpoint..
- Detalle: Control 7 (ALTO): endpoint costoso sin decorador/dependencia de rate limiting; agregá límites por IP y por usuario según el costo del endpoint.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en código base.
- Clasificación: CWE-770.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [8] Detected possible hardcoded credentials or secret in source code. — backend/bench/examples/api-auth-bench/api.py:6

- Hallazgo 8 — severidad alta — backend/bench/examples/api-auth-bench/api.py:6.
- ¿Qué es? Detected possible hardcoded credentials or secret in source code..
- Detalle: Detected possible hardcoded credentials or secret in source code.
- ¿Por qué tiene esta severidad? Severidad high: secreto o credencial expuesta en archivo de pruebas internas, asociado al Control 1: Gestión de Identidades, Credenciales y Autenticación.
- Clasificación: CWE-798.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [9] Control 7 (ALTO): endpoint costoso sin decorador/dependencia de rate limiting; agregá límites por IP y por usuario según el costo del endpoint. — backend/bench/examples/api-auth-bench/api.py:8

- Hallazgo 9 — severidad baja — backend/bench/examples/api-auth-bench/api.py:8.
- ¿Qué es? Control 7 (ALTO): endpoint costoso sin decorador/dependencia de rate limiting; agregá límites por IP y por usuario según el costo del endpoint..
- Detalle: Control 7 (ALTO): endpoint costoso sin decorador/dependencia de rate limiting; agregá límites por IP y por usuario según el costo del endpoint.
- ¿Por qué tiene esta severidad? Severidad low: vulnerabilidad en código en archivo de pruebas internas.
- Clasificación: CWE-770.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [10] Detected broken or weak cryptographic hash function (MD5/SHA1). — backend/bench/examples/api-auth-bench/api.py:12

- Hallazgo 10 — severidad media — backend/bench/examples/api-auth-bench/api.py:12.
- ¿Qué es? Detected broken or weak cryptographic hash function (MD5/SHA1)..
- Detalle: Detected broken or weak cryptographic hash function (MD5/SHA1).
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en archivo de pruebas internas, asociado al Control 3: Protección Criptográfica de Datos en Tránsito y Reposo.
- Clasificación: CWE-327.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [11] Detected SQL injection risk: dynamic SQL query constructed via concatenation. — backend/bench/examples/api-auth-bench/api.py:19

- Hallazgo 11 — severidad alta — backend/bench/examples/api-auth-bench/api.py:19.
- ¿Qué es? Detected SQL injection risk: dynamic SQL query constructed via concatenation..
- Detalle: Detected SQL injection risk: dynamic SQL query constructed via concatenation.
- ¿Por qué tiene esta severidad? Severidad high: inyección crítica o ejecución remota de comandos en archivo de pruebas internas, asociado al Control 4: Validación y Sanitización de Entradas e Inyecciones.
- Clasificación: CWE-89.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [12] Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using an object-relational mapper (ORM) such as SQLAlchemy which will protect your queries. — backend/bench/examples/api-auth-bench/api.py:19

- Hallazgo 12 — severidad baja — backend/bench/examples/api-auth-bench/api.py:19.
- ¿Qué es? Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using an object-relational mapper (ORM) such as SQLAlchemy which will protect your queries..
- Detalle: Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using an object-relational mapper (ORM) such as SQLAlchemy which will protect your queries.
- ¿Por qué tiene esta severidad? Severidad low: vulnerabilidad en código en archivo de pruebas internas.
- Clasificación: CWE-704.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [13] Detected Flask route directly returning a formatted string. This is subject to cross-site scripting if user input can reach the string. Consider using the template engine instead and rendering pages with 'render_template()'. — backend/bench/examples/api-auth-bench/api.py:20

- Hallazgo 13 — severidad alta — backend/bench/examples/api-auth-bench/api.py:20.
- ¿Qué es? Detected Flask route directly returning a formatted string. This is subject to cross-site scripting if user input can reach the string. Consider using the template engine instead and rendering pages with 'render_template()'..
- Detalle: Detected Flask route directly returning a formatted string. This is subject to cross-site scripting if user input can reach the string. Consider using the template engine instead and rendering pages with 'render_template()'.
- ¿Por qué tiene esta severidad? Severidad high: vulnerabilidad de acceso o inyección en aplicación en archivo de pruebas internas, asociado al Control 4: Validación y Sanitización de Entradas e Inyecciones.
- Clasificación: CWE-79.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [14] Found user data in a call to 'eval'. This is extremely dangerous because it can enable an attacker to execute arbitrary remote code on the system. Instead, refactor your code to not use 'eval' and instead use a safe library for the specific functionality you need. — backend/bench/examples/api-auth-bench/api.py:24

- Hallazgo 14 — severidad alta — backend/bench/examples/api-auth-bench/api.py:24.
- ¿Qué es? Found user data in a call to 'eval'. This is extremely dangerous because it can enable an attacker to execute arbitrary remote code on the system. Instead, refactor your code to not use 'eval' and instead use a safe library for the specific functionality you need..
- Detalle: Found user data in a call to 'eval'. This is extremely dangerous because it can enable an attacker to execute arbitrary remote code on the system. Instead, refactor your code to not use 'eval' and instead use a safe library for the specific functionality you need.
- ¿Por qué tiene esta severidad? Severidad high: inyección crítica o ejecución remota de comandos en archivo de pruebas internas, asociado al Control 4: Validación y Sanitización de Entradas e Inyecciones.
- Clasificación: CWE-95.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [15] Detected arbitrary code execution via eval() or exec(). — backend/bench/examples/api-auth-bench/api.py:26

- Hallazgo 15 — severidad alta — backend/bench/examples/api-auth-bench/api.py:26.
- ¿Qué es? Detected arbitrary code execution via eval() or exec()..
- Detalle: Detected arbitrary code execution via eval() or exec().
- ¿Por qué tiene esta severidad? Severidad high: inyección crítica o ejecución remota de comandos en archivo de pruebas internas, asociado al Control 4: Validación y Sanitización de Entradas e Inyecciones.
- Clasificación: CWE-94.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [16] Detected potential OS command injection via unvalidated system execution. — backend/bench/examples/benchmark-python/src/test_1.py:10

- Hallazgo 16 — severidad alta — backend/bench/examples/benchmark-python/src/test_1.py:10.
- ¿Qué es? Detected potential OS command injection via unvalidated system execution..
- Detalle: Detected potential OS command injection via unvalidated system execution.
- ¿Por qué tiene esta severidad? Severidad high: inyección crítica o ejecución remota de comandos en archivo de pruebas internas, asociado al Control 4: Validación y Sanitización de Entradas e Inyecciones.
- Clasificación: CWE-78.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [17] Detected broken or weak cryptographic hash function (MD5/SHA1). — backend/bench/examples/benchmark-python/src/test_3.py:10

- Hallazgo 17 — severidad media — backend/bench/examples/benchmark-python/src/test_3.py:10.
- ¿Qué es? Detected broken or weak cryptographic hash function (MD5/SHA1)..
- Detalle: Detected broken or weak cryptographic hash function (MD5/SHA1).
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en archivo de pruebas internas, asociado al Control 3: Protección Criptográfica de Datos en Tránsito y Reposo.
- Clasificación: CWE-327.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [18] Control 1 (CRÍTICO): CORS con allow_origins=['*'] y allow_credentials=True permite que cualquier origen lea respuestas autenticadas. Definí una lista explícita de orígenes confiables. — backend/bench/examples/controls-bench/api_cors.py:4

- Hallazgo 18 — severidad baja — backend/bench/examples/controls-bench/api_cors.py:4.
- ¿Qué es? Control 1 (CRÍTICO): CORS con allow_origins=['*'] y allow_credentials=True permite que cualquier origen lea respuestas autenticadas. Definí una lista explícita de orígenes confiables..
- Detalle: Control 1 (CRÍTICO): CORS con allow_origins=['*'] y allow_credentials=True permite que cualquier origen lea respuestas autenticadas. Definí una lista explícita de orígenes confiables.
- ¿Por qué tiene esta severidad? Severidad low: vulnerabilidad en código en archivo de pruebas internas, asociado al Control 5: Configuración Segura de Infraestructura y Contenedores.
- Clasificación: CWE-942.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [19] Control 1 (CRÍTICO): cors({origin: true, credentials: true}) refleja cualquier origen y permite credenciales; usá una lista explícita de orígenes. — backend/bench/examples/controls-bench/app_express.js:2

- Hallazgo 19 — severidad baja — backend/bench/examples/controls-bench/app_express.js:2.
- ¿Qué es? Control 1 (CRÍTICO): cors({origin: true, credentials: true}) refleja cualquier origen y permite credenciales; usá una lista explícita de orígenes..
- Detalle: Control 1 (CRÍTICO): cors({origin: true, credentials: true}) refleja cualquier origen y permite credenciales; usá una lista explícita de orígenes.
- ¿Por qué tiene esta severidad? Severidad low: vulnerabilidad en código en archivo de pruebas internas, asociado al Control 5: Configuración Segura de Infraestructura y Contenedores.
- Clasificación: CWE-942.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [20] Control 3 (CRÍTICO): DEBUG = True en producción expone stack traces, rutas internas y configuración; desactivá el modo debug. — backend/bench/examples/controls-bench/config_debug.py:1

- Hallazgo 20 — severidad baja — backend/bench/examples/controls-bench/config_debug.py:1.
- ¿Qué es? Control 3 (CRÍTICO): DEBUG = True en producción expone stack traces, rutas internas y configuración; desactivá el modo debug..
- Detalle: Control 3 (CRÍTICO): DEBUG = True en producción expone stack traces, rutas internas y configuración; desactivá el modo debug.
- ¿Por qué tiene esta severidad? Severidad low: vulnerabilidad en código en archivo de pruebas internas, asociado al Control 5: Configuración Segura de Infraestructura y Contenedores.
- Clasificación: CWE-489.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: verified.

### [21] Control 10 (ALTO): cookie de sesión con flag de seguridad desactivado (secure=False / httponly=False / samesite='None'); usá Secure, HttpOnly y SameSite Strict o Lax. — backend/bench/examples/controls-bench/cookies_flags.py:2

- Hallazgo 21 — severidad baja — backend/bench/examples/controls-bench/cookies_flags.py:2.
- ¿Qué es? Control 10 (ALTO): cookie de sesión con flag de seguridad desactivado (secure=False / httponly=False / samesite='None'); usá Secure, HttpOnly y SameSite Strict o Lax..
- Detalle: Control 10 (ALTO): cookie de sesión con flag de seguridad desactivado (secure=False / httponly=False / samesite='None'); usá Secure, HttpOnly y SameSite Strict o Lax.
- ¿Por qué tiene esta severidad? Severidad low: vulnerabilidad en código en archivo de pruebas internas, asociado al Control 5: Configuración Segura de Infraestructura y Contenedores.
- Clasificación: CWE-1004.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [22] Control 1 (CRÍTICO): CORS_ALLOW_ALL_ORIGINS = True acepta cualquier origen; reemplazalo por una lista explícita de orígenes confiables. — backend/bench/examples/controls-bench/django_cors.py:2

- Hallazgo 22 — severidad baja — backend/bench/examples/controls-bench/django_cors.py:2.
- ¿Qué es? Control 1 (CRÍTICO): CORS_ALLOW_ALL_ORIGINS = True acepta cualquier origen; reemplazalo por una lista explícita de orígenes confiables..
- Detalle: Control 1 (CRÍTICO): CORS_ALLOW_ALL_ORIGINS = True acepta cualquier origen; reemplazalo por una lista explícita de orígenes confiables.
- ¿Por qué tiene esta severidad? Severidad low: vulnerabilidad en código en archivo de pruebas internas, asociado al Control 5: Configuración Segura de Infraestructura y Contenedores.
- Clasificación: CWE-942.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [23] Control 3 (CRÍTICO): app.run(debug=True) activa el depurador interactivo; en producción DEBUG debe estar desactivado. — backend/bench/examples/controls-bench/flask_debug.py:4

- Hallazgo 23 — severidad baja — backend/bench/examples/controls-bench/flask_debug.py:4.
- ¿Qué es? Control 3 (CRÍTICO): app.run(debug=True) activa el depurador interactivo; en producción DEBUG debe estar desactivado..
- Detalle: Control 3 (CRÍTICO): app.run(debug=True) activa el depurador interactivo; en producción DEBUG debe estar desactivado.
- ¿Por qué tiene esta severidad? Severidad low: vulnerabilidad en código en archivo de pruebas internas, asociado al Control 5: Configuración Segura de Infraestructura y Contenedores.
- Clasificación: CWE-489.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [24] Running flask app with host 0.0.0.0 could expose the server publicly. — backend/bench/examples/controls-bench/flask_debug.py:4

- Hallazgo 24 — severidad media — backend/bench/examples/controls-bench/flask_debug.py:4.
- ¿Qué es? Running flask app with host 0.0.0.0 could expose the server publicly..
- Detalle: Running flask app with host 0.0.0.0 could expose the server publicly.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en archivo de pruebas internas, asociado al Control 2: Control de Acceso y Autorización.
- Clasificación: CWE-668.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [25] Control 11 (ALTO): JWT con expiración de horas o días; el inventario exige access tokens de 15-30 minutos con rotación de refresh tokens. — backend/bench/examples/controls-bench/jwt_emision.py:6

- Hallazgo 25 — severidad media — backend/bench/examples/controls-bench/jwt_emision.py:6.
- ¿Qué es? Control 11 (ALTO): JWT con expiración de horas o días; el inventario exige access tokens de 15-30 minutos con rotación de refresh tokens..
- Detalle: Control 11 (ALTO): JWT con expiración de horas o días; el inventario exige access tokens de 15-30 minutos con rotación de refresh tokens.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en archivo de pruebas internas, asociado al Control 1: Gestión de Identidades, Credenciales y Autenticación.
- Clasificación: CWE-613.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [26] C13: llamada a modelo sin max_tokens/max_completion_tokens; definí límite de tokens por request, presupuesto por usuario y alertas de costo. — backend/bench/examples/controls-bench/llm_consumo.py:7

- Hallazgo 26 — severidad baja — backend/bench/examples/controls-bench/llm_consumo.py:7.
- ¿Qué es? C13: llamada a modelo sin max_tokens/max_completion_tokens; definí límite de tokens por request, presupuesto por usuario y alertas de costo..
- Detalle: C13: llamada a modelo sin max_tokens/max_completion_tokens; definí límite de tokens por request, presupuesto por usuario y alertas de costo.
- ¿Por qué tiene esta severidad? Severidad low: vulnerabilidad en código en archivo de pruebas internas.
- Clasificación: CWE-770.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [27] C7: registro de datos sensibles (token/contraseña/secret/authorization) en logs o trazas; scrubbeá el dato antes de loguearlo. — backend/bench/examples/controls-bench/logs_sensibles.py:7

- Hallazgo 27 — severidad baja — backend/bench/examples/controls-bench/logs_sensibles.py:7.
- ¿Qué es? C7: registro de datos sensibles (token/contraseña/secret/authorization) en logs o trazas; scrubbeá el dato antes de loguearlo..
- Detalle: C7: registro de datos sensibles (token/contraseña/secret/authorization) en logs o trazas; scrubbeá el dato antes de loguearlo.
- ¿Por qué tiene esta severidad? Severidad low: vulnerabilidad en código en archivo de pruebas internas, asociado al Control 7: Registro y Monitoreo de Eventos de Seguridad.
- Clasificación: CWE-532.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [28] Control 7 (ALTO): endpoint costoso sin decorador/dependencia de rate limiting; agregá límites por IP y por usuario según el costo del endpoint. — backend/bench/examples/controls-bench/ratelimit_login.py:6

- Hallazgo 28 — severidad baja — backend/bench/examples/controls-bench/ratelimit_login.py:6.
- ¿Qué es? Control 7 (ALTO): endpoint costoso sin decorador/dependencia de rate limiting; agregá límites por IP y por usuario según el costo del endpoint..
- Detalle: Control 7 (ALTO): endpoint costoso sin decorador/dependencia de rate limiting; agregá límites por IP y por usuario según el costo del endpoint.
- ¿Por qué tiene esta severidad? Severidad low: vulnerabilidad en código en archivo de pruebas internas.
- Clasificación: CWE-770.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [29] Control 7 (ALTO): endpoint costoso sin decorador/dependencia de rate limiting; agregá límites por IP y por usuario según el costo del endpoint. — backend/bench/examples/controls-bench/ratelimit_login.py:11

- Hallazgo 29 — severidad baja — backend/bench/examples/controls-bench/ratelimit_login.py:11.
- ¿Qué es? Control 7 (ALTO): endpoint costoso sin decorador/dependencia de rate limiting; agregá límites por IP y por usuario según el costo del endpoint..
- Detalle: Control 7 (ALTO): endpoint costoso sin decorador/dependencia de rate limiting; agregá límites por IP y por usuario según el costo del endpoint.
- ¿Por qué tiene esta severidad? Severidad low: vulnerabilidad en código en archivo de pruebas internas.
- Clasificación: CWE-770.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [30] Detected SQL injection risk: dynamic SQL query constructed via concatenation. — backend/bench/examples/controls-bench/sql_concat.py:2

- Hallazgo 30 — severidad alta — backend/bench/examples/controls-bench/sql_concat.py:2.
- ¿Qué es? Detected SQL injection risk: dynamic SQL query constructed via concatenation..
- Detalle: Detected SQL injection risk: dynamic SQL query constructed via concatenation.
- ¿Por qué tiene esta severidad? Severidad high: inyección crítica o ejecución remota de comandos en archivo de pruebas internas, asociado al Control 4: Validación y Sanitización de Entradas e Inyecciones.
- Clasificación: CWE-89.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [31] C4 (SSRF): petición del servidor a una URL variable (webhook/scraping) sin allowlist visible; restringí destinos con allowlist, bloqueá IPs privadas y la metadata service (IMDSv2). — backend/bench/examples/controls-bench/ssrf_webhook.py:5

- Hallazgo 31 — severidad media — backend/bench/examples/controls-bench/ssrf_webhook.py:5.
- ¿Qué es? C4 (SSRF): petición del servidor a una URL variable (webhook/scraping) sin allowlist visible; restringí destinos con allowlist, bloqueá IPs privadas y la metadata service (IMDSv2)..
- Detalle: C4 (SSRF): petición del servidor a una URL variable (webhook/scraping) sin allowlist visible; restringí destinos con allowlist, bloqueá IPs privadas y la metadata service (IMDSv2).
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en archivo de pruebas internas, asociado al Control 9: Protección contra Solicitudes Falsificadas y SSRF.
- Clasificación: CWE-918.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [32] Control 10 (ALTO): token de sesión guardado en localStorage (accesible por XSS); usá cookies con Secure, HttpOnly y SameSite. — backend/bench/examples/controls-bench/ui_session.js:2

- Hallazgo 32 — severidad media — backend/bench/examples/controls-bench/ui_session.js:2.
- ¿Qué es? Control 10 (ALTO): token de sesión guardado en localStorage (accesible por XSS); usá cookies con Secure, HttpOnly y SameSite..
- Detalle: Control 10 (ALTO): token de sesión guardado en localStorage (accesible por XSS); usá cookies con Secure, HttpOnly y SameSite.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en archivo de pruebas internas, asociado al Control 1: Gestión de Identidades, Credenciales y Autenticación.
- Clasificación: CWE-522.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [33] Detected possible hardcoded credentials or secret in source code. — backend/bench/examples/juice-shop-sample/insecurity.py:4

- Hallazgo 33 — severidad alta — backend/bench/examples/juice-shop-sample/insecurity.py:4.
- ¿Qué es? Detected possible hardcoded credentials or secret in source code..
- Detalle: Detected possible hardcoded credentials or secret in source code.
- ¿Por qué tiene esta severidad? Severidad high: secreto o credencial expuesta en archivo de pruebas internas, asociado al Control 1: Gestión de Identidades, Credenciales y Autenticación.
- Clasificación: CWE-798.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [34] Detected potential OS command injection via unvalidated system execution. — backend/bench/examples/juice-shop-sample/updater.py:6

- Hallazgo 34 — severidad alta — backend/bench/examples/juice-shop-sample/updater.py:6.
- ¿Qué es? Detected potential OS command injection via unvalidated system execution..
- Detalle: Detected potential OS command injection via unvalidated system execution.
- ¿Por qué tiene esta severidad? Severidad high: inyección crítica o ejecución remota de comandos en archivo de pruebas internas, asociado al Control 4: Validación y Sanitización de Entradas e Inyecciones.
- Clasificación: CWE-78.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [35] Detected potential reflected cross-site scripting (XSS). — backend/bench/examples/owasp-web-bench/app.py:11

- Hallazgo 35 — severidad alta — backend/bench/examples/owasp-web-bench/app.py:11.
- ¿Qué es? Detected potential reflected cross-site scripting (XSS)..
- Detalle: Detected potential reflected cross-site scripting (XSS).
- ¿Por qué tiene esta severidad? Severidad high: vulnerabilidad de acceso o inyección en aplicación en archivo de pruebas internas, asociado al Control 4: Validación y Sanitización de Entradas e Inyecciones.
- Clasificación: CWE-79.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [36] Detected potential path traversal vulnerability in file access. — backend/bench/examples/owasp-web-bench/app.py:17

- Hallazgo 36 — severidad media — backend/bench/examples/owasp-web-bench/app.py:17.
- ¿Qué es? Detected potential path traversal vulnerability in file access..
- Detalle: Detected potential path traversal vulnerability in file access.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad de acceso o inyección en aplicación en archivo de pruebas internas, asociado al Control 2: Control de Acceso y Autorización.
- Clasificación: CWE-22.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [37] Detected unsafe deserialization of untrusted input. — backend/bench/examples/owasp-web-bench/app.py:24

- Hallazgo 37 — severidad media — backend/bench/examples/owasp-web-bench/app.py:24.
- ¿Qué es? Detected unsafe deserialization of untrusted input..
- Detalle: Detected unsafe deserialization of untrusted input.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad de acceso o inyección en aplicación en archivo de pruebas internas, asociado al Control 8: Integridad de Software y Deserialización Segura.
- Clasificación: CWE-502.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [38] Detected possible hardcoded credentials or secret in source code. — backend/bench/examples/owasp-web-bench/app.py:28

- Hallazgo 38 — severidad alta — backend/bench/examples/owasp-web-bench/app.py:28.
- ¿Qué es? Detected possible hardcoded credentials or secret in source code..
- Detalle: Detected possible hardcoded credentials or secret in source code.
- ¿Por qué tiene esta severidad? Severidad high: secreto o credencial expuesta en archivo de pruebas internas, asociado al Control 1: Gestión de Identidades, Credenciales y Autenticación.
- Clasificación: CWE-798.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [39] Detected potential OS command injection via unvalidated system execution. — backend/bench/examples/tiny-vuln-app/app.py:8

- Hallazgo 39 — severidad alta — backend/bench/examples/tiny-vuln-app/app.py:8.
- ¿Qué es? Detected potential OS command injection via unvalidated system execution..
- Detalle: Detected potential OS command injection via unvalidated system execution.
- ¿Por qué tiene esta severidad? Severidad high: inyección crítica o ejecución remota de comandos en archivo de pruebas internas, asociado al Control 4: Validación y Sanitización de Entradas e Inyecciones.
- Clasificación: CWE-78.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [40] Detected SQL injection risk: dynamic SQL query constructed via concatenation. — backend/bench/examples/tiny-vuln-app/app.py:14

- Hallazgo 40 — severidad alta — backend/bench/examples/tiny-vuln-app/app.py:14.
- ¿Qué es? Detected SQL injection risk: dynamic SQL query constructed via concatenation..
- Detalle: Detected SQL injection risk: dynamic SQL query constructed via concatenation.
- ¿Por qué tiene esta severidad? Severidad high: inyección crítica o ejecución remota de comandos en archivo de pruebas internas, asociado al Control 4: Validación y Sanitización de Entradas e Inyecciones.
- Clasificación: CWE-89.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [41] Detected arbitrary code execution via eval() or exec(). — backend/bench/examples/tiny-vuln-app/app.py:20

- Hallazgo 41 — severidad alta — backend/bench/examples/tiny-vuln-app/app.py:20.
- ¿Qué es? Detected arbitrary code execution via eval() or exec()..
- Detalle: Detected arbitrary code execution via eval() or exec().
- ¿Por qué tiene esta severidad? Severidad high: inyección crítica o ejecución remota de comandos en archivo de pruebas internas, asociado al Control 4: Validación y Sanitización de Entradas e Inyecciones.
- Clasificación: CWE-94.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [42] Detected possible hardcoded credentials or secret in source code. — backend/bench/examples/tiny-vuln-app/app.py:26

- Hallazgo 42 — severidad alta — backend/bench/examples/tiny-vuln-app/app.py:26.
- ¿Qué es? Detected possible hardcoded credentials or secret in source code..
- Detalle: Detected possible hardcoded credentials or secret in source code.
- ¿Por qué tiene esta severidad? Severidad high: secreto o credencial expuesta en archivo de pruebas internas, asociado al Control 1: Gestión de Identidades, Credenciales y Autenticación.
- Clasificación: CWE-798.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [43] Detected broken or weak cryptographic hash function (MD5/SHA1). — backend/bench/examples/tiny-vuln-app/app.py:27

- Hallazgo 43 — severidad media — backend/bench/examples/tiny-vuln-app/app.py:27.
- ¿Qué es? Detected broken or weak cryptographic hash function (MD5/SHA1)..
- Detalle: Detected broken or weak cryptographic hash function (MD5/SHA1).
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en archivo de pruebas internas, asociado al Control 3: Protección Criptográfica de Datos en Tránsito y Reposo.
- Clasificación: CWE-327.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [44] Detected possible hardcoded credentials or secret in source code. — backend/bench/examples/tiny-vuln-app/app.py:32

- Hallazgo 44 — severidad alta — backend/bench/examples/tiny-vuln-app/app.py:32.
- ¿Qué es? Detected possible hardcoded credentials or secret in source code..
- Detalle: Detected possible hardcoded credentials or secret in source code.
- ¿Por qué tiene esta severidad? Severidad high: secreto o credencial expuesta en archivo de pruebas internas, asociado al Control 1: Gestión de Identidades, Credenciales y Autenticación.
- Clasificación: CWE-798.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [45] C4 (SSRF): petición del servidor a una URL variable (webhook/scraping) sin allowlist visible; restringí destinos con allowlist, bloqueá IPs privadas y la metadata service (IMDSv2). — backend/proxy/server.py:219

- Hallazgo 45 — severidad alta — backend/proxy/server.py:219.
- ¿Qué es? C4 (SSRF): petición del servidor a una URL variable (webhook/scraping) sin allowlist visible; restringí destinos con allowlist, bloqueá IPs privadas y la metadata service (IMDSv2)..
- Detalle: C4 (SSRF): petición del servidor a una URL variable (webhook/scraping) sin allowlist visible; restringí destinos con allowlist, bloqueá IPs privadas y la metadata service (IMDSv2).
- ¿Por qué tiene esta severidad? Severidad high: vulnerabilidad en código en ruta HTTP o controlador expuesto, asociado al Control 9: Protección contra Solicitudes Falsificadas y SSRF.
- Clasificación: CWE-918.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [46] Control 1 (CRÍTICO): cors({origin: true, credentials: true}) refleja cualquier origen y permite credenciales; usá una lista explícita de orígenes. — backend/rules/semgrep/control-01-cors/rule.js:6

- Hallazgo 46 — severidad media — backend/rules/semgrep/control-01-cors/rule.js:6.
- ¿Qué es? Control 1 (CRÍTICO): cors({origin: true, credentials: true}) refleja cualquier origen y permite credenciales; usá una lista explícita de orígenes..
- Detalle: Control 1 (CRÍTICO): cors({origin: true, credentials: true}) refleja cualquier origen y permite credenciales; usá una lista explícita de orígenes.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en código base, asociado al Control 5: Configuración Segura de Infraestructura y Contenedores.
- Clasificación: CWE-942.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [47] Control 1 (CRÍTICO): CORS con allow_origins=['*'] y allow_credentials=True permite que cualquier origen lea respuestas autenticadas. Definí una lista explícita de orígenes confiables. — backend/rules/semgrep/control-01-cors/rule.py:6

- Hallazgo 47 — severidad media — backend/rules/semgrep/control-01-cors/rule.py:6.
- ¿Qué es? Control 1 (CRÍTICO): CORS con allow_origins=['*'] y allow_credentials=True permite que cualquier origen lea respuestas autenticadas. Definí una lista explícita de orígenes confiables..
- Detalle: Control 1 (CRÍTICO): CORS con allow_origins=['*'] y allow_credentials=True permite que cualquier origen lea respuestas autenticadas. Definí una lista explícita de orígenes confiables.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en código base, asociado al Control 5: Configuración Segura de Infraestructura y Contenedores.
- Clasificación: CWE-942.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [48] Control 1 (CRÍTICO): allow_methods=['*'] y allow_headers=['*'] amplían la superficie CORS sin necesidad; restringilos a lo que la API usa. — backend/rules/semgrep/control-01-cors/rule.py:15

- Hallazgo 48 — severidad media — backend/rules/semgrep/control-01-cors/rule.py:15.
- ¿Qué es? Control 1 (CRÍTICO): allow_methods=['*'] y allow_headers=['*'] amplían la superficie CORS sin necesidad; restringilos a lo que la API usa..
- Detalle: Control 1 (CRÍTICO): allow_methods=['*'] y allow_headers=['*'] amplían la superficie CORS sin necesidad; restringilos a lo que la API usa.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en código base, asociado al Control 5: Configuración Segura de Infraestructura y Contenedores.
- Clasificación: CWE-942.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [49] Control 1 (CRÍTICO): CORS_ALLOW_ALL_ORIGINS = True acepta cualquier origen; reemplazalo por una lista explícita de orígenes confiables. — backend/rules/semgrep/control-01-cors/rule.py:23

- Hallazgo 49 — severidad media — backend/rules/semgrep/control-01-cors/rule.py:23.
- ¿Qué es? Control 1 (CRÍTICO): CORS_ALLOW_ALL_ORIGINS = True acepta cualquier origen; reemplazalo por una lista explícita de orígenes confiables..
- Detalle: Control 1 (CRÍTICO): CORS_ALLOW_ALL_ORIGINS = True acepta cualquier origen; reemplazalo por una lista explícita de orígenes confiables.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en código base, asociado al Control 5: Configuración Segura de Infraestructura y Contenedores.
- Clasificación: CWE-942.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [50] Control 2 (MEDIO): HTML crudo con dangerouslySetInnerHTML sin sanitizar (DOMPurify) permite XSS con datos del usuario. — backend/rules/semgrep/control-02-escape/rule.jsx:6

- Hallazgo 50 — severidad crítica — backend/rules/semgrep/control-02-escape/rule.jsx:6.
- ¿Qué es? Control 2 (MEDIO): HTML crudo con dangerouslySetInnerHTML sin sanitizar (DOMPurify) permite XSS con datos del usuario..
- Detalle: Control 2 (MEDIO): HTML crudo con dangerouslySetInnerHTML sin sanitizar (DOMPurify) permite XSS con datos del usuario.
- ¿Por qué tiene esta severidad? Severidad critical: vulnerabilidad de acceso o inyección en aplicación en código base, asociado al Control 4: Validación y Sanitización de Entradas e Inyecciones.
- Clasificación: CWE-79.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [51] Control 2 (MEDIO): HTML crudo con dangerouslySetInnerHTML sin sanitizar (DOMPurify) permite XSS con datos del usuario. — backend/rules/semgrep/control-02-escape/rule.jsx:11

- Hallazgo 51 — severidad crítica — backend/rules/semgrep/control-02-escape/rule.jsx:11.
- ¿Qué es? Control 2 (MEDIO): HTML crudo con dangerouslySetInnerHTML sin sanitizar (DOMPurify) permite XSS con datos del usuario..
- Detalle: Control 2 (MEDIO): HTML crudo con dangerouslySetInnerHTML sin sanitizar (DOMPurify) permite XSS con datos del usuario.
- ¿Por qué tiene esta severidad? Severidad critical: vulnerabilidad de acceso o inyección en aplicación en código base, asociado al Control 4: Validación y Sanitización de Entradas e Inyecciones.
- Clasificación: CWE-79.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [52] Control 2 (MEDIO): consulta SQL con template literal interpolado; usá consultas parametrizadas. — backend/rules/semgrep/control-02-escape/rule.jsx:16

- Hallazgo 52 — severidad crítica — backend/rules/semgrep/control-02-escape/rule.jsx:16.
- ¿Qué es? Control 2 (MEDIO): consulta SQL con template literal interpolado; usá consultas parametrizadas..
- Detalle: Control 2 (MEDIO): consulta SQL con template literal interpolado; usá consultas parametrizadas.
- ¿Por qué tiene esta severidad? Severidad critical: inyección crítica o ejecución remota de comandos en código base, asociado al Control 4: Validación y Sanitización de Entradas e Inyecciones.
- Clasificación: CWE-89.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [53] Control 2 (MEDIO): bypassSecurityTrust* marca contenido como confiable y desactiva la sanitización de Angular. — backend/rules/semgrep/control-02-escape/rule.jsx:23

- Hallazgo 53 — severidad crítica — backend/rules/semgrep/control-02-escape/rule.jsx:23.
- ¿Qué es? Control 2 (MEDIO): bypassSecurityTrust* marca contenido como confiable y desactiva la sanitización de Angular..
- Detalle: Control 2 (MEDIO): bypassSecurityTrust* marca contenido como confiable y desactiva la sanitización de Angular.
- ¿Por qué tiene esta severidad? Severidad critical: vulnerabilidad de acceso o inyección en aplicación en código base, asociado al Control 4: Validación y Sanitización de Entradas e Inyecciones.
- Clasificación: CWE-79.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [54] Detected SQL injection risk: dynamic SQL query constructed via concatenation. — backend/rules/semgrep/control-02-escape/rule.py:5

- Hallazgo 54 — severidad crítica — backend/rules/semgrep/control-02-escape/rule.py:5.
- ¿Qué es? Detected SQL injection risk: dynamic SQL query constructed via concatenation..
- Detalle: Detected SQL injection risk: dynamic SQL query constructed via concatenation.
- ¿Por qué tiene esta severidad? Severidad critical: inyección crítica o ejecución remota de comandos en código base, asociado al Control 4: Validación y Sanitización de Entradas e Inyecciones.
- Clasificación: CWE-89.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [55] Control 2 (MEDIO): HTMLResponse construida con f-string interpola datos sin escapar; sanitizá el contenido antes de renderizarlo. — backend/rules/semgrep/control-02-escape/rule.py:8

- Hallazgo 55 — severidad crítica — backend/rules/semgrep/control-02-escape/rule.py:8.
- ¿Qué es? Control 2 (MEDIO): HTMLResponse construida con f-string interpola datos sin escapar; sanitizá el contenido antes de renderizarlo..
- Detalle: Control 2 (MEDIO): HTMLResponse construida con f-string interpola datos sin escapar; sanitizá el contenido antes de renderizarlo.
- ¿Por qué tiene esta severidad? Severidad critical: vulnerabilidad de acceso o inyección en aplicación en código base, asociado al Control 4: Validación y Sanitización de Entradas e Inyecciones.
- Clasificación: CWE-79.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [56] Control 2 (MEDIO): v-html renderiza HTML crudo; sanitizá con DOMPurify antes de asignarlo. — backend/rules/semgrep/control-02-escape/rule.py:11

- Hallazgo 56 — severidad crítica — backend/rules/semgrep/control-02-escape/rule.py:11.
- ¿Qué es? Control 2 (MEDIO): v-html renderiza HTML crudo; sanitizá con DOMPurify antes de asignarlo..
- Detalle: Control 2 (MEDIO): v-html renderiza HTML crudo; sanitizá con DOMPurify antes de asignarlo.
- ¿Por qué tiene esta severidad? Severidad critical: vulnerabilidad de acceso o inyección en aplicación en código base, asociado al Control 4: Validación y Sanitización de Entradas e Inyecciones.
- Clasificación: CWE-79.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [57] Control 2 (MEDIO): v-html renderiza HTML crudo; sanitizá con DOMPurify antes de asignarlo. — backend/rules/semgrep/control-02-escape/rule.yml:28

- Hallazgo 57 — severidad crítica — backend/rules/semgrep/control-02-escape/rule.yml:28.
- ¿Qué es? Control 2 (MEDIO): v-html renderiza HTML crudo; sanitizá con DOMPurify antes de asignarlo..
- Detalle: Control 2 (MEDIO): v-html renderiza HTML crudo; sanitizá con DOMPurify antes de asignarlo.
- ¿Por qué tiene esta severidad? Severidad critical: vulnerabilidad de acceso o inyección en aplicación en código base, asociado al Control 4: Validación y Sanitización de Entradas e Inyecciones.
- Clasificación: CWE-79.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [58] Control 3 (CRÍTICO): el manejador de errores responde con err.stack/err.message; devolvé un mensaje genérico en producción y el detalle solo a logs. — backend/rules/semgrep/control-03-errores-debug/rule.js:3

- Hallazgo 58 — severidad media — backend/rules/semgrep/control-03-errores-debug/rule.js:3.
- ¿Qué es? Control 3 (CRÍTICO): el manejador de errores responde con err.stack/err.message; devolvé un mensaje genérico en producción y el detalle solo a logs..
- Detalle: Control 3 (CRÍTICO): el manejador de errores responde con err.stack/err.message; devolvé un mensaje genérico en producción y el detalle solo a logs.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en código base.
- Clasificación: CWE-209.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [59] Control 3 (CRÍTICO): DEBUG = True en producción expone stack traces, rutas internas y configuración; desactivá el modo debug. — backend/rules/semgrep/control-03-errores-debug/rule.py:2

- Hallazgo 59 — severidad media — backend/rules/semgrep/control-03-errores-debug/rule.py:2.
- ¿Qué es? Control 3 (CRÍTICO): DEBUG = True en producción expone stack traces, rutas internas y configuración; desactivá el modo debug..
- Detalle: Control 3 (CRÍTICO): DEBUG = True en producción expone stack traces, rutas internas y configuración; desactivá el modo debug.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en código base, asociado al Control 5: Configuración Segura de Infraestructura y Contenedores.
- Clasificación: CWE-489.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: verified.

### [60] Running flask app with host 0.0.0.0 could expose the server publicly. — backend/rules/semgrep/control-03-errores-debug/rule.py:3

- Hallazgo 60 — severidad alta — backend/rules/semgrep/control-03-errores-debug/rule.py:3.
- ¿Qué es? Running flask app with host 0.0.0.0 could expose the server publicly..
- Detalle: Running flask app with host 0.0.0.0 could expose the server publicly.
- ¿Por qué tiene esta severidad? Severidad high: vulnerabilidad en código en código base, asociado al Control 2: Control de Acceso y Autorización.
- Clasificación: CWE-668.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: verified.

### [61] Control 3 (CRÍTICO): la respuesta incluye el detalle de la excepción (str(exc)/traceback); devolvé un mensaje genérico con ID de correlación y logueá el detalle internamente. — backend/rules/semgrep/control-03-errores-debug/rule.py:10

- Hallazgo 61 — severidad media — backend/rules/semgrep/control-03-errores-debug/rule.py:10.
- ¿Qué es? Control 3 (CRÍTICO): la respuesta incluye el detalle de la excepción (str(exc)/traceback); devolvé un mensaje genérico con ID de correlación y logueá el detalle internamente..
- Detalle: Control 3 (CRÍTICO): la respuesta incluye el detalle de la excepción (str(exc)/traceback); devolvé un mensaje genérico con ID de correlación y logueá el detalle internamente.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en código base.
- Clasificación: CWE-209.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: verified.

### [62] Running flask app with host 0.0.0.0 could expose the server publicly. — backend/rules/semgrep/control-03-errores-debug/rule.py:15

- Hallazgo 62 — severidad alta — backend/rules/semgrep/control-03-errores-debug/rule.py:15.
- ¿Qué es? Running flask app with host 0.0.0.0 could expose the server publicly..
- Detalle: Running flask app with host 0.0.0.0 could expose the server publicly.
- ¿Por qué tiene esta severidad? Severidad high: vulnerabilidad en código en código base, asociado al Control 2: Control de Acceso y Autorización.
- Clasificación: CWE-668.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: verified.

### [63] Control 7 (ALTO): endpoint costoso sin decorador/dependencia de rate limiting; agregá límites por IP y por usuario según el costo del endpoint. — backend/rules/semgrep/control-07-ratelimit/rule.py:7

- Hallazgo 63 — severidad media — backend/rules/semgrep/control-07-ratelimit/rule.py:7.
- ¿Qué es? Control 7 (ALTO): endpoint costoso sin decorador/dependencia de rate limiting; agregá límites por IP y por usuario según el costo del endpoint..
- Detalle: Control 7 (ALTO): endpoint costoso sin decorador/dependencia de rate limiting; agregá límites por IP y por usuario según el costo del endpoint.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en código base.
- Clasificación: CWE-770.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [64] Control 7 (ALTO): endpoint costoso sin decorador/dependencia de rate limiting; agregá límites por IP y por usuario según el costo del endpoint. — backend/rules/semgrep/control-07-ratelimit/rule.py:12

- Hallazgo 64 — severidad media — backend/rules/semgrep/control-07-ratelimit/rule.py:12.
- ¿Qué es? Control 7 (ALTO): endpoint costoso sin decorador/dependencia de rate limiting; agregá límites por IP y por usuario según el costo del endpoint..
- Detalle: Control 7 (ALTO): endpoint costoso sin decorador/dependencia de rate limiting; agregá límites por IP y por usuario según el costo del endpoint.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en código base.
- Clasificación: CWE-770.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [65] Control 10 (ALTO): token de sesión guardado en localStorage (accesible por XSS); usá cookies con Secure, HttpOnly y SameSite. — backend/rules/semgrep/control-10-cookies/rule.js:2

- Hallazgo 65 — severidad alta — backend/rules/semgrep/control-10-cookies/rule.js:2.
- ¿Qué es? Control 10 (ALTO): token de sesión guardado en localStorage (accesible por XSS); usá cookies con Secure, HttpOnly y SameSite..
- Detalle: Control 10 (ALTO): token de sesión guardado en localStorage (accesible por XSS); usá cookies con Secure, HttpOnly y SameSite.
- ¿Por qué tiene esta severidad? Severidad high: vulnerabilidad en código en código base, asociado al Control 1: Gestión de Identidades, Credenciales y Autenticación.
- Clasificación: CWE-522.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [66] Control 10 (ALTO): cookie de sesión escrita con document.cookie sin control de flags; manejá la sesión desde el backend con Secure/HttpOnly/SameSite. — backend/rules/semgrep/control-10-cookies/rule.js:3

- Hallazgo 66 — severidad media — backend/rules/semgrep/control-10-cookies/rule.js:3.
- ¿Qué es? Control 10 (ALTO): cookie de sesión escrita con document.cookie sin control de flags; manejá la sesión desde el backend con Secure/HttpOnly/SameSite..
- Detalle: Control 10 (ALTO): cookie de sesión escrita con document.cookie sin control de flags; manejá la sesión desde el backend con Secure/HttpOnly/SameSite.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en código base, asociado al Control 5: Configuración Segura de Infraestructura y Contenedores.
- Clasificación: CWE-1004.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [67] Control 10 (ALTO): cookie de sesión con flag de seguridad desactivado (secure=False / httponly=False / samesite='None'); usá Secure, HttpOnly y SameSite Strict o Lax. — backend/rules/semgrep/control-10-cookies/rule.py:2

- Hallazgo 67 — severidad media — backend/rules/semgrep/control-10-cookies/rule.py:2.
- ¿Qué es? Control 10 (ALTO): cookie de sesión con flag de seguridad desactivado (secure=False / httponly=False / samesite='None'); usá Secure, HttpOnly y SameSite Strict o Lax..
- Detalle: Control 10 (ALTO): cookie de sesión con flag de seguridad desactivado (secure=False / httponly=False / samesite='None'); usá Secure, HttpOnly y SameSite Strict o Lax.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en código base, asociado al Control 5: Configuración Segura de Infraestructura y Contenedores.
- Clasificación: CWE-1004.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [68] Control 11 (ALTO): JWT firmado con expiración de días o semanas; el inventario exige 15-30 minutos. — backend/rules/semgrep/control-11-jwt/rule.js:5

- Hallazgo 68 — severidad alta — backend/rules/semgrep/control-11-jwt/rule.js:5.
- ¿Qué es? Control 11 (ALTO): JWT firmado con expiración de días o semanas; el inventario exige 15-30 minutos..
- Detalle: Control 11 (ALTO): JWT firmado con expiración de días o semanas; el inventario exige 15-30 minutos.
- ¿Por qué tiene esta severidad? Severidad high: vulnerabilidad en código en código base, asociado al Control 1: Gestión de Identidades, Credenciales y Autenticación.
- Clasificación: CWE-613.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [69] Control 11 (ALTO): jwt.decode sin verificación de firma; usá jwt.verify con key, audience e issuer. — backend/rules/semgrep/control-11-jwt/rule.js:9

- Hallazgo 69 — severidad alta — backend/rules/semgrep/control-11-jwt/rule.js:9.
- ¿Qué es? Control 11 (ALTO): jwt.decode sin verificación de firma; usá jwt.verify con key, audience e issuer..
- Detalle: Control 11 (ALTO): jwt.decode sin verificación de firma; usá jwt.verify con key, audience e issuer.
- ¿Por qué tiene esta severidad? Severidad high: vulnerabilidad en código en código base, asociado al Control 1: Gestión de Identidades, Credenciales y Autenticación.
- Clasificación: CWE-347.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [70] Control 11 (ALTO): JWT con expiración de horas o días; el inventario exige access tokens de 15-30 minutos con rotación de refresh tokens. — backend/rules/semgrep/control-11-jwt/rule.py:7

- Hallazgo 70 — severidad alta — backend/rules/semgrep/control-11-jwt/rule.py:7.
- ¿Qué es? Control 11 (ALTO): JWT con expiración de horas o días; el inventario exige access tokens de 15-30 minutos con rotación de refresh tokens..
- Detalle: Control 11 (ALTO): JWT con expiración de horas o días; el inventario exige access tokens de 15-30 minutos con rotación de refresh tokens.
- ¿Por qué tiene esta severidad? Severidad high: vulnerabilidad en código en código base, asociado al Control 1: Gestión de Identidades, Credenciales y Autenticación.
- Clasificación: CWE-613.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [71] Control 11 (ALTO): JWT con expiración de horas o días; el inventario exige access tokens de 15-30 minutos con rotación de refresh tokens. — backend/rules/semgrep/control-11-jwt/rule.py:15

- Hallazgo 71 — severidad alta — backend/rules/semgrep/control-11-jwt/rule.py:15.
- ¿Qué es? Control 11 (ALTO): JWT con expiración de horas o días; el inventario exige access tokens de 15-30 minutos con rotación de refresh tokens..
- Detalle: Control 11 (ALTO): JWT con expiración de horas o días; el inventario exige access tokens de 15-30 minutos con rotación de refresh tokens.
- ¿Por qué tiene esta severidad? Severidad high: vulnerabilidad en código en código base, asociado al Control 1: Gestión de Identidades, Credenciales y Autenticación.
- Clasificación: CWE-613.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [72] Control 11 (ALTO): el token se decodifica sin validar firma (verify_signature=False o alg=none); validá firma, exp, aud e iss. — backend/rules/semgrep/control-11-jwt/rule.py:22

- Hallazgo 72 — severidad alta — backend/rules/semgrep/control-11-jwt/rule.py:22.
- ¿Qué es? Control 11 (ALTO): el token se decodifica sin validar firma (verify_signature=False o alg=none); validá firma, exp, aud e iss..
- Detalle: Control 11 (ALTO): el token se decodifica sin validar firma (verify_signature=False o alg=none); validá firma, exp, aud e iss.
- ¿Por qué tiene esta severidad? Severidad high: vulnerabilidad en código en código base, asociado al Control 1: Gestión de Identidades, Credenciales y Autenticación.
- Clasificación: CWE-347.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [73] Detected JWT token decoded with 'verify=False'. This bypasses any integrity checks for the token which means the token could be tampered with by malicious actors. Ensure that the JWT token is verified. — backend/rules/semgrep/control-11-jwt/rule.py:23

- Hallazgo 73 — severidad alta — backend/rules/semgrep/control-11-jwt/rule.py:23.
- ¿Qué es? Detected JWT token decoded with 'verify=False'. This bypasses any integrity checks for the token which means the token could be tampered with by malicious actors. Ensure that the JWT token is verified..
- Detalle: Detected JWT token decoded with 'verify=False'. This bypasses any integrity checks for the token which means the token could be tampered with by malicious actors. Ensure that the JWT token is verified.
- ¿Por qué tiene esta severidad? Severidad high: vulnerabilidad en código en código base, asociado al Control 1: Gestión de Identidades, Credenciales y Autenticación.
- Clasificación: CWE-287.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [74] Detected use of the 'none' algorithm in a JWT token. The 'none' algorithm assumes the integrity of the token has already been verified. This would allow a malicious actor to forge a JWT token that will automatically be verified. Do not explicitly use the 'none' algorithm. Instead, use an algorithm such as 'HS256'. — backend/rules/semgrep/control-11-jwt/rule.py:24

- Hallazgo 74 — severidad alta — backend/rules/semgrep/control-11-jwt/rule.py:24.
- ¿Qué es? Detected use of the 'none' algorithm in a JWT token. The 'none' algorithm assumes the integrity of the token has already been verified. This would allow a malicious actor to forge a JWT token that will automatically be verified. Do not explicitly use the 'none' algorithm. Instead, use an algorithm such as 'HS256'..
- Detalle: Detected use of the 'none' algorithm in a JWT token. The 'none' algorithm assumes the integrity of the token has already been verified. This would allow a malicious actor to forge a JWT token that will automatically be verified. Do not explicitly use the 'none' algorithm. Instead, use an algorithm such as 'HS256'.
- ¿Por qué tiene esta severidad? Severidad high: vulnerabilidad en código en código base, asociado al Control 3: Protección Criptográfica de Datos en Tránsito y Reposo.
- Clasificación: CWE-327.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [75] Control 11 (ALTO): jwt.decode sin validación de audience/issuer; validá aud e iss además de firma y exp. — backend/rules/semgrep/control-11-jwt/rule.py:30

- Hallazgo 75 — severidad alta — backend/rules/semgrep/control-11-jwt/rule.py:30.
- ¿Qué es? Control 11 (ALTO): jwt.decode sin validación de audience/issuer; validá aud e iss además de firma y exp..
- Detalle: Control 11 (ALTO): jwt.decode sin validación de audience/issuer; validá aud e iss además de firma y exp.
- ¿Por qué tiene esta severidad? Severidad high: vulnerabilidad en código en código base, asociado al Control 1: Gestión de Identidades, Credenciales y Autenticación.
- Clasificación: CWE-287.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [76] C13: llamada a modelo sin max_tokens en el request; definí límites por request/usuario y alertas de facturación. — backend/rules/semgrep/control-c13-llm-tokens/rule.js:3

- Hallazgo 76 — severidad media — backend/rules/semgrep/control-c13-llm-tokens/rule.js:3.
- ¿Qué es? C13: llamada a modelo sin max_tokens en el request; definí límites por request/usuario y alertas de facturación..
- Detalle: C13: llamada a modelo sin max_tokens en el request; definí límites por request/usuario y alertas de facturación.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en código base.
- Clasificación: CWE-770.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [77] C13: llamada a modelo sin max_tokens/max_completion_tokens; definí límite de tokens por request, presupuesto por usuario y alertas de costo. — backend/rules/semgrep/control-c13-llm-tokens/rule.py:7

- Hallazgo 77 — severidad media — backend/rules/semgrep/control-c13-llm-tokens/rule.py:7.
- ¿Qué es? C13: llamada a modelo sin max_tokens/max_completion_tokens; definí límite de tokens por request, presupuesto por usuario y alertas de costo..
- Detalle: C13: llamada a modelo sin max_tokens/max_completion_tokens; definí límite de tokens por request, presupuesto por usuario y alertas de costo.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en código base.
- Clasificación: CWE-770.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [78] C13: generate_content sin generation_config con max_output_tokens; definí límite de tokens por request y presupuesto. — backend/rules/semgrep/control-c13-llm-tokens/rule.py:13

- Hallazgo 78 — severidad media — backend/rules/semgrep/control-c13-llm-tokens/rule.py:13.
- ¿Qué es? C13: generate_content sin generation_config con max_output_tokens; definí límite de tokens por request y presupuesto..
- Detalle: C13: generate_content sin generation_config con max_output_tokens; definí límite de tokens por request y presupuesto.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en código base.
- Clasificación: CWE-770.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [79] C4 (SSRF): fetch/axios del servidor hacia una URL variable (webhook) sin allowlist; bloqueá IPs privadas y 169.254.169.254. — backend/rules/semgrep/control-c4-ssrf/rule.js:5

- Hallazgo 79 — severidad alta — backend/rules/semgrep/control-c4-ssrf/rule.js:5.
- ¿Qué es? C4 (SSRF): fetch/axios del servidor hacia una URL variable (webhook) sin allowlist; bloqueá IPs privadas y 169.254.169.254..
- Detalle: C4 (SSRF): fetch/axios del servidor hacia una URL variable (webhook) sin allowlist; bloqueá IPs privadas y 169.254.169.254.
- ¿Por qué tiene esta severidad? Severidad high: vulnerabilidad en código en código base, asociado al Control 9: Protección contra Solicitudes Falsificadas y SSRF.
- Clasificación: CWE-918.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [80] C4 (SSRF): fetch/axios del servidor hacia una URL variable (webhook) sin allowlist; bloqueá IPs privadas y 169.254.169.254. — backend/rules/semgrep/control-c4-ssrf/rule.js:9

- Hallazgo 80 — severidad alta — backend/rules/semgrep/control-c4-ssrf/rule.js:9.
- ¿Qué es? C4 (SSRF): fetch/axios del servidor hacia una URL variable (webhook) sin allowlist; bloqueá IPs privadas y 169.254.169.254..
- Detalle: C4 (SSRF): fetch/axios del servidor hacia una URL variable (webhook) sin allowlist; bloqueá IPs privadas y 169.254.169.254.
- ¿Por qué tiene esta severidad? Severidad high: vulnerabilidad en código en código base, asociado al Control 9: Protección contra Solicitudes Falsificadas y SSRF.
- Clasificación: CWE-918.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [81] C4 (SSRF): fetch/axios del servidor hacia una URL variable (webhook) sin allowlist; bloqueá IPs privadas y 169.254.169.254. — backend/rules/semgrep/control-c4-ssrf/rule.js:12

- Hallazgo 81 — severidad alta — backend/rules/semgrep/control-c4-ssrf/rule.js:12.
- ¿Qué es? C4 (SSRF): fetch/axios del servidor hacia una URL variable (webhook) sin allowlist; bloqueá IPs privadas y 169.254.169.254..
- Detalle: C4 (SSRF): fetch/axios del servidor hacia una URL variable (webhook) sin allowlist; bloqueá IPs privadas y 169.254.169.254.
- ¿Por qué tiene esta severidad? Severidad high: vulnerabilidad en código en código base, asociado al Control 9: Protección contra Solicitudes Falsificadas y SSRF.
- Clasificación: CWE-918.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [82] C4 (SSRF): petición del servidor a una URL variable (webhook/scraping) sin allowlist visible; restringí destinos con allowlist, bloqueá IPs privadas y la metadata service (IMDSv2). — backend/rules/semgrep/control-c4-ssrf/rule.py:8

- Hallazgo 82 — severidad alta — backend/rules/semgrep/control-c4-ssrf/rule.py:8.
- ¿Qué es? C4 (SSRF): petición del servidor a una URL variable (webhook/scraping) sin allowlist visible; restringí destinos con allowlist, bloqueá IPs privadas y la metadata service (IMDSv2)..
- Detalle: C4 (SSRF): petición del servidor a una URL variable (webhook/scraping) sin allowlist visible; restringí destinos con allowlist, bloqueá IPs privadas y la metadata service (IMDSv2).
- ¿Por qué tiene esta severidad? Severidad high: vulnerabilidad en código en código base, asociado al Control 9: Protección contra Solicitudes Falsificadas y SSRF.
- Clasificación: CWE-918.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [83] C4 (SSRF): petición del servidor a una URL variable (webhook/scraping) sin allowlist visible; restringí destinos con allowlist, bloqueá IPs privadas y la metadata service (IMDSv2). — backend/rules/semgrep/control-c4-ssrf/rule.py:11

- Hallazgo 83 — severidad alta — backend/rules/semgrep/control-c4-ssrf/rule.py:11.
- ¿Qué es? C4 (SSRF): petición del servidor a una URL variable (webhook/scraping) sin allowlist visible; restringí destinos con allowlist, bloqueá IPs privadas y la metadata service (IMDSv2)..
- Detalle: C4 (SSRF): petición del servidor a una URL variable (webhook/scraping) sin allowlist visible; restringí destinos con allowlist, bloqueá IPs privadas y la metadata service (IMDSv2).
- ¿Por qué tiene esta severidad? Severidad high: vulnerabilidad en código en código base, asociado al Control 9: Protección contra Solicitudes Falsificadas y SSRF.
- Clasificación: CWE-918.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [84] C7: console/logger registra variables sensibles (token/password/secret/authorization); scrubbeá antes de registrar. — backend/rules/semgrep/control-c7-logs/rule.js:5

- Hallazgo 84 — severidad media — backend/rules/semgrep/control-c7-logs/rule.js:5.
- ¿Qué es? C7: console/logger registra variables sensibles (token/password/secret/authorization); scrubbeá antes de registrar..
- Detalle: C7: console/logger registra variables sensibles (token/password/secret/authorization); scrubbeá antes de registrar.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en código base, asociado al Control 7: Registro y Monitoreo de Eventos de Seguridad.
- Clasificación: CWE-532.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [85] C7: console/logger registra variables sensibles (token/password/secret/authorization); scrubbeá antes de registrar. — backend/rules/semgrep/control-c7-logs/rule.js:9

- Hallazgo 85 — severidad media — backend/rules/semgrep/control-c7-logs/rule.js:9.
- ¿Qué es? C7: console/logger registra variables sensibles (token/password/secret/authorization); scrubbeá antes de registrar..
- Detalle: C7: console/logger registra variables sensibles (token/password/secret/authorization); scrubbeá antes de registrar.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en código base, asociado al Control 7: Registro y Monitoreo de Eventos de Seguridad.
- Clasificación: CWE-532.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [86] C7: registro de datos sensibles (token/contraseña/secret/authorization) en logs o trazas; scrubbeá el dato antes de loguearlo. — backend/rules/semgrep/control-c7-logs/rule.py:6

- Hallazgo 86 — severidad media — backend/rules/semgrep/control-c7-logs/rule.py:6.
- ¿Qué es? C7: registro de datos sensibles (token/contraseña/secret/authorization) en logs o trazas; scrubbeá el dato antes de loguearlo..
- Detalle: C7: registro de datos sensibles (token/contraseña/secret/authorization) en logs o trazas; scrubbeá el dato antes de loguearlo.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en código base, asociado al Control 7: Registro y Monitoreo de Eventos de Seguridad.
- Clasificación: CWE-532.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [87] C7: el mensaje de log formateado interpola un dato sensible (password=, token=...); eliminá el valor del log. — backend/rules/semgrep/control-c7-logs/rule.py:9

- Hallazgo 87 — severidad media — backend/rules/semgrep/control-c7-logs/rule.py:9.
- ¿Qué es? C7: el mensaje de log formateado interpola un dato sensible (password=, token=...); eliminá el valor del log..
- Detalle: C7: el mensaje de log formateado interpola un dato sensible (password=, token=...); eliminá el valor del log.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en código base, asociado al Control 7: Registro y Monitoreo de Eventos de Seguridad.
- Clasificación: CWE-532.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [88] Detected potential reflected cross-site scripting (XSS). — backend/triage_agent.py:529

- Hallazgo 88 — severidad crítica — backend/triage_agent.py:529.
- ¿Qué es? Detected potential reflected cross-site scripting (XSS)..
- Detalle: Detected potential reflected cross-site scripting (XSS).
- ¿Por qué tiene esta severidad? Severidad critical: vulnerabilidad de acceso o inyección en aplicación en código base, asociado al Control 4: Validación y Sanitización de Entradas e Inyecciones.
- Clasificación: CWE-79.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [89] By not specifying a USER, a program in the container may run as 'root'. This is a security hazard. If an attacker can control a process running as root, they may have control over the container. Ensure that the last USER in a Dockerfile is a USER other than 'root'. — frontend/Dockerfile:20

- Hallazgo 89 — severidad media — frontend/Dockerfile:20.
- ¿Qué es? By not specifying a USER, a program in the container may run as 'root'. This is a security hazard. If an attacker can control a process running as root, they may have control over the container. Ensure that the last USER in a Dockerfile is a USER other than 'root'..
- Detalle: By not specifying a USER, a program in the container may run as 'root'. This is a security hazard. If an attacker can control a process running as root, they may have control over the container. Ensure that the last USER in a Dockerfile is a USER other than 'root'.
- ¿Por qué tiene esta severidad? Severidad medium: vulnerabilidad en código en archivo de configuración de infraestructura, asociado al Control 5: Configuración Segura de Infraestructura y Contenedores.
- Clasificación: CWE-250.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [90] '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation. — frontend/nginx.conf:17

- Hallazgo 90 — severidad alta — frontend/nginx.conf:17.
- ¿Qué es? '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation..
- Detalle: '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.
- ¿Por qué tiene esta severidad? Severidad high: vulnerabilidad en código en código base, asociado al Control 1: Gestión de Identidades, Credenciales y Autenticación.
- Clasificación: CWE-290.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [91] '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation. — frontend/nginx.conf:30

- Hallazgo 91 — severidad alta — frontend/nginx.conf:30.
- ¿Qué es? '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation..
- Detalle: '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.
- ¿Por qué tiene esta severidad? Severidad high: vulnerabilidad en código en código base, asociado al Control 1: Gestión de Identidades, Credenciales y Autenticación.
- Clasificación: CWE-290.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [92] C4 (SSRF): fetch/axios del servidor hacia una URL variable (webhook) sin allowlist; bloqueá IPs privadas y 169.254.169.254. — frontend/src/api/client.js:21

- Hallazgo 92 — severidad alta — frontend/src/api/client.js:21.
- ¿Qué es? C4 (SSRF): fetch/axios del servidor hacia una URL variable (webhook) sin allowlist; bloqueá IPs privadas y 169.254.169.254..
- Detalle: C4 (SSRF): fetch/axios del servidor hacia una URL variable (webhook) sin allowlist; bloqueá IPs privadas y 169.254.169.254.
- ¿Por qué tiene esta severidad? Severidad high: vulnerabilidad en código en ruta HTTP o controlador expuesto, asociado al Control 9: Protección contra Solicitudes Falsificadas y SSRF.
- Clasificación: CWE-918.
- Cómo corregirlo: Review the finding and apply the secure coding guidance for this rule.
- Estado de remediación: open.

### [93] Dependabot no está configurado — .github/dependabot.yml

- Hallazgo 93 — severidad media — .github/dependabot.yml.
- ¿Qué es? Dependabot no está configurado.
- Detalle: El repositorio no configura Dependabot: las dependencias no reciben actualizaciones automáticas de seguridad.
- ¿Por qué tiene esta severidad? Severidad medium: dependencia vulnerable en archivo de configuración de infraestructura, asociado al Control 6: Gestión de Vulnerabilidades y Parcheo de Dependencias.
- Clasificación: CWE-1104.
- Cómo corregirlo: Agregá .github/dependabot.yml con un bloque 'package-ecosystem' y 'schedule' por cada gestor detectado.
- Estado de remediación: open.

## Guía de buenas prácticas (agente redactor)

> Cada sección proviene exclusivamente de hallazgos reales de este análisis.

### A03:2021 - Injection — 20 hallazgo(s)

- Review the finding and apply the secure coding guidance for this rule.

### A07:2021 - Identification and Authentication Failures — 13 hallazgo(s)

- Review the finding and apply the secure coding guidance for this rule.

### A02:2021 - Cryptographic Failures — 4 hallazgo(s)

- Review the finding and apply the secure coding guidance for this rule.

### A01:2021 - Broken Access Control — 4 hallazgo(s)

- Review the finding and apply the secure coding guidance for this rule.

### A07:2021 - Identification and Authentication Failures (CWE-613) — 7 hallazgo(s)

- Review the finding and apply the secure coding guidance for this rule.

### A10:2021 - Server-Side Request Forgery — 8 hallazgo(s)

- Review the finding and apply the secure coding guidance for this rule.

### ['A08:2021 - Software and Data Integrity Failures', 'A08:2025 - Software and Data Integrity Failures'] — 5 hallazgo(s)

- Review the finding and apply the secure coding guidance for this rule.

### A04:2021 - Insecure Design / API4:2023 — 7 hallazgo(s)

- Review the finding and apply the secure coding guidance for this rule.

### A01:2021 - Broken Access Control (también A05) — 7 hallazgo(s)

- Review the finding and apply the secure coding guidance for this rule.

### A04:2021 - Insecure Design (CWE-209) — 5 hallazgo(s)

- Review the finding and apply the secure coding guidance for this rule.

### LLM10:2025 - Unbounded Consumption — 4 hallazgo(s)

- Review the finding and apply the secure coding guidance for this rule.

### A09:2021 - Security Logging and Monitoring Failures — 5 hallazgo(s)

- Review the finding and apply the secure coding guidance for this rule.

### A08:2021 - Software and Data Integrity Failures — 1 hallazgo(s)

- Review the finding and apply the secure coding guidance for this rule.

### A05:2021 - Security Misconfiguration — 1 hallazgo(s)

- Review the finding and apply the secure coding guidance for this rule.

### A06:2021 - Vulnerable and Outdated Components — 1 hallazgo(s)

- Agregá .github/dependabot.yml con un bloque 'package-ecosystem' y 'schedule' por cada gestor detectado.

### ['A01:2017 - Injection', 'A03:2021 - Injection', 'A05:2025 - Injection'] — 1 hallazgo(s)

- Review the finding and apply the secure coding guidance for this rule.

## Datos faltantes declarados

- `finding 93` → falta `line`.
