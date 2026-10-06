# Reporte Final de Seguridad (OWASP Top 10)

Como experto auditor de ciberseguridad, he analizado el reporte SAST proporcionado. Es importante notar que este repositorio parece pertenecer a **OWASP Juice Shop** (una aplicación diseñada deliberadamente con vulnerabilidades para entrenamiento).

A continuación, presento el análisis técnico de los 43 hallazgos:

---

### Hallazgo 1-8: `github-actions-mutable-action-tag`
- **Archivo**: `.github/workflows/*.yml`
- **¿Es un falso positivo?**: No.
- **Severidad**: Alto.
- **¿Cuál es el problema?**: Se están utilizando versiones mutables (como `master` o `v1`) en las acciones de GitHub, lo que permite que una acción maliciosa sustituya la versión legítima.
- **¿Cómo solucionarlo?**: Fijar las acciones mediante su hash SHA-256 (ej: `uses: actions/checkout@v4@hash-especifico`).

---

### Hallazgo 9-13: `run-shell-injection`
- **Archivo**: `.github/workflows/update-challenges-*.yml`
- **¿Es un falso positivo?**: No.
- **Severidad**: Crítico.
- **¿Cuál es el problema?**: Inyección de comandos mediante entradas no saneadas que se ejecutan directamente en un shell de CI/CD.
- **¿Cómo solucionarlo?**: Evitar el uso de variables directas en scripts shell. Usar `args` con parámetros separados en lugar de concatenar cadenas.

---

### Hallazgo 14, 25: `npm-missing-minimum-release-age`
- **Archivo**: `.npmrc` / `frontend/.npmrc`
- **¿Es un falso positivo?**: Sí (es una política de seguridad, no una vulnerabilidad de código).
- **Severidad**: Bajo.
- **¿Cuál es el problema?**: No hay restricciones de edad mínima para las dependencias.
- **¿Cómo solucionarlo?**: Es una configuración de seguridad, no un bug. Se puede ignorar o configurar `fund` u otras políticas de auditoría.

---

### Hallazgo 15-16, 23-24, 32, 35: `sequelize-injection-express`
- **Archivo**: `data/static/codefixes/*.ts`, `routes/*.ts`
- **¿Es un falso positivo?**: No.
- **Severidad**: Crítico.
- **¿Cuál es el problema?**: Inyección SQL vía Sequelize al concatenar entradas de usuario directamente en consultas.
- **¿Cómo solucionarlo?**: Utilizar `parameterized queries` o el operador `where` de Sequelize con objetos, nunca concatenar strings.

---

### Hallazgo 17, 19, 21, 26, 42: `aws-subnet-has-public-ip-address`
- **Archivo**: `.tf`
- **¿Es un falso positivo?**: No.
- **Severidad**: Medio.
- **¿Cuál es el problema?**: Subnets expuestas directamente a Internet con IP pública.
- **¿Cómo solucionarlo?**: Establecer `map_public_ip_on_launch = false` y usar un NAT Gateway para acceso de salida.

---

### Hallazgo 18, 20, 22, 27, 43: `insecure-load-balancer-tls-version`
- **Archivo**: `.tf`
- **¿Es unфици falso positivo?**: No.
- **Severidad**: Alto.
- **¿Cuál es el problema?**: Uso de versiones TLS obsoletas (ej. TLS 1.0/1.1).
- **¿Cómo solucionarlo?**: Configurar `ssl_policy` en el balanceador de carga para aceptar únicamente TLS 1.2 o superior.

---

### Hallazgo 28: `hardcoded-jwt-secret`
- **Archivo**: `lib/insecurity.ts`
- **¿Es un falso positivo?**: No.
- **Severidad**: Crítico.
- **¿Cuál es el problema?**: Clave secreta para firmar JWT expuesta en el código fuente.
- **¿Cómo solucionarlo?**: Mover el secreto a una variable de entorno (`process.env.JWT_SECRET`) y gestionarlo en un vault de secretos.

---

### Hallazgo 29-31, 33: `express-res-sendfile`
- **Archivo**: `routes/*.ts`
- **¿Es un falso positivo?**: No.
- **Severidad**: Alto.
- **¿Cuál es el problema?**: Path Traversal. Permitir que el usuario defina rutas de archivos a enviar.
- **¿Cómo solucionarlo?**: Validar y sanitizar la ruta de entrada, o restringir el directorio base mediante `path.resolve` y verificar que el resultado inicie con el directorio permitido.

---

### Hallazgo 34: `express-open-redirect`
- **Archivo**: `routes/redirect.ts`
- **¿Es un falso positivo?**: No.
- **Severidad**: Medio.
- **¿Cuál es el problema?**: Redirección abierta hacia sitios externos maliciosos usando parámetros no validados.
- **¿Cómo solucionarlo?**: Mantener una lista blanca (whitelist) de dominios permitidos para redirección.

---

### Hallazgo 36: `code-string-concat`
- **Archivo**: `routes/userProfile.ts`
- **¿Es un falso positivo?**: No.
- **Severidad**: Medio.
- **¿Cuál es el problema?**: Riesgo de inyección de código mediante concatenación de strings en funciones críticas.
- **¿Cómo solucionarlo?**: Usar plantillas o métodos de concatenación seguros y sanitizar los datos de entrada.

---

### Hallazgo 37-41: `express-check-directory-listing`
- **Archivo**: `server.ts`
- **¿Es un falso positivo?**: No.
- **Severidad**: Bajo.
- **¿Cuál es el problema?**: Servidor configurado para permitir listado de directorios (Directory Browsing).
- **¿Cómo solucionarlo?**: Deshabilitar el listado de directorios en la configuración de `express.static` o en el servidor web (Nginx/Apache).

---
*Nota del auditor: Dado que los archivos analizados incluyen "codefixes" (usados para los desafíos de Juice Shop), muchos de estos archivos fueron creados intencionalmente como vulnerables para fines educativos.*