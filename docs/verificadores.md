# F11. Verificación en Vivo y Evidencia

La plataforma incorpora verificación dinámica defensiva y registro de evidencia manual
para complementar el análisis SAST estático del inventario de controles de seguridad.

---

## 1. Modos de Verificación en Vivo (`verificadores/`)

### Modo HTTP
Pruebas dinámicas contra URLs indicadas mediante peticiones **no destructivas y de baja frecuencia**:
- **Control 1 (CORS):** Envía peticiones con `Origin: https://evil-untrusted-origin.example.com` y valida que no se refleje en `Access-Control-Allow-Origin` ni conviva con `Access-Control-Allow-Credentials: true`.
- **Control 3 (Errores):** Provocación de error controlado 404/400 verificando que las respuestas no filtren stack traces, volcados de memoria, SQL ni mensajes de depuración interna.
- **Control 7 (Rate Limit):** Ráfaga controlada de baja frecuencia comprobando respuesta con código HTTP 429 o cabeceras estándar de control de tasa (`RateLimit-*`, `Retry-After`).
- **Control 10 (Cookies):** Inspección de cabeceras `Set-Cookie` exigiendo banderas `Secure`, `HttpOnly` y `SameSite`.
- **Control 14 (TLS):** Comprobación de que el servidor exija TLS moderno (>= 1.2) y rechace versiones obsoletas (< 1.2).
- **Control 16 (Headers):** Inspección de cabeceras de seguridad esenciales (`Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, `Referrer-Policy`).

### Modo Nube
Auditoría de infraestructura con credenciales de solo lectura que **atraviesan el proxy de secretos de F8**:
- **Control 13 (Cifrado BD):** `aws rds describe-db-instances` / `describe-db-clusters` comprobando `StorageEncrypted`.
- **Control 14 (TLS ALB):** `aws elbv2 describe-listeners` comprobando políticas SSL modernas (TLS 1.2+).
- **Control 15 (S3 público):** `aws s3api get-public-access-block` comprobando bloqueo de acceso público.
- **Control 18 (BD pública):** `aws rds describe-db-instances` comprobando `PubliclyAccessible: false`.
- **Control 19 (Ciclo de vida):** `aws s3api get-bucket-lifecycle-configuration` comprobando reglas de retención y expiración.
- **Control C6 (Respaldos):** `aws rds describe-db-instances` comprobando `BackupRetentionPeriod > 0`.
- **Control C9 (CloudTrail):** `aws cloudtrail describe-trails` comprobando trails de auditoría multirregión activos.

---

## 2. Garantías de Seguridad y Reglas de Operación

1. **Autorización explícita previa obligatoria**: Antes de cualquier prueba en vivo se exige confirmar formalmente la autorización sobre el objetivo (`autorizacion_confirmada: true`). De lo contrario, la ejecución se bloquea (HTTP 400).
2. **Lista blanca estricta en la nube**: El proxy F8 y los ejecutores únicamente aceptan comandos `describe` y `get` autorizados. Cualquier parámetro mutante (`delete`, `put`, `create`, `update`, `modify`, `terminate`, etc.) es rechazado.
3. **Solicitudes benignas**: Nunca se envían cargas dañinas ni ataques de fuerza bruta.
4. **Honestidad ante incertidumbre**: Si un control no se puede verificar (por fallo de red, falta de credenciales o ausencia de recursos), queda en **«requiere evidencia»**, nunca se marca como «cumple».
5. **Bitácora de auditoría**: Toda prueba en vivo se registra en `storage/live_verification_audit.jsonl` con fecha, usuario, objetivo, resultado y redacción estricta de secretos.

---

## 3. UI/UX en la Vista Controles

- **Columna Método**: Muestra el origen de evaluación (`repo`, `en vivo`, `evidencia`) con filtros por estado, familia y método.
- **Ficha de Evidencia**: Para controles no automatizables (`4`, `C1`, `C6`, `C9`, `C12`), se ofrece un modal con la guía de qué subir, quién lo sube, la fecha del informe/simulacro y notas de respaldo.
- **Confirmación previa**: Antes de ejecutar verificaciones en vivo, se despliega un modal con el objetivo (URL o cuenta), el desglose de qué se va a probar y el checkbox obligatorio de autorización.

---

## 4. Agregar un Control Nuevo sin Modificar Código

Cualquier control nuevo se agrega creando su especificación en `controls/<id>.yml` con los campos:
`id`, `nombre`, `referencia`, `familia`, `dónde buscar`, `señales de incumplimiento`, `falsos positivos conocidos`, `remediación`, `verificación` y `método`.

Tanto el cargador dinámico (`spec_loader.py`), el revisor (`review_service.py`), la API y la vista web en React lo reconocen y renderizan automáticamente en su orden natural.

---

## 5. Pruebas Automatizadas

```bash
# Pruebas exclusivas de verificadores en vivo y evidencia F11:
python -m pytest backend/tests/test_verificadores.py -v

# Prueba de campos obligatorios en controls/ y revisión completa:
python -m pytest backend/tests/test_controls.py -v

# Contrato OpenAPI con endpoints de F11:
python -m pytest backend/tests/test_openapi_contract.py -v
```
