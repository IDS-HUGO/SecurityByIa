# Evidencia de Operación del Proxy de Secretos (F8) con Proveedor Real

Este documento proporciona la evidencia verificable del funcionamiento del **Proxy de Secretos
y APIs (F8)**, demostrando el aislamiento de credenciales, el control de acceso mediante tokens
limitados con hash SHA-256, y la generación de bitácoras de auditoría libres de secretos.

---

## 1. Flujo de la Invocación

Para ejecutar una solicitud al modelo fundacional (`gemini-3.5-flash-lite`), el agente de triage
del backend nunca utiliza la clave directa de Google. En su lugar:

1. El agente envía una petición HTTP local al proxy con su token limitado:
   `Authorization: Bearer sec-demo-audit-token-xyz`.
2. El proxy calcula el hash SHA-256 del token:
   `e1654460f1ad974a621e25e98f0203f71c4cbe27ebffec6034f55a12da970ff8`.
3. El proxy valida el hash contra su archivo autorizado [`backend/proxy/tokens.json`](file:///home/productdeath/Documentos/UNIVERSAL/UNI/ESTADIA/HUGO/NEUROTRY/demo-seguridad/backend/proxy/tokens.json)
   y comprueba los permisos del servicio (`"providers": ["gemini"]`).
4. El proxy valida la ruta contra la lista blanca estricta (`/gemini/models/<modelo>:(generateContent|countTokens)`).
5. El proxy inyecta de forma segura la clave real en la cabecera `x-goog-api-key` hacia el upstream
   de Google (`https://generativelanguage.googleapis.com`).
6. El proxy recibe la respuesta, redacta cualquier posible fuga de credenciales (`_redact_text`),
   la retorna al agente y escribe una entrada en el registro de auditoría JSONL.

---

## 2. Registro de Auditoría Real (`backend/storage/proxy_audit.jsonl`)

A continuación se muestra el extracto verificado del archivo de auditoría, donde se evidencia
que **solo se registran metadatos operacionales y nunca se almacenan cuerpos de peticiones ni secretos**:

### Entrada 1: Solicitud autorizada y procesada exitosamente (HTTP 200)
```json
{
  "timestamp": "2026-10-24T16:35:22.264122+00:00",
  "token_id": "agent-triage-prod",
  "service": "gemini",
  "route": "gemini/models/gemini-3.5-flash-lite:generateContent",
  "status_code": 200,
  "result": "allowed",
  "duration_ms": 320
}
```

### Entrada 2: Intento de acceso a ruta no autorizada bloqueado por la lista blanca (HTTP 403)
```json
{
  "timestamp": "2026-10-24T16:35:14.302431+00:00",
  "token_id": "agent-triage-prod",
  "service": "gemini",
  "route": "gemini/v1beta/models/gemini-3.5-flash-lite:generateContent",
  "status_code": 403,
  "result": "denied:path-not-allowed",
  "duration_ms": 0
}
```

### Entrada 3: Auditoría histórica en corrida de análisis completo
```json
{
  "timestamp": "2026-10-16T20:35:04.764917+00:00",
  "token_id": "demo-triage",
  "service": "gemini",
  "route": "gemini/models/gemini-3.5-flash-lite:generateContent",
  "status_code": 200,
  "result": "allowed",
  "duration_ms": 8203
}
```

---

## 3. Verificación de No-Fuga de Secretos

Para garantizar que el archivo de auditoría jamás filtre credenciales ni tokens:

1. **Prueba automatizada con Gitleaks**:
   En la suite de pruebas [`backend/tests/test_proxy.py`](file:///home/productdeath/Documentos/UNIVERSAL/UNI/ESTADIA/HUGO/NEUROTRY/demo-seguridad/backend/tests/test_proxy.py) (`TestAuditoriaNoFiltraSecretos`), se ejecuta un escaneo directo de Gitleaks sobre el archivo `proxy_audit.jsonl` tras múltiples llamadas autorizadas y fallidas.
2. **Resultado de la prueba**:
   `0 secretos detectados` por Gitleaks en la bitácora de auditoría.
3. **Control positivo**:
   La misma prueba inyecta deliberadamente una clave sintética en un archivo temporal y comprueba que Gitleaks sí la detecta, validando la sensibilidad del escaneo.
