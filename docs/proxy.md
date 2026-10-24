# Proxy de Secretos y APIs (F8)

El proxy de secretos es un reverse proxy que se interpone entre los agentes del
demo y los proveedores de modelos (Gemini, OpenAI, Claude). Su objetivo: **ningún
agente lee la clave del proveedor directamente** — la clave vive solo en el proxy,
los agentes se autentican con un token limitado, y todo queda auditado.

Módulos:

- `backend/proxy/server.py` — el proxy (Flask, puerto 5001 por defecto).
- `backend/proxy/client.py` — cliente que usan los agentes (`model_request`).

## Arranque mínimo con Docker Compose

F8 requiere dos valores relacionados: el token en claro que usa el backend y el
hash del mismo token dentro de `PROXY_TOKENS`. Las claves de los proveedores se
declaran únicamente para el servicio `proxy`.

1. Copiá `.env.example` a `.env` y reemplazá los marcadores. Generá el token y
  su hash sin guardarlos en el repositorio:

  ```bash
  python -c "import hashlib,secrets; t='sec-'+secrets.token_urlsafe(24); print('SECURITY_PROXY_TOKEN='+t); print('TOKEN_SHA256='+hashlib.sha256(t.encode()).hexdigest())"
  ```

2. Usá el token impreso en `SECURITY_PROXY_TOKEN` y su hash en el objeto de
  `PROXY_TOKENS`. Cargá al menos `GEMINI_API_KEY` si vas a usar triage o
  enriquecimiento con Gemini.

3. Levantá los servicios:

  ```bash
  docker compose up --build
  ```

Sin claves de proveedor, el dashboard y los escaneos sin IA funcionan; las
llamadas de IA fallan cerradas con respuesta `503`.

---

## Cómo funciona

```
[triage_agent / analyzer]                    [proxy (F8)]                      [proveedor]
  SECURITY_PROXY_TOKEN  ── POST /gemini/… ──►  valida token (hash SHA-256)
                                               verifica lista blanca + ruta
                                               rate limit por token
                                               inyecta GEMINI_API_KEY ────────►  https://generativelanguage…
                                               redacta la respuesta          ◄──
                                               audita (fecha/servicio/ruta/resultado/token)
```

Reglas de diseño (todas verificables en `backend/tests/test_proxy.py`):

1. **Inyección según la ruta**: el proxy elige la clave y el mecanismo de
   autenticación por proveedor (`x-goog-api-key` para Gemini, `Authorization:
   Bearer` para OpenAI, `x-api-key` para Claude). El token limitado del agente
   **nunca viaja al proveedor** y la clave del proveedor **nunca viaja al agente**.
2. **Lista blanca estricta**: solo existen tres destinos (`/gemini`, `/openai`,
   `/claude`) con rutas permitidas por proveedor (p. ej. Gemini solo
   `models/<modelo>:(generateContent|countTokens)`). Cualquier otro destino o
   ruta responde 403.
3. **Redacción**: la respuesta del proveedor y los mensajes de error se pasan por
   `_redact_text`, que reemplaza el valor del secreto inyectado y patrones
   genéricos de claves (`AIza…`, `sk-…`, `Bearer …`, `ghp_…`, `api_key=…`).
4. **Límite de tasa por token**: ventana deslizante de 60 s con
  `rate_limit_per_minute` por token (recomendado 150 para una corrida grande). Excedido → 429.
5. **Auditoría sin secretos**: cada intento (permitido o denegado) agrega una
   línea JSONL a `storage/proxy_audit.jsonl` con fecha, servicio, ruta, código
   HTTP, resultado (`allowed` / `denied:<motivo>`), duración y token. **Nunca se
   registran cuerpos ni valores secretos** (verificado con Gitleaks en las pruebas).
6. **Falla cerrada**: token inválido → 401; destino o ruta no permitidos → 403;
   secreto del proveedor ausente → 503; upstream caído → 502 con mensaje
   redactado. En el cliente: si `SECURITY_PROXY_URL` está configurada y el proxy
   no responde, se lanza `ProxyUnavailable` y **no existe fallback a la clave
   directa** — los agentes ni siquiera leen esa variable en modo proxy.

---

## Tokens limitados y rotación

Los tokens se declaran solo como **hash SHA-256** en `PROXY_TOKENS_FILE`
(default `backend/proxy/tokens.json`) o inline en `PROXY_TOKENS` (JSON):

```json
[
  {
    "id": "demo-triage",
    "token_sha256": "<sha256-hex>",
    "providers": ["gemini"],
    "rate_limit_per_minute": 150
  }
]
```

Generar el hash de un token nuevo:

```bash
python -c "import hashlib, secrets; t='sec-'+secrets.token_urlsafe(24); print(t, hashlib.sha256(t.encode()).hexdigest())"
```

**Rotación**: reemplazá el `token_sha256` del id en el archivo. El token viejo
muere de inmediato (401) y el nuevo funciona sin reiniciar el proxy — cubierto
por `test_token_rotation`.

Scopes: `providers` limita a qué proveedores puede llamar el token; pedir otro
proveedor responde 403.

---

## Proveedores configurables detrás del proxy

El agente indica el proveedor en la ruta y el proxy decide el upstream:

| Ruta del proxy            | Upstream                                          | Clave (env del proxy) |
| :---                      | :---                                              | :--- |
| `/gemini/models/<m>:generateContent` | `https://generativelanguage.googleapis.com/v1beta` | `GEMINI_API_KEY` |
| `/openai/chat/completions`| `https://api.openai.com/v1`                       | `OPENAI_API_KEY` |
| `/claude/messages`        | `https://api.anthropic.com/v1`                    | `ANTHROPIC_API_KEY` |

Cambiar de proveedor es, entonces, decisión de configuración (env del proxy) y
de la ruta que pide el agente: el backend nunca necesita la clave del nuevo
proveedor. `fixer_agent` es determinista (plantillas, sin IA) y no consume
claves; cualquier futuro paso suyo con modelos debe usar `proxy.client`.

---

## Uso por los agentes

- `triage_agent.call_triage_model(...)` y `analyzer._enrich_with_gemini(...)`
  consultan `proxy_client.proxy_configured()`:
  - **Proxy configurado** → `proxy_client.model_request(proveedor, ruta, cuerpo)`
    con el token limitado; si el proxy cae, `ProxyUnavailable` (triage devuelve
    error; el enriquecimiento se omite) y la clave directa jamás se usa.
  - **Sin proxy** → comportamiento histórico con la clave del entorno (los tests
    y despliegues existentes no se rompen).
- El despliegue con `docker compose` ya deja el proxy configurado para el
  backend (`SECURITY_PROXY_URL=http://proxy:5001`).

---

## Auditoría en el dashboard

- `GET /api/proxy/audit?limit=50` — últimas entradas (fecha, servicio, ruta,
  resultado, token, código HTTP, duración).
- `GET /api/proxy/status` — indicador: `configured`, `reachable` (healthz),
  `token_configured` y la lista blanca de proveedores.
- Pestaña **Proxy** del dashboard: indicador de estado (operativo / caído
  fail-closed / no configurado) y tabla de auditoría.

---

## Variables de entorno

| Variable | Dónde | Uso |
| :--- | :--- | :--- |
| `SECURITY_PROXY_URL` | backend | Activa el modo proxy en los agentes (fail-closed). |
| `SECURITY_PROXY_TOKEN` | backend | Token limitado que presentan los agentes. |
| `PROXY_HOST` / `PROXY_PORT` | proxy | Bind del proxy (default `127.0.0.1:5001`). |
| `PROXY_TOKENS_FILE` / `PROXY_TOKENS` | proxy | Tokens limitados (archivo o JSON inline, solo hashes). |
| `PROXY_AUDIT_FILE` | proxy | Ruta del JSONL de auditoría (default `storage/proxy_audit.jsonl`). |
| `GEMINI_API_KEY` / `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | **solo proxy** | Claves de proveedores; nunca en el backend. |

---

## Pruebas

```bash
python -m pytest tests/test_proxy.py -v
```

Cobertura: acceso permitido con inyección del secreto y auditoría; token
inválido, sin scope y ruta no permitida; destino fuera de la lista blanca;
límite de tasa; proxy caído (fail-closed del cliente, sin usar la clave directa);
secreto ausente (503); redacción en respuestas y errores; **verificación con
Gitleaks** (control positivo incluido: detecta el secreto en claro y confirma que
la auditoría redactada queda limpia); rotación de tokens.
