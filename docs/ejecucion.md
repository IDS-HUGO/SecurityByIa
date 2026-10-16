# Guia de ejecucion

Esta guia explica como instalar, configurar, levantar y probar Security Control Center.
La aplicacion tiene tres servicios cuando se usa Docker Compose:

- `frontend`: SPA React servida por Nginx en el puerto 80.
- `backend`: API Flask y motor de analisis en el puerto 5000.
- `proxy`: proxy opcional de secretos y proveedores de IA en el puerto 5001.

## 1. Requisitos

Instala o verifica:

```bash
docker --version
docker compose version
git --version
```

Docker es la ruta recomendada porque incluye Gitleaks y ejecuta todo con las versiones
esperadas. Para desarrollo local tambien necesitas Python 3.10+ y Node.js 20+.

## 2. Configuracion del entorno

Desde la raiz del repositorio:

```bash
cp .env.example .env
```

El archivo `.env` es local y nunca debe subirse a git.

### Token del proxy

El backend envia un token limitado al proxy. El proxy solo guarda el hash SHA-256.
Genera ambos valores:

```bash
python3 -c "import hashlib,secrets; t='sec-'+secrets.token_urlsafe(24); print('SECURITY_PROXY_TOKEN='+t); print('TOKEN_SHA256='+hashlib.sha256(t.encode()).hexdigest())"
```

Copia el token en `SECURITY_PROXY_TOKEN` y el hash en `PROXY_TOKENS` dentro de `.env`:

```env
SECURITY_PROXY_TOKEN=sec-valor-generado
PROXY_TOKENS=[{"id":"demo-triage","token_sha256":"hash-generado","providers":["gemini"],"rate_limit_per_minute":150}]
```

### Claves de proveedores

Las claves viven unicamente en el servicio `proxy`, no en el backend:

```env
GEMINI_API_KEY=tu-clave-de-google-ai-studio
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
GEMINI_MODEL=gemini-3.5-flash-lite
```

Para comenzar solo necesitas Gemini. Las claves se obtienen en las consolas oficiales
de cada proveedor. Si no configuras ninguna, los escaneos sin IA continuan funcionando;
las llamadas de IA responden con error controlado `503`.

### Webhook de GitHub, opcional

Solo es necesario para F7:

```bash
openssl rand -hex 32
```

Usa el resultado como `GITHUB_WEBHOOK_SECRET` en el entorno del backend y como secreto
del webhook en GitHub. Para publicar comentarios y checks configura tambien `GITHUB_TOKEN`.
El servidor debe ser accesible desde GitHub.

## 3. Ejecucion con Docker Compose

Valida primero la configuracion:

```bash
docker compose config --quiet
```

Construye y levanta los servicios:

```bash
docker compose up --build
```

Para ejecutarlos en segundo plano:

```bash
docker compose up --build -d
docker compose ps
```

URLs locales:

- Dashboard: <http://localhost>
- API: <http://localhost:5000>
- Estado del proxy: <http://localhost:5000/api/proxy/status>
- OpenAPI: <http://localhost:5000/openapi.yaml>

Logs:

```bash
docker compose logs -f backend
docker compose logs -f proxy
```

Detener y eliminar contenedores:

```bash
docker compose down
```

El historial se conserva en `backend/storage/`, montado como volumen del backend y del
proxy.

## 4. Primer analisis desde el dashboard

Abre <http://localhost>, pega una URL publica de GitHub y presiona **Iniciar analisis**.
Deja desactivado **Triage con IA** para la primera prueba. El resultado pasa por estos
estados:

```text
queued -> cloning -> scanning -> normalizing -> completed
```

Si falla, el dashboard muestra el motivo y una accion sugerida. No se aceptan URLs `http`,
SSH, `file://` ni repositorios privados.

## 5. Primer analisis mediante API

Inicia un analisis:

```bash
curl -X POST http://localhost:5000/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://github.com/OWASP/NodeGoat","enable_ai_triage":false}'
```

La respuesta incluye `analysis_id`. Consulta el estado reemplazando el identificador:

```bash
curl http://localhost:5000/api/analysis/ID_DEL_ANALISIS
```

Tambien puedes listar el historial:

```bash
curl http://localhost:5000/api/analyses
```

Para activar F5, configura las claves del proxy y envia explicitamente:

```json
{"url":"https://github.com/OWASP/NodeGoat","enable_ai_triage":true}
```

El triage envia un fragmento limitado de codigo con secretos redactados. No actives esta
opcion para codigo de terceros sin autorizacion de la organizacion.

## 6. Repositorios recomendados

Usa estos repositorios en este orden:

1. Un repositorio pequeno propio.
2. `https://github.com/OWASP/NodeGoat` para una prueba funcional.
3. `https://github.com/juice-shop/juice-shop` para una prueba mas grande.

Los repositorios de benchmark no son una lista fija de repositorios soportados. Son datos
de evaluacion declarados en `backend/bench/refs.yml`.

Ejecuta el ejemplo pequeno:

```bash
docker compose exec backend python bench/test_tiny.py
```

Ejecuta todo el benchmark:

```bash
docker compose exec backend python bench/benchmark.py
```

Guarda una corrida como baseline:

```bash
docker compose exec backend python bench/benchmark.py \
  --save-as-baseline --feature "F8 - Proxy de secretos"
```

## 7. Pruebas

Dentro del contenedor backend:

```bash
docker compose exec backend python -m pytest tests -v
```

Pruebas mas acotadas:

```bash
docker compose exec backend python -m pytest tests/test_proxy.py -v
docker compose exec backend python -m pytest tests/test_webhook.py -v
docker compose exec backend python -m pytest tests/test_fixer_agent.py -v
```

Para validar el frontend sin Docker:

```bash
npm --prefix frontend install
npm --prefix frontend run build
```

## 8. Flujo interno

```text
Frontend React
    |
    | POST /api/analyze
    v
API Flask y cola de workers
    |
    v
Clon temporal HTTPS endurecido
    |
    +--> Semgrep y reglas OWASP
    +--> Gitleaks
    +--> Scanners opcionales segun el stack
    +--> Deduplicacion y severidad contextual
    +--> Triage IA opt-in a traves del proxy
    v
JSON persistido en backend/storage/analyses
    |
    v
Dashboard, benchmark y reportes
```

El repositorio analizado se trata como dato: el sistema lo lee, pero no ejecuta su codigo.
Los parches del fixer se aplican en ramas temporales, se vuelven a escanear y requieren
aprobacion humana.

## 9. Carpetas principales

- `backend/`: API y logica principal.
- `backend/analyzer.py`: clonacion, escaneo, normalizacion y reportes.
- `backend/scanner_tools.py`: deteccion de stack y adaptadores opcionales.
- `backend/severity_engine.py`: CWE, OWASP, severidad y SLA.
- `backend/triage_agent.py`: triage IA acotado y decisiones humanas.
- `backend/fixer_agent.py`: parches deterministas y re-verificacion.
- `backend/webhook_service.py`: analisis de pull requests de GitHub.
- `backend/proxy/`: proxy fail-closed de claves y APIs de modelos.
- `backend/bench/`: benchmark y ground truth.
- `backend/rules/`: reglas Semgrep propias.
- `backend/data/`: mapas OWASP e inventario de controles.
- `backend/tests/`: pruebas automatizadas.
- `frontend/`: unico frontend React/Vite.
- `backend/storage/`: estado generado, historial y auditoria.
- `docs/`: documentacion operativa y tecnica.

## 10. Problemas comunes

### El puerto 80 ya esta ocupado

Cambia el puerto del frontend en `docker-compose.yml`:

```yaml
ports:
  - "8080:80"
```

Abre entonces <http://localhost:8080>.

### El proxy responde `401` o `503`

Verifica que el token en `SECURITY_PROXY_TOKEN` coincida con el hash dentro de
`PROXY_TOKENS`, y que la clave del proveedor este configurada para el servicio proxy.

### Falta una herramienta de analisis

El analisis continua y la herramienta aparece como `unavailable`. La imagen instala
Semgrep y Gitleaks; OSV-Scanner, Bandit, Trivy, Checkov, TruffleHog y otros scanners son
opcionales y deben instalarse si quieres cobertura adicional.

### Un analisis queda interrumpido

Consulta los logs:

```bash
docker compose logs backend
```

Un reinicio marca trabajos en vuelo como interrumpidos. Puedes iniciar un nuevo analisis.
