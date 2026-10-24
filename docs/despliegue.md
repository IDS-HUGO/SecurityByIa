# Guía de Despliegue en la Nube (Cloud Deployment Guide)

Esta guía describe el procedimiento de despliegue de **Security Control Center** en
entornos de nube de producción y prueba, conforme a las especificaciones de la
arquitectura desacoplada (F4B) y el aislamiento de credenciales (F8).

---

## 1. Arquitectura de Despliegue

La solución se compone de tres servicios en contenedores aislados:

```
                          [ Internet / Clientes ]
                                     │
                             (HTTPS / Puerto 443)
                                     ▼
                     ┌───────────────────────────────┐
                     │   Ingress / Nginx Frontend    │ (Servicio 'frontend')
                     │     React SPA (dist/)         │ Puerto 80 / 443
                     └───────────────┬───────────────┘
                                     │ /api/* (Reverse Proxy interno)
                                     ▼
                     ┌───────────────────────────────┐
                     │       Backend API REST        │ (Servicio 'backend')
                     │      Flask (puerto 5000)      │
                     │  Montaje: /backend/storage    │ (Volumen persistente)
                     └───────────────┬───────────────┘
                                     │ Llamadas IA con token limitado
                                     ▼
                     ┌───────────────────────────────┐
                     │   Proxy de Secretos (F8)      │ (Servicio 'proxy')
                     │    Flask (puerto 5001)        │ Red interna aislada
                     └───────────────┬───────────────┘
                                     │ Solo egreso HTTPS auditado
                                     ▼
                     [ Proveedores: Gemini / OpenAI ]
```

---

## 2. Opción A: Despliegue en Máquina Virtual Cloud (AWS EC2 / GCP Compute Engine / Ubuntu)

Esta opción es la recomendada para entornos de demostración y producción estándar.

### Requisitos mínimos de la VM
- **SO**: Ubuntu 22.04 LTS o superior.
- **Capacidad**: 2 vCPU, 4 GB RAM (mínimo para ejecución fluida de Semgrep y AST).
- **Disco**: 30 GB SSD (espacio para clones de repositorios y base de hallazgos en `/storage`).
- **Puertos de Firewall (Security Group)**:
  - `22/TCP`: SSH administrativo (restringido por IP).
  - `80/TCP`: HTTP (redirección a HTTPS).
  - `443/TCP`: HTTPS público (Dashboard web y Webhooks).
  - *Puertos 5000 y 5001 cerrados al exterior* (solo comunicación entre contenedores en la red Docker).

### Paso 1: Instalación de Docker y dependencias
```bash
sudo apt update && sudo apt install -y curl git docker.io docker-compose-v2
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
```

### Paso 2: Clonado del repositorio
```bash
git clone https://github.com/tu-organizacion/demo-seguridad.git /opt/demo-seguridad
cd /opt/demo-seguridad
```

### Paso 3: Configuración de Variables de Entorno (`.env`)
Genere los tokens criptográficos de seguridad:

```bash
# Generar token del agente y su hash SHA-256
python3 -c "import hashlib,secrets; t='sec-'+secrets.token_urlsafe(24); print('TOKEN='+t); print('HASH='+hashlib.sha256(t.encode()).hexdigest())"
```

Cree el archivo `/opt/demo-seguridad/.env` a partir de `.env.example`:

```bash
# Dominio o IP pública del despliegue
APP_DOMAIN=seguridad.tuempresa.com

# Backend Flask
HOST=0.0.0.0
PORT=5000
CORS_ALLOWED_ORIGINS=https://seguridad.tuempresa.com,http://localhost
MAX_CONCURRENT_ANALYSES=4
RATE_LIMIT_PER_MINUTE=60
STORAGE_DIR=/app/backend/storage

# Cliente de Proxy (usado por el Backend)
SECURITY_PROXY_URL=http://proxy:5001
SECURITY_PROXY_TOKEN=sec-<token-generado-en-paso-previo>

# Proxy de Secretos (Servicio 'proxy')
PROXY_PORT=5001
PROXY_TOKENS=[{"id":"backend-prod","token_sha256":"<hash-sha256-generado>","providers":["gemini"],"rate_limit_per_minute":150}]

# Claves de proveedores (viven SOLO en el proxy, nunca en el backend)
GEMINI_API_KEY=AIzaSy...tu_clave_real_de_gemini...
# OPENAI_API_KEY=sk-...

# Control de auditoría y revisión de controles
ENABLE_CONTROLS_REVIEW=true
ENABLE_AI_TRIAGE=false
CHECK_FAIL_SEVERITY=critical
```

### Paso 4: Despliegue con Docker Compose
```bash
# Construir y levantar servicios en segundo plano
docker compose up -d --build

# Verificar que los tres contenedores estén saludables
docker compose ps
```

### Paso 5: Certificado SSL/TLS con Let's Encrypt (Nginx Certbot)
```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d seguridad.tuempresa.com
```

---

## 3. Opción B: Despliegue Serverless / Contenedores Gestionados (AWS ECS / GCP Cloud Run)

Para infraestructuras que exigen escalado elástico sin gestión de VMs:

1. **Compilación y publicación de imágenes**:
   ```bash
   # Compilar Frontend
   docker build -t gcr.io/mi-proyecto/scc-frontend:latest ./frontend
   docker push gcr.io/mi-proyecto/scc-frontend:latest

   # Compilar Backend
   docker build -t gcr.io/mi-proyecto/scc-backend:latest ./backend
   docker push gcr.io/mi-proyecto/scc-backend:latest
   ```

2. **Almacenamiento persistente**:
   - En **AWS ECS**: Montar un volumen persistente **Amazon EFS** sobre `/app/backend/storage` para retener análisis, huellas de falsos positivos y reportes entre reinicios de tareas.
   - En **GCP Cloud Run**: Configurar **Cloud Storage FUSE volume mount** sobre `/app/backend/storage`.

3. **Inyección de secretos de nube**:
   - Almacenar las credenciales (`GEMINI_API_KEY`, `SECURITY_PROXY_TOKEN`) en **AWS Secrets Manager** o **Google Secret Manager**, inyectándolas como variables de entorno al iniciar el contenedor.

---

## 4. Matriz de Variables de Entorno de Producción

| Variable | Servicio | Descripción | Valor recomendado / Ejemplo |
| :--- | :--- | :--- | :--- |
| `CORS_ALLOWED_ORIGINS` | `backend` | Lista blanca estricta de orígenes HTTP/HTTPS permitidos | `https://seguridad.empresa.com` |
| `STORAGE_DIR` | `backend` | Ruta absoluta al almacenamiento de análisis y caché | `/app/backend/storage` |
| `SECURITY_PROXY_URL` | `backend` | URL del reverse proxy de modelos (red interna) | `http://proxy:5001` |
| `SECURITY_PROXY_TOKEN` | `backend` | Token limitado en claro para autenticarse con el proxy | `sec-<token-aleatorio>` |
| `PROXY_TOKENS` | `proxy` | JSON con hashes SHA-256 autorizados, proveedores y límites | `[{"id":"backend","token_sha256":"..."}]` |
| `GEMINI_API_KEY` | `proxy` | Clave API de Google AI Studio / Vertex AI | Clave privada (nunca visible fuera del proxy) |
| `MAX_CONCURRENT_ANALYSES` | `backend` | Límite de escaneos simultáneos en el pool de threads | `2` a `4` según CPU |
| `RATE_LIMIT_PER_MINUTE` | `backend` | Límite de peticiones de análisis por IP cliente | `30` |
| `CHECK_FAIL_SEVERITY` | `ci/cd` | Severidad mínima que bloquea el merge en pull requests | `critical` |

---

## 5. Verificación del Despliegue

Una vez completado el despliegue, verifique el estado del sistema:

1. **Health check de la API**:
   ```bash
   curl -fsSL https://seguridad.tuempresa.com/api/
   # Respuesta esperada: {"openapi":"/openapi.yaml","service":"Security Control Center API","status":"healthy","version":"1.0.0"}
   ```

2. **Health check del Proxy de Secretos (desde la red interna)**:
   ```bash
   curl -fsSL http://localhost:5001/healthz
   # Respuesta esperada: {"status":"healthy","proxy":"active","allowlist":["gemini","openai","claude"]}
   ```

3. **Auditoría activa**:
   Compruebe que el archivo `backend/storage/proxy_audit.jsonl` reciba los registros sin exponer tokens crudos ni credenciales de proveedores.
