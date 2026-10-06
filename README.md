# Security Control Center

## ¿De qué trata?

Security Control Center es un prototipo de análisis de seguridad para repositorios públicos de GitHub. La aplicación permite ingresar la URL de un repositorio y consultar, desde una interfaz web, los hallazgos detectados mediante análisis estático.

El objetivo de la demo es apoyar un proceso de seguridad basado en OWASP Top 10, mostrando los riesgos de forma clara para facilitar su clasificación, priorización, documentación y remediación.

La solución está pensada como una herramienta de apoyo. Los resultados deben ser revisados por una persona con conocimiento de seguridad antes de tomar decisiones definitivas.

## Funcionalidades

- Validación de URLs públicas de GitHub.
- Clonación temporal del repositorio.
- Análisis SAST mediante Semgrep y las reglas `p/owasp-top-ten`.
- Detección de secretos y credenciales expuestas mediante Gitleaks.
- Clasificación por severidad:
  - Critical
  - High
  - Medium
  - Low
- Normalización y deduplicación de hallazgos.
- Información de OWASP, CWE, regla, archivo y línea afectada.
- Contexto acotado del código alrededor del hallazgo.
- Explicación del problema y recomendación de solución.
- Estados de ejecución:
  - Queued
  - Running
  - Completed
  - Failed
- Barra de progreso del análisis.
- Historial de análisis anteriores.
- Reanálisis de un repositorio desde el historial.
- Filtros por severidad, archivo, OWASP, CWE y estado.
- Descarga del reporte en Markdown y JSON.
- Interfaz visual de tipo dashboard de seguridad, sin apariencia de chatbot.
- Enriquecimiento opcional con Gemini.

## Arquitectura

```text
Usuario
  |
  v
Dashboard HTML/CSS/JavaScript
  |
  | POST /api/analyze
  v
API Flask
  |
  v
Analizador Python
  |
  +-- git clone temporal
  +-- Semgrep OWASP Top 10
  +-- Gitleaks (secret scanning)
  +-- Normalización y deduplicación
  +-- Enriquecimiento opcional con Gemini
  +-- Generación del reporte
  |
  v
storage/analyses/{analysis_id}.json
```

## Requisitos

- Windows PowerShell.
- Python 3.10 o superior recomendado.
- Git disponible en el `PATH`.
- Semgrep instalado.
- Gitleaks instalado y disponible en el `PATH` (opcional; si no está disponible se informa en `analysis.tools`).
- Dependencias de Python del archivo `requirements.txt`.
- Una clave `GEMINI_API_KEY` solamente si se desea activar el enriquecimiento con Gemini.

## Instalación en Windows

Abre PowerShell y entra en la carpeta del proyecto:

```powershell
cd C:\Users\Esparrago\Downloads\demo
```

Activa el entorno virtual:

```powershell
.\venv\Scripts\Activate.ps1
```

Si PowerShell bloquea la ejecución de scripts, permite la ejecución únicamente para la sesión actual:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

Instala las dependencias:

```powershell
python -m pip install -r requirements.txt
```

Comprueba las herramientas principales:

```powershell
python --version
git --version
semgrep --version
gitleaks version
```

## Ejecución de la aplicación web

Desde la carpeta del proyecto y con el entorno virtual activado:

```powershell
python api_server.py
```

Abre el navegador en:

```text
http://127.0.0.1:5000
```

Para detener el servidor:

```text
Ctrl + C
```

## Ejecución con enriquecimiento de Gemini

La integración con Gemini es opcional. Sin una clave, el análisis funciona utilizando los resultados de Semgrep.

En PowerShell, configura la variable únicamente para la sesión actual:

```powershell
$env:GEMINI_API_KEY = "tu_clave_de_gemini"
python api_server.py
```

También se pueden configurar opcionalmente el modelo y el endpoint:

```powershell
$env:GEMINI_MODEL = "gemini-1.5-flash"
$env:GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
```

La aplicación aplica controles antes de enviar información al modelo:

- No envía el código fuente ni el contexto completo del hallazgo.
- Envía únicamente metadatos mínimos del hallazgo.
- Redacta posibles tokens, claves API, contraseñas y claves privadas.
- Exige una respuesta JSON con un esquema definido.
- Valida IDs, tipos y severidades.
- Conserva el resultado de Semgrep si Gemini falla o devuelve una respuesta inválida.
- Registra el origen de los campos mediante `sources`.
- Envía un payload versionado con resumen, detector, ubicación, OWASP, CWE y referencias acotadas.
- Nunca envía el valor detectado por Gitleaks (`Secret`/`Match`).

No guardes claves reales en el código fuente ni las subas al repositorio.

## Uso de la interfaz

1. Abre `http://127.0.0.1:5000`.
2. Introduce una URL pública de GitHub, por ejemplo:

   ```text
   https://github.com/juice-shop/juice-shop
   ```

3. Presiona **Start analysis**.
4. Observa el estado y progreso del análisis.
5. Revisa el resumen por severidad.
6. Filtra los hallazgos por severidad, archivo, OWASP, CWE o estado.
7. Haz clic en un hallazgo para consultar su detalle y contexto de código.
8. Descarga el resultado como JSON o Markdown.

El repositorio debe ser público y utilizar una URL con este formato:

```text
https://github.com/organizacion/repositorio
https://github.com/organizacion/repositorio.git
```

## Uso de la API

### Iniciar un análisis

PowerShell:

```powershell
$body = @{
  url = "https://github.com/juice-shop/juice-shop"
} | ConvertTo-Json

Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:5000/api/analyze `
  -ContentType "application/json" `
  -Body $body
```

Respuesta esperada:

```json
{
  "analysis_id": "uuid",
  "status": "processing",
  "stage": "queued",
  "progress": 0,
  "message": "Analysis queued"
}
```

### Consultar un análisis

Reemplaza `ID_DEL_ANALISIS` por el valor recibido:

```powershell
Invoke-RestMethod `
  -Uri http://127.0.0.1:5000/api/analysis/ID_DEL_ANALISIS
```

El resultado incluye:

- Estado.
- Repositorio.
- Resumen por severidad.
- Hallazgos normalizados.
- Evidencia y contexto de código.
- Origen de los campos.
- Reporte Markdown.

### Consultar el historial

```powershell
Invoke-RestMethod `
  -Uri http://127.0.0.1:5000/api/analyses
```

## Formato de un hallazgo

```json
{
  "id": 1,
  "rule": "python.lang.security.audit.eval-detected",
  "owasp": "A03:2021 - Injection",
  "cwe": ["CWE-95"],
  "references": [],
  "severity": "high",
  "file": "src/example.py",
  "line": 42,
  "title": "Uso inseguro de eval",
  "problem": "La entrada puede ejecutarse como código.",
  "solution": "Reemplazar eval por un parser seguro.",
  "false_positive": false,
  "status": "open",
  "code_context": [
    {
      "line": 40,
      "text": "..."
    }
  ],
  "sources": {
    "severity": "semgrep",
    "problem": "gemini"
  }
}
```

## Ejecución desde línea de comandos

También se puede ejecutar el analizador sin iniciar la interfaz:

```powershell
python analyzer.py --url "https://github.com/juice-shop/juice-shop"
```

Al finalizar, se generan:

- `reporte_seguridad.json`
- `reporte_seguridad.md`

## Estructura principal

```text
demo/
├── analyzer.py                 # Motor de análisis SAST y enriquecimiento opcional
├── api_server.py               # API Flask y ejecución asíncrona
├── requirements.txt            # Dependencias Python
├── static/
│   ├── index.html              # Interfaz principal
│   ├── css/styles.css          # Estilos del dashboard
│   └── js/app.js               # Lógica del cliente
├── storage/
│   └── analyses/               # Resultados persistidos en JSON
├── reporte_seguridad.md        # Reporte CLI generado
└── reporte_seguridad.json      # Resultado CLI generado
```

## Validaciones realizadas

Las validaciones básicas del proyecto pueden ejecutarse con:

```powershell
python -m py_compile analyzer.py api_server.py
node --check .\static\js\app.js
```

También se validan:

- URLs inválidas.
- Respuesta de la página principal.
- Ciclo de vida asíncrono de un análisis.
- Redacción de secretos antes de enviar datos a Gemini.
- Validación del esquema de respuesta de Gemini.
- Deduplicación y contexto de código.
- Integración opcional de Gitleaks y estado individual de cada herramienta.

## Limitaciones actuales

- El análisis combina SAST con Semgrep y secret scanning con Gitleaks cuando el binario está disponible.
- Solo se aceptan repositorios públicos de GitHub.
- Todavía no incluye análisis completo de dependencias, contenedores, IaC ni workflows.
- No sustituye una revisión manual de seguridad.
- La clasificación automática puede requerir confirmación humana.
- La persistencia actual utiliza archivos JSON y está orientada a una demo local.
- No incluye autenticación, rate limiting ni una cola distribuida de trabajos.

## Próximas mejoras recomendadas

1. Agregar análisis de dependencias con `pip-audit`, `npm audit` o Trivy.
2. Incorporar reglas Semgrep propias del equipo.
3. Añadir puntuación de riesgo basada en impacto, probabilidad y exposición.
4. Implementar comparación entre análisis.
5. Añadir autenticación y soporte seguro para repositorios privados.
6. Integrar el análisis en GitHub Actions y Pull Requests.
7. Validar automáticamente que una remediación elimine el hallazgo.
8. Migrar el almacenamiento a SQLite o PostgreSQL cuando existan varios usuarios.

