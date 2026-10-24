# docs/ — Guías Operativas y Entregables del Proyecto

Índice central de documentación técnica, operativa y de gobierno de **Security Control Center**:

## Entregables Principales y Operación
- **[guia-buenas-practicas.md](guia-buenas-practicas.md)** (Entregable 5) — cómo actualizar reglas, correr benchmarks, rotar tokens del proxy, agregar herramientas y plazos máximos por severidad (SLA).
- **[despliegue.md](despliegue.md)** — guía de despliegue en la nube (VM con Docker Compose y servicios de contenedores gestionados), variables de entorno y endurecimiento.
- **[confidencialidad.md](confidencialidad.md)** — nota de confidencialidad, consentimiento explícito (opt-in), tratamiento de datos (Control C12, Anexo B) y comparativa con herramientas comerciales (Arnica / Aikido).
- **[evidencia-proxy.md](evidencia-proxy.md)** — evidencia de operación del proxy de secretos F8 con llamada real/auditada, token limitado y registro redactado.
- **[ejecucion.md](ejecucion.md)** — guía rápida de ejecución local y primer recorrido del dashboard.

## Precisión, Benchmarks e Inteligencia Artificial
- **[resultados-ia.md](resultados-ia.md)** — resultados empíricos de la IA en triage con comparativa multi-modelo (Gemini vs OpenAI vs Claude), y reducción de FPR antes y después.
- **[resultados-benchmark.md](resultados-benchmark.md)** — línea base oficial de precisión (baseline) contra OWASP Benchmark for Python real (repo reservado holdout) desglosado por categorías CWE.
- **[benchmark.md](benchmark.md)** — metodología del benchmark contra repositorios de referencia (`refs.yml`, ground truth, matching y métricas).

## Arquitectura y Módulos Técnicos
- **[analizar.md](analizar.md)** — cómo correr un análisis por CLI y API, flags, límites de seguridad y flujo interno del motor.
- **[clasificacion-severidad.md](clasificacion-severidad.md)** — cálculo de severidad contextual, scoring, SLAs y mitigaciones.
- **[proxy.md](proxy.md)** — arquitectura técnica del proxy de secretos y APIs (F8).
- **[controles.md](controles.md)** — revisión por control con IA (F10): 35 especificaciones, gating LLM, reglas Semgrep propias y hoja de registro.
- **[verificadores.md](verificadores.md)** — verificación en vivo y evidencia (F11): modo HTTP y modo nube.
- **[agregar-herramienta.md](agregar-herramienta.md)** — integración de nuevos analizadores estáticos y de dependencias en `scanner_tools.py`.

## Reportes de Ejemplo
- **[Reporte propio repo](ejemplos/reporte-propio-repo.md)** — informe Markdown generado sobre la plataforma con estados de remediación asistida F6.
- **[Reporte repositorio de terceros](ejemplos/reporte-terceros.md)** — informe generado sobre repositorio de prueba con parches verificados y aprobados.
