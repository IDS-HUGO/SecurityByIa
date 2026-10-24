# docs/ — Guías operativas

- **[analizar.md](analizar.md)** — cómo correr un análisis por CLI y API, flags,
  límites de seguridad y flujo interno del motor.
- **[clasificacion-severidad.md](clasificacion-severidad.md)** — cómo el motor
  contextual clasifica la severidad (score, SLA, límites del ajuste IA).
- **[agregar-herramienta.md](agregar-herramienta.md)** — cómo integrar un
  escáner opcional en `scanner_tools.py` (patrón, fusión, pruebas).
- **[benchmark.md](benchmark.md)** — cómo medir precisión contra los repos de
  referencia (`bench/refs.yml`, ground truth, métricas, baseline).
- **[proxy.md](proxy.md)** — proxy de secretos y APIs (F8): tokens limitados,
  lista blanca, auditoría y rotación.
- **[controles.md](controles.md)** — revisión por control con IA (F10): 35 especificaciones,
  gating LLM, reglas Semgrep propias y hoja de registro.
- **[verificadores.md](verificadores.md)** — verificación en vivo y evidencia (F11): modo HTTP,
  modo nube pasando por proxy F8, ficha de evidencia manual y extensibilidad dinámica.
- **[ejecucion.md](ejecucion.md)** — instalación, despliegue con Docker Compose
  y primer recorrido del dashboard.
