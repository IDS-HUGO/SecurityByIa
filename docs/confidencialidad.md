# Nota de Confidencialidad y Tratamiento de Datos con IA

Este documento describe la política de privacidad, consentimiento y tratamiento de datos
aplicada en las funciones de Inteligencia Artificial de **Security Control Center**, conforme
al **Control C12 del Inventario v1.0** y al **Anexo B** de la carta de compromiso y
confidencialidad del proyecto.

---

## 1. Consentimiento Explícito (Opt-in Obligatorio)

La plataforma opera bajo el principio de **privacidad por diseño**:

1. **Desactivado por defecto**: Las funciones que involucran modelos de lenguaje (triage
   asistido de hallazgos y enriquecimiento explicativo) están **estrictamente apagadas**
   de forma predeterminada (`ENABLE_AI_TRIAGE=false`).
2. **Activación deliberada**: El análisis mediante IA solo se ejecuta si el usuario u
   operador otorga su consentimiento explícito a través de:
   - La casilla de verificación *«Habilitar Triage con IA»* en la interfaz web.
   - El parámetro booleano `"enable_ai_triage": true` en las peticiones a la API (`POST /api/analyze`).
   - La variable de entorno `ENABLE_AI_TRIAGE=true` en despliegues automatizados.
3. **Modo estándar sin IA**: Si no se otorga consentimiento, el motor ejecuta el escaneo
   completo de forma 100% determinista local (Semgrep + Gitleaks + reglas locales),
   marcando las decisiones con `decided_by: "regla"`.

---

## 2. Proveedores de Modelos y Políticas de Retención (Control C12 y Anexo B)

Cuando se activa el triage asistido, las solicitudes se canalizan hacia proveedores
con acuerdos empresariales de confidencialidad:

### Proveedor Principal: Google Gemini API / Google Cloud Vertex AI
- **Acuerdo de privacidad**: Términos de Servicio Empresariales de Google Cloud / Vertex AI.
- **Política de retención (Zero Data Retention)**: Los datos transmitidos (prompts y
  respuestas) **NO se utilizan para entrenar**, perfeccionar ni mejorar modelos de lenguaje
  de Google ni de terceros.
- **Ciclo de vida de los datos**: El procesamiento ocurre de manera efímera en memoria
  durante la inferencia y no se almacena en bases de datos del proveedor.
- **Cifrado en tránsito y en reposo**: Comunicaciones cifradas mediante TLS 1.3 con
  certificados verificados.

### Proveedores Opcionales: OpenAI API / Anthropic Claude
- Si la organización opta por configurar endpoints de OpenAI o Anthropic en el proxy F8,
  deben utilizarse cuentas de nivel **Enterprise / Business API**, las cuales garantizan
  por contrato que las llamadas a la API están excluidas del entrenamiento de modelos (Zero Data Training Policy).

---

## 3. Medidas Técnicas de Protección del Código Fuente

Para garantizar que el código del repositorio nunca sea expuesto indiscriminadamente:

```
[ Código del Repositorio ]
          │
          ▼
1. Extracción acotada (máximo 20 líneas centradas en la alerta)
          │
          ▼
2. Redacción criptográfica (API keys, JWT, passwords -> [REDACTED_SECRET])
          │
          ▼
3. Envoltorio no ejecutable (<CODE_DATA> ... </CODE_DATA>)
          │
          ▼
4. Tránsito por Proxy F8 (auditoría sin payloads, inyección de clave sin exposición)
          │
          ▼
[ Inferencia Efímera en Proveedor ]
```

1. **Contexto estrictamente acotado**: El agente **nunca envía archivos completos ni el árbol
   del proyecto**. Únicamente extrae una ventana de **hasta 20 líneas** centradas en la línea
   exacta del hallazgo, suficiente para determinar el flujo de la variable.
2. **Redacción estricta de secretos**: Todo fragmento de código extraído se procesa antes de
   su envío mediante filtros de expresiones regulares para sustituir contraseñas, tokens JWT,
   credenciales de nube (AWS, Google, GitHub, GitLab) y Bearer tokens por la constante
   `[REDACTED_SECRET]`.
3. **Código como dato no ejecutable (Inyección indirecta neutralizada)**: El extracto se
   encapsula dentro de etiquetas delimitadoras `<CODE_DATA>` y el prompt del sistema
   instruye explícitamente al modelo a tratar el código como datos no confiables para
   análisis pasivo, prohibiendo acatar instrucciones o comandos contenidos en comentarios o
   cadenas del código analizado.
4. **Proxy intermedio de aislamiento (F8)**: Los agentes del backend no poseen claves de
   proveedores. Se comunican con el reverse proxy interno mediante tokens con hash SHA-256.
   La bitácora de auditoría registra timestamp, token_id, servicio y resultado, **omitiendo
   cuerpos y secretos** (validado en pruebas con Gitleaks).

---

## 4. Comparativa con Herramientas de la Industria (Arnica, Aikido, Snyk)

En relación a la comparativa solicitada con plataformas comerciales de DevSecOps:

> **Nota sobre accesos**: Al no disponerse de credenciales ni instancias activas en los
> entornos corporativos de **Arnica** o **Aikido Security** durante esta fase, se adoptó
> una arquitectura basada en **herramientas y principios equivalentes de la industria**:

| Capacidad | Plataformas Comerciales (Arnica / Aikido) | Security Control Center (Implementación) |
| :--- | :--- | :--- |
| **Escaneo unificado (SAST + Secrets + SCA)** | Orquestación centralizada de motores abiertos y propietarios en un pipeline único. | Integración nativa de Semgrep (SAST), Gitleaks (Secrets con historial), Syft (SBOM), y Scorecard en [`backend/scanner_tools.py`](file:///home/productdeath/Documentos/UNIVERSAL/UNI/ESTADIA/HUGO/NEUROTRY/demo-seguridad/backend/scanner_tools.py). |
| **Reducción de ruido con IA** | Modelos LLM propietarios para descartar falsos positivos en base al contexto. | Agente de triage acotado ([`backend/triage_agent.py`](file:///home/productdeath/Documentos/UNIVERSAL/UNI/ESTADIA/HUGO/NEUROTRY/demo-seguridad/backend/triage_agent.py)) con reducción medida del FPR de hasta ~48% y caché persistente de huellas (`known_false_positives.json`). |
| **Auto-remediación verificada** | Generación de pull requests automáticos con sugerencias de código. | Agente de corrección ([`backend/fixer_agent.py`](file:///home/productdeath/Documentos/UNIVERSAL/UNI/ESTADIA/HUGO/NEUROTRY/demo-seguridad/backend/fixer_agent.py)) con diffs unificados mínimos, validación en ramas temporales aisladas sin push a `main`, y descarte automático si surgen nuevas alertas. |
| **Privacidad de credenciales** | Secret brokers empresariales y pasarelas de red. | Proxy inverso de secretos F8 ([`backend/proxy/`](file:///home/productdeath/Documentos/UNIVERSAL/UNI/ESTADIA/HUGO/NEUROTRY/demo-seguridad/backend/proxy/)) con tokens SHA-256, listas blancas y auditoría JSONL redactada. |
| **Evaluación continua de precisión** | Métricas internas de eficacia no siempre públicas. | Módulo de benchmark reproducible ([`backend/bench/`](file:///home/productdeath/Documentos/UNIVERSAL/UNI/ESTADIA/HUGO/NEUROTRY/demo-seguridad/backend/bench/)) con repositorio reservado holdout (OWASP Benchmark) documentado en [`docs/resultados-benchmark.md`](file:///home/productdeath/Documentos/UNIVERSAL/UNI/ESTADIA/HUGO/NEUROTRY/demo-seguridad/docs/resultados-benchmark.md). |
