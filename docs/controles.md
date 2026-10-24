# Revisión por control con IA (Inventario de Controles de Seguridad v1.0)

La plataforma evalúa los 35 controles del inventario (1 a 22 y C1 a C13) sobre
cada análisis, combinando un agente revisor que **solo lee** con las señales
exactas que las reglas Semgrep propias detectan.

---

## 1. Especificaciones (`backend/controls/specs/`)

Una especificación YAML por control, con los campos del esquema: `id`, `nombre`,
`categoria_owasp`, `criticidad_referencia`, `familia`, `metodo` (`repo`,
`en_vivo`, `nube` o `evidencia`), `donde_buscar` (patrones de archivo),
`senales_incumplimiento`, `falsos_positivos`, `herramientas`, `ia_revisa`,
`remediacion`, `verificacion`, `criterio_aceptacion` y `fragmentos_regex` (para
acotar los fragmentos de evidencia). El texto proviene del inventario v1.0; los
C1–C13 son `COMPLEMENTARIO` y C10–C13 declaran `aplica_con_llm: true`.

El cargador (`controls/spec_loader.py`) valida el esquema estricto (35 specs,
ids exactos, regex compilables) y detecta de forma determinista si el repo usa
un SDK de modelos de lenguaje (tokens de `openai`, `anthropic`, `langchain`,
etc. en manifiestos). **C10–C13 solo aplican con SDK de LLM**: si no, quedan en
`no aplica` con la justificación registrada en el resultado.

## 2. Paquete de evidencia determinista (`controls/evidence_builder.py`)

Sin modelos de por medio: detecta el stack, localiza los archivos de
"dónde buscar" con los globs de la especificación, extrae fragmentos acotados
(ventanas de ±12 líneas alrededor de las coincidencias de `fragmentos_regex`)
y enumera endpoints, rutas y recursos (FastAPI, Flask, Django, Express, Nest,
Next). Todo se recorta a un tope de tokens (`SECURITY_CONTROLS_EVIDENCE_TOKENS`,
default 6000, ~chars/4) marcando `truncado`.

## 3. Agente revisor (`controls/reviewer_agent.py`)

- **Solo lee**: nunca ejecuta nada del repositorio; el fragmento viaja
  delimitado como datos (`<EVIDENCE_DATA_EXCERPTS>`) con la prohibición explícita
  de tratarlo como instrucciones.
- **Salida validada contra esquema estricto**: `estado` (`cumple`, `parcial`,
  `no cumple`, `no aplica`), `evidencia` (máx. 8 citas con `archivo`, `linea`,
  `fragmento`), `razonamiento` (20–600 chars) y `confianza` (0.0–1.0).
- **Verificación de líneas citadas**: antes de aceptar la respuesta se comprueba
  que cada línea citada existe en el archivo del paquete y que el fragmento
  corresponde a esa línea. **Si cualquier cita no verifica, la respuesta
  completa se descarta** y se reintenta; tras el segundo fallo queda
  `descartado` y va a la cola Por revisar.
- Sale a los proveedores por el proxy de secretos (F8) o con la clave del
  entorno; reutiliza la capa de modelos de `triage_agent`.

## 4. Orquestación (`controls/review_service.py`)

- **Opt-in**: `ENABLE_CONTROLS_REVIEW=true` (por defecto desactivada).
- **RBAC (12) e IDOR (C2)**: el agente juzga **un endpoint a la vez** con un
  paquete centrado en su declaración; la **cobertura** se calcula como
  endpoints revisados sobre endpoints totales (muestreo con tope
  `CONTROLS_MAX_ENDPOINTS_REVIEW`, default 20).
- **Cruce con scanners**: los hallazgos de scanners cuya regla declara
  `metadata.control` se cruzan con el veredicto: las coincidencias suben la
  confianza (+0.15, `scanner+agente`) y lo detectado **solo por el agente**
  (`solo_agente`) va a la cola Por revisar; un `cumple` del agente con
  hallazgos de scanners queda en conflicto y también requiere revisión humana.
- Controles de método `nube`/`evidencia` sin archivos en el repo quedan
  `no_evaluado` (Por revisar) en vez de inventar un veredicto.

## 5. Reglas Semgrep por control (`backend/rules/semgrep/`)

Una carpeta por control con las señales exactas del inventario: CORS con
comodín y credenciales (1), sinks de HTML crudo y SQL por concatenación (2),
DEBUG activo y detalle de excepciones en respuestas (3), endpoints costosos
sin rate limit (7), cookies con flags desactivados y tokens en localStorage
(10), JWT con expiración larga o sin aud/iss (11), SSRF a URLs de usuario
(C4), registro de tokens o contraseñas (C7) y llamadas a modelos sin límite
de tokens (C13). Cada regla lleva `metadata.control` con el número del
inventario, cubre los lenguajes que Semgrep soporta (Python, Django, Flask,
FastAPI, JavaScript/Express/React/Vue/Angular, genérico) y trae archivos de
prueba (`rule.py`, `rule.js`, `rule.jsx`) con caso detectable (`# ruleid:`) y
caso seguro. Las señales de omisión no expresables en Semgrep quedan como
`# no-semgrep:` en el YAML y las cubre el agente.

El analyzer carga estas reglas junto a `rules/security-rules.yml` y al registry
`p/owasp-top-ten`, y cada hallazgo incorpora el `control` en sus metadatos para
el cruce.

## 6. Medición con el benchmark (`bench/examples/controls-bench/`)

Repo sintético con **15 violaciones conocidas del inventario** (CWE-942 CORS,
CWE-89 SQLi, CWE-489 DEBUG, CWE-770 rate limit y LLM, CWE-1004 cookies,
CWE-613 JWT, CWE-918 SSRF, CWE-532 logs, CWE-1104 ausencia de Dependabot) más
gemelos seguros para medir FPR. Corrida de referencia (Semgrep 1.182.1):

| Corrida | TP | FP | FN | Recall | FPR |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Sin reglas de controles | 6 | 1 | 9 | 40.0% | 14.3% |
| Con reglas de controles | 15 | 1 | 0 | 100.0% | 6.2% |

Las reglas nuevas suben el recall +60 puntos **sin sumar ni un falso positivo**
(mismo único FP del registry en ambas corridas). Para reproducir:

```bash
cd backend
SEMGREP_PATH=$PWD/.venv/bin/semgrep .venv/bin/python bench/benchmark.py \
  --repo-ids repo-controles-violaciones --feature controles-v1.0
# Y sin las reglas propias (renombrando rules/semgrep fuera) para comparar.
```

## 7. API y dashboard

- `GET /api/controls` — las 35 especificaciones.
- `GET /api/analysis/<id>/controls` — la revisión del análisis (estado,
  evidencia con archivo y línea, confianza, cobertura); sin revisión almacenada
  responde `disponible: false` con el motivo, **nunca** fabrica veredictos.
- `POST /api/analysis/<id>/controls/review` — re-derivación honesta desde el
  análisis guardado (solo scanners: `no cumple` con evidencia real para los
  controles con hallazgos, `no_evaluado` para el resto).
- Pestaña **Controles** del dashboard: hoja de registro con encabezado
  (aplicación, fecha de revisión, revisor, commit revisado), una fila por
  control (número, control, criticidad, estado, evidencia con enlace a
  `archivo#Llínea`), filtros por estado y familia, marca "solo agente" cuando
  el veredicto no tiene corroboración de scanners, y estados de carga, vacío
  y error.

## 8. Pruebas

```bash
python -m pytest backend/tests/test_controls.py -v
```

Cubren: esquema de las 35 specs, detección de SDK de LLM, evidencia
determinista y su tope de tokens, enumeración de endpoints, verificación y
descarte de citas del agente, gating de C10–C13, cobertura RBAC/IDOR, cruce
con scanners, endpoints de API, estructura de las reglas Semgrep e integridad
del ground truth. Las reglas se validan con `semgrep --test rules/semgrep/`
(9/9 carpetas) y el benchmark mide recall/FPR del conjunto.
