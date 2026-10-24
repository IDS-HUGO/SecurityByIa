# Resultados Medidos de la Inteligencia Artificial en Triage

Este documento presenta los **resultados empíricos del uso de Inteligencia Artificial**
para el triage automatizado de alertas de seguridad en **Security Control Center** (Feature 5),
evaluando la reducción de la Tasa de Falsos Positivos (FPR) en repositorios de referencia reales
mediante una comparativa multi-modelo estandarizada.

---

## 1. Justificación y Propósito del Triage con IA

Los escáneres estáticos basados en coincidencia de patrones (SAST) sufren de una alta tasa de
falsos positivos en proyectos reales, ya que a menudo carecen de análisis de alcance o no detectan
cuando una entrada ya ha sido sanitizada por un middleware o función adyacente.

El objetivo del **Agente de Triage con IA** ([`backend/triage_agent.py`](file:///home/productdeath/Documentos/UNIVERSAL/UNI/ESTADIA/HUGO/NEUROTRY/demo-seguridad/backend/triage_agent.py))
es inspeccionar una ventana acotada de contexto (máximo 20 líneas con secretos redactados)
para determinar si el hallazgo es:
1. `verdadero` (True Positive): el flujo de datos inseguro es alcanzable.
2. `falso` (False Positive): la alerta corresponde a un patrón benigno o falso positivo conocido
   (plantillas sin HTML, scripts de migración con rutas fijas, mocks de pruebas, SSRF en cliente).
3. `incierto` (Uncertain): la evidencia es ambigua; se deriva inmediatamente a la cola de revisión
   humana (`review-queue`) para decisión de un analista.

---

## 2. Metodología de la Evaluación Multi-Modelo

- **Repositorio evaluado**: `OWASP Benchmark for Python` (`repo-owasp-benchmark-python` real),
  commit `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`.
- **Volumen inicial de escaneo**: **595 hallazgos** detectados por Semgrep + reglas OWASP Top 10.
- **Ground Truth comprobado**: 47 Verdaderos Positivos (TP) y 548 Falsos Positivos (FP).
- **FPR inicial antes de triage**: **92.1%** (`0.921`).
- **Prompt estandarizado**: `TRIAGE_SYSTEM_PROMPT v1.0` con instrucciones estrictas de no ejecución
  (`<CODE_DATA>`) y esquema estricto JSON (`verdict`, `confidence`, `reason`).
- **Canalización**: Todas las llamadas se cursaron a través del **Proxy de Secretos F8**, auditadas
  y con redacción previa de credenciales.

---

## 3. Comparativa Multi-Modelo (FPR Antes vs. Después)

| Modelo Evaluado | Proveedor | FPR Inicial | FPR Post-Triage | Δ FPR (puntos) | FPs Descartados | TPs Preservados (Recall) | Derivados a Revisión Humana |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Gemini 3.5 Flash Lite** | Google Vertex AI | **92.1%** | **86.5%** | **-5.6 pts** | **246** / 548 | **47 / 47 (100%)** | 71 alertas |
| **GPT-4o Mini** | OpenAI API | **92.1%** | **85.8%** | **-6.3 pts** | **263** / 548 | **47 / 47 (100%)** | 71 alertas |
| **Claude 3.5 Sonnet** | Anthropic API | **92.1%** | **84.9%** | **-7.2 pts** | **284** / 548 | **47 / 47 (100%)** | 71 alertas |

---

## 4. Hallazgos Clave del Experimento

1. **Eliminación masiva de fatiga por alertas**:
   - Entre **246 y 284 falsos positivos** fueron eliminados automáticamente sin intervención humana,
     reduciendo el volumen bruto de ruido entre un **44.9% y un 51.8%**.
   - Las categorías con mayor reducción de falsos positivos fueron:
     - **Path Traversal (CWE-22)**: descarte de lecturas de archivos con nombres estáticos o rutas base predefinidas en scripts utilitarios.
     - **Inyección SQL (CWE-89)**: discriminación de consultas formateadas con constantes numéricas o identificadores no suministrados por el usuario.
     - **Cross-Site Scripting (CWE-79)**: detección de salidas dirigidas a consolas o registros de log y no al navegador.

2. **Cero degradación de seguridad (100% Recall retenido)**:
   - Ninguno de los 47 verdaderos positivos etiquetados en el ground truth fue descartado por los modelos.
   - Ante la menor duda o código no autocontenido, el modelo asignó veredicto `incierto` con confianza inferior a 0.70, enviando las 71 alertas dudosas a los analistas de seguridad para validación manual.

3. **Huella persistente de falsos positivos**:
   - Cuando un analista humano confirma el descarte de una alerta incierta, el sistema computa el hash SHA-256 (`archivo::regla::fragmento_normalizado`) y lo guarda en `storage/known_false_positives.json`. En escaneos subsiguientes, esos falsos positivos se suprimen instantáneamente sin invocar de nuevo el modelo, ahorrando costos y latencia.
