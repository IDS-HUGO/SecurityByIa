# Guía: cómo se clasifica la severidad

La severidad de cada hallazgo la calcula `backend/severity_engine.py`
(`calculate_finding_severity`), un motor **contextual** por puntos: no se limita
a la severidad cruda de la herramienta, sino que combina inventario de
controles, CVSS, exposición del archivo y confianza.

---

## 1. Niveles y SLA

Niveles: `critical`, `high`, `medium`, `low` (no existe `info`).
SLA de remediación (`_REMEDIATION_DEADLINES`, Control 6):

| Severidad | Plazo |
| :--- | :--- |
| critical | 48 horas |
| high | 30 días |
| medium | 90 días |
| low | 180 días |

---

## 2. Cálculo del score (0–100)

1. **Base por inventario de controles**: si el hallazgo matchea el inventario
   (`data/controls_inventory.json`, p. ej. CTRL-01 → base 70 pts), se usa esa
   base; si no, la severidad cruda de la herramienta.
2. **Ajuste por severidad reportada**: critical +15, high +8, low −10.
3. **Ajustes por tipo**:
   - Secretos: verificación `VALID` +25, `INVALID` −15.
   - Dependencias con CVSS: ≥9.0 +25, ≥7.0 +15, ≥4.0 +5, sin CVSS −10.
   - Código: RCE/SQLi/inyección +15; XSS/traversal/deserialización +8.
4. **Exposición del archivo** (`_detect_file_exposure`): en `tests/` −25;
   en módulos de autenticación +15; en rutas HTTP +12; en IaC +5.
5. **Confianza** de la detección: high +5, low −10.

Mapeo final del score: `≥75` → critical, `≥50` → high, `≥25` → medium,
si no → low. La función devuelve `(severity, severity_reason, deadline)`;
el motivo textual queda en `finding.severity_reason` y el plazo en
`finding.remediation_deadline`.

---

## 3. Límites del ajuste por IA

El enriquecimiento con modelos (Gemini, vía proxy F8) puede proponer un cambio
de severidad, pero `validate_model_severity_change` lo acota: máximo 1 nivel y
justificación de al menos 5 caracteres; si no, se conserva la severidad del
motor. Cualquier fallo del modelo es fail-open: no altera el resultado.

---

## 4. Categorización OWASP

Cada hallazgo lleva su categoría OWASP 2021 resuelta por CWE con el catálogo
`data/cwe_owasp_2021.json` (`resolve_owasp_category`). El campo `owasp` se usa
en el dashboard, en el reporte y en la guía de buenas prácticas del agente
redactor (F9), que agrupa exclusivamente por las categorías realmente presentes.

---

## 5. Verificación

```bash
python -m pytest backend/tests/ -v
```

Las pruebas de severidad cubren los cortes de score, la exposición de archivos
(`tests/` baja, `auth`/HTTP sube) y el techo del ajuste IA.
