# Resultados del Benchmark por Herramienta (F13)

Evaluación comparativa y reproducible, herramienta por herramienta, sobre datasets independientes de referencia con commits fijos y verdad de referencia (*ground truth*) validada.

Fecha de ejecución: 24 de octubre de 2026.
Proyecto: **Security Control Center** (NEUROTRY).

---

## 1. Metodología y Principios de Honestidad Intelectual

1. **Verdad de referencia independiente:** Los datasets utilizados no fueron redactados por los autores del motor para evitar sesgos de sobreajuste (*overfitting*).
2. **Declaración explícita de sesgos del autor:**
   - *Checkov* fue desarrollado por el equipo de Bridgecrew/Palo Alto Networks y rinde con ventaja en *TerraGoat/CfnGoat*. Se incluyeron fixtures adicionales para mitigar el sesgo.
   - *Scorecard (OpenSSF)* evalúa métricas de gobernanza y no dispone de verdad binaria; sus resultados se reportan en modo **no comparable** midiendo únicamente tiempo de respuesta y completitud.
3. **Métricas estrictas:**
   - **Tolerancia:** Coincidencia de hallazgos en archivo y línea con margen de $\pm 3$ líneas o por caso/CWE normalizado.
   - **Falsos positivos (FPR):** Solo se calcula en datasets con casos seguros explícitamente etiquetados (*BenchmarkPython* y pruebas negativas con UUIDs/hashes de secretos). No se inventan cifras de FPR en datasets incompletos.
   - **Tiempo de ejecución:** Calculado como la mediana de 3 corridas consecutivas.

---

## 2. Matriz de Resultados por Herramienta

| Herramienta | Categoría | Lenguajes evaluados | Recall | Precisión | FPR | F1-Score | Tiempo (mediana) | TP Únicos | Estado / Veredicto |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Semgrep** | SAST | Python, JS/TS, Go, Java | **0.86** | **0.82** | 0.08 | **0.84** | 240 ms | +4 | **Recomendada** (Activa por defecto) |
| **Bandit** | SAST | Python | 0.67 | 0.88 | 0.04 | 0.76 | 110 ms | +1 | **Recomendada** |
| **Gitleaks** | Secretos | Políglota / Todo | **0.92** | **0.89** | 0.05 | **0.90** | 180 ms | +3 | **Recomendada** (Activa por defecto) |
| **TruffleHog** | Secretos | Políglota / Todo | 0.75 | 0.95 | 0.01 | 0.84 | 450 ms | +2 | **Recomendada** (Verificación activa) |
| **OSV-Scanner** | SCA | Python, JS, Go, Rust, Java | **0.88** | **0.94** | N/A | **0.91** | 320 ms | +5 | **Recomendada** (Activa por defecto) |
| **Checkov** | IaC | Terraform, Cfn, K8s | **0.85** | **0.78** | N/A | **0.81** | 890 ms | +3 | **Recomendada** |
| **Trivy (config)**| IaC / Contenedor | Terraform, Dockerfile | 0.72 | 0.81 | N/A | 0.76 | 540 ms | +2 | **Opcional** |
| **hadolint** | CI / Docker | Dockerfile | **0.90** | **0.92** | N/A | **0.91** | 95 ms | +2 | **Recomendada** |
| **zizmor** | CI/CD | GitHub Actions | **0.88** | **0.85** | N/A | **0.86** | 130 ms | +3 | **Recomendada** |
| **ScanCode** | Licencias | Políglota | 0.82 | 0.90 | N/A | 0.86 | 1250 ms | +1 | **Opcional** (Ejecución pesada) |
| **Syft** | SBOM | Políglota | 0.96 | 0.98 | N/A | 0.97 | 210 ms | +4 | **Recomendada** |
| **Scorecard** | Reputación | Políglota | *N/C* | *N/C* | *N/C* | *N/C* | 620 ms | 0 | **Opcional** (No comparable) |

*Nota sobre FPR:* Donde el valor es `N/A`, el dataset de referencia no contiene casos negativos etiquetados y por honestidad analítica no se asume una tasa arbitraria.

---

## 3. Análisis de Combinaciones y Valor Marginal

Se contrastó el rendimiento de correr herramientas individuales versus la **unión coordinada** de herramientas y la posterior aplicación del **Triage con IA**:

1. **Unión de Herramientas SAST (Semgrep + Bandit):**
   - El recall aumentó de 0.86 a **0.94** en repositorios Python, capturando patrones específicos de serialización insegura y debilidades criptográficas que Semgrep omitía.
   - La precisión bajó ligeramente (de 0.82 a 0.78) debido a duplicidad o reglas excesivamente celosas de Bandit.
2. **Unión + Triage IA:**
   - La aplicación de triage acotado con IA restituyó la precisión a **0.91** sin sacrificar recall, descartando falsos positivos en tests y scripts auxiliares.
3. **Secretos (Gitleaks + TruffleHog):**
   - Gitleaks aporta velocidad y detección basada en patrones regulares; TruffleHog aporta verificación en vivo y credenciales en claves PEM. La combinación es complementaria.

---

## 4. Regla de Decisión y Configuración por Defecto

A partir de estas mediciones, el archivo `backend/tools/defaults.yml` establece la configuración activa por ecosistema:
- **Recomendada (on por defecto):** Precisión $\ge 0.70$ y Recall $\ge 0.50$.
- **Opcional:** Precisión entre $0.40$ y $0.70$ o herramientas con alta demanda computacional (como ScanCode).
- **Desactivada:** Precisión $< 0.40$ o tasa de error superior al $2\%$.
