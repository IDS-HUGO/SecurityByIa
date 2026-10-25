# Preguntas Abiertas y Decisiones Técnicas (24 de Octubre de 2026)

Este documento registra las dudas y decisiones operativas para revisión con el equipo y Carlos (NEUROTRY):

---

## 1. Credenciales de Agentes y Acceso Delegado (F12)

1. **Gestor de Contraseñas Corporativo:**
   - *Decisión tomada para el MVP:* Se implementó `EncryptedFileVault` (cifrado local simétrico con permisos 0600) y `FakeVault` para pruebas, junto con adaptadores desacoplados para `BitwardenCliVault` y `OnePasswordCliVault`.
   - *Pregunta para Carlos:* ¿Cuál es el gestor oficial que utiliza NEUROTRY para sus cuentas de servicio y entornos de staging (1Password, Bitwarden u otro)? ¿Se provisionará una Service Account dedicada?

2. **Resolución de Segundo Factor (MFA):**
   - *Decisión tomada:* El broker incluye generador autónomo de TOTP RFC 6238 en el componente de confianza si se provee la semilla Base32. Si el sitio exige aprobación push o hardware token, se detiene el flujo y se solicita intervención humana en la bandeja de aprobación.
   - *Pregunta para Carlos:* ¿Se admitirán cuentas de auditoría con semilla TOTP compartida o se requerirá modo de toma de control (*takeover*) para todos los logins?

3. **Ejecución de Navegador (Headless Workers):**
   - *Decisión tomada:* Se implementó el handshake HTTP/DOM con verificación estricta de origen (`OriginMismatchError`) y redacción garantizada ante fallos (`fields_cleared`).
   - *Pregunta para Carlos:* ¿Los workers de navegación correrán en contenedores Docker dedicados con Playwright (`--network none` salvo hacia el objetivo) o como servicios en el host?

---

## 2. Benchmark por Herramienta (F13)

1. **Categorías sin verdad de referencia absoluta:**
   - *Decisión tomada:* Siguiendo los principios de honestidad intelectual, OpenSSF Scorecard se etiquetó como **no comparable** midiendo únicamente tiempo de respuesta y completitud.
   - *Ajuste:* Las métricas se guardan con su hash de commit del dataset en `backend/bench/tools/datasets.yml`.

2. **Umbrales de Clasificación de Herramientas:**
   - *Decisión tomada:* Se aplicó la regla de decisión: Recomendada (precisión $\ge 0.70$), Opcional ($0.40 - 0.70$) y Desactivada ($< 0.40$). La configuración por defecto se autogenera en `backend/tools/defaults.yml`.

---

## 3. Cobertura Políglota (F14)

1. **Lenguajes con Cobertura Parcial:**
   - *Decisión tomada:* Cuando un repositorio contiene lenguajes sin herramienta SAST dedicada (por ejemplo Elixir o Dart), el análisis finaliza en `completed_with_gaps` y la interfaz y reportes (Markdown y SARIF) destacan la advertencia sugiriendo la revisión asistida con IA como cubierta complementaria. Nunca se reporta falsamente "limpio".
