// Control 4 (inventario v1.0): SSRF — el servidor llama a URLs que controla el usuario

// Caso que debe detectar: fetch del servidor a una URL variable (webhook)
// ruleid: js-fetch-variable-url-ctl4
await fetch(webhookUrl, { method: "POST", body });

// Caso que debe detectar: axios.post a variable target
// ruleid: js-fetch-variable-url-ctl4
await axios.post(targetUrl, payload);

// Caso seguro: destino fijo de la allowlist
await fetch(WEBHOOK, { method: "POST", body });
