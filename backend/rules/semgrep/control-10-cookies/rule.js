// Casos que deben detectar (Control 10)
localStorage.setItem("auth_token", token); // ruleid: js-localstorage-token-ctl10
document.cookie = "session=" + sessionToken; // ruleid: js-document-cookie-session-ctl10

// Caso seguro: la sesión la maneja el backend con Set-Cookie flags; nada sensible en storage
localStorage.setItem("theme", "dark");
