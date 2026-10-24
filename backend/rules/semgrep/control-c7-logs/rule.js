// Control C7 (inventario v1.0): datos sensibles en logs y trazas

// Caso que debe detectar: token en log
// ruleid: js-log-sensitive-ctl7
console.log("req con bearer token:", authorization);

// Caso que debe detectar: password interpolada en la traza
// ruleid: js-log-sensitive-ctl7
logger.error(`fallo autenticando a ${password}`);

// Casos seguros: sin valores sensibles
console.log("req procesada para user", userId);
logger.error("fallo de autenticación", { userId });
