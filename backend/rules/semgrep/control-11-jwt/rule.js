// Control 11 (inventario v1.0): tokens JWT de duración corta (15-30 minutos)

// Caso que debe detectar: expiración de días
// ruleid: js-jwt-long-exp-ctl11
const t1 = jwt.sign(payload, key, { expiresIn: "30d" });

// Caso que debe detectar: decode sin verificación de firma
// ruleid: js-jwt-unverified-decode-ctl11
const c1 = jwt.decode(token);

// Casos seguros: 15-30 minutos y verificación con aud/iss
const t2 = jwt.sign(payload, key, { expiresIn: "20m" });
const c2 = jwt.verify(token, key, { audience: "api://app", issuer: "https://idp.example.com" });
