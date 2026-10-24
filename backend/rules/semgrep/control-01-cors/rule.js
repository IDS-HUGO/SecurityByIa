// Control 1 (inventario v1.0): CORS minimizado solo orígenes confiables
const cors = require("cors");

// Caso que debe detectar: refleja cualquier origen y habilita credenciales
// ruleid: js-express-cors-credentials-ctl1
app.use(cors({ origin: true, credentials: true }));

// Caso seguro: lista explícita de orígenes confiables
app.use(cors({ origin: ["https://app.example.com"], credentials: true }));
