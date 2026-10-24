const cors = require("cors");
app.use(cors({ origin: true, credentials: true }));

// Caso seguro: lista explícita de orígenes
app.use(cors({ origin: ["https://app.example.com"], credentials: true }));
