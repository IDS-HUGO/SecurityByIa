// Caso que debe detectar (Control 3): stack/exception hacia el cliente
app.use((err, req, res, next) => {
  res.status(500).send(err.stack); // ruleid: js-error-stack-response-ctl3
});

// Caso seguro: mensaje genérico; el detalle va a logs
app.use((err, req, res, next) => {
  logger.error("unhandled error", { stack: err.stack, correlationId: req.id });
  res.status(500).send({ error: "Error interno", correlationId: req.id });
});
