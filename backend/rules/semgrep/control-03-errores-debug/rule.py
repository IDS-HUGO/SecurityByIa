# Casos que deben detectar (Control 3)
DEBUG = True  # ruleid: py-django-debug-true-ctl3
app.run(host="0.0.0.0", debug=True)  # ruleid: py-flask-debug-true-ctl3

@app.get("/items")
def get_item(item_id: int):
    try:
        return db.get(item_id)
    except Exception as exc:
        return jsonify(str(exc))  # ruleid: py-error-detail-response-ctl3
    raise HTTPException(status_code=500, detail=str(exc))  # ruleid: py-error-detail-response-ctl3

# Casos seguros: DEBUG fuera y mensaje genérico con id de correlación
DEBUG = False
app.run(host="0.0.0.0")

@app.get("/items-safe")
def get_item_safe(item_id: int):
    try:
        return db.get(item_id)
    except Exception:
        logger.exception("fallo al obtener item")  # detalle solo a logs internos
        return jsonify({"error": "Error interno", "correlation_id": corr_id})
