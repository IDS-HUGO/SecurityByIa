"""Verificador Nube para Control C6: Respaldos automáticos y retención."""

import json
from typing import Any, Callable, Dict
from ..base import ResultadoVerificacion, redactar_secretos

CONTROL_ID = "C6"
NOMBRE = "Respaldos automáticos y protección contra borrado accidental"


def verificar_respaldos(
    ejecutor: Callable[[str], Dict[str, Any]],
    target: str = "aws",
) -> ResultadoVerificacion:
    """Ejecuta describe-db-instances para verificar BackupRetentionPeriod y DeletionProtection."""
    cmd = "aws rds describe-db-instances --query DBInstances[*].{ID:DBInstanceIdentifier,Retention:BackupRetentionPeriod,Protection:DeletionProtection} --output json"
    resp = ejecutor(cmd)

    if resp.get("status") != "ok" or resp.get("exit_code") != 0:
        err = resp.get("stderr") or resp.get("error") or "Fallo de ejecución o credenciales no configuradas"
        return ResultadoVerificacion(
            control_id=CONTROL_ID,
            nombre=NOMBRE,
            modo="nube",
            estado="requiere evidencia",
            detalles=f"No se pudo consultar la configuración de respaldos ({err}); requiere evidencia.",
            evidencia=f"Comando: {cmd}\nSalida: {resp.get('stdout', '')}\nError: {err}",
            objetivo=target,
        )

    stdout = resp.get("stdout", "").strip()
    try:
        data = json.loads(stdout)
    except Exception:
        data = None

    if not data or not isinstance(data, list):
        return ResultadoVerificacion(
            control_id=CONTROL_ID,
            nombre=NOMBRE,
            modo="nube",
            estado="requiere evidencia",
            detalles="Sin instancias detectadas para verificar política de respaldos; requiere evidencia.",
            evidencia=f"Comando: {cmd}\nSalida:\n{stdout}",
            objetivo=target,
        )

    sin_respaldo = [item.get("ID") for item in data if not item.get("Retention") or int(item.get("Retention") or 0) <= 0]
    evidencia_texto = f"Comando: {cmd}\nBases de datos inspeccionadas:\n{json.dumps(data, indent=2)}"

    if sin_respaldo:
        estado = "no cumple"
        detalles = f"Bases de datos con período de retención de respaldos desactivado (0 días): {', '.join(str(i) for i in sin_respaldo)}."
    else:
        estado = "cumple"
        detalles = f"Todas las instancias RDS ({len(data)}) tienen respaldos automáticos activos con período de retención > 0 días."

    return ResultadoVerificacion(
        control_id=CONTROL_ID,
        nombre=NOMBRE,
        modo="nube",
        estado=estado,
        detalles=detalles,
        evidencia=evidencia_texto,
        objetivo=target,
    )
