"""Verificador Nube para Control C9: Auditoría centralizada con CloudTrail."""

import json
from typing import Any, Callable, Dict
from ..base import ResultadoVerificacion, redactar_secretos

CONTROL_ID = "C9"
NOMBRE = "Auditoría de infraestructura centralizada (CloudTrail y MFA de root)"


def verificar_cloudtrail(
    ejecutor: Callable[[str], Dict[str, Any]],
    target: str = "aws",
) -> ResultadoVerificacion:
    """Ejecuta aws cloudtrail describe-trails para verificar trails multirregión activos."""
    cmd = "aws cloudtrail describe-trails --output json"
    resp = ejecutor(cmd)

    if resp.get("status") != "ok" or resp.get("exit_code") != 0:
        err = resp.get("stderr") or resp.get("error") or "Fallo de ejecución o credenciales no configuradas"
        return ResultadoVerificacion(
            control_id=CONTROL_ID,
            nombre=NOMBRE,
            modo="nube",
            estado="requiere evidencia",
            detalles=f"No se pudo consultar la configuración de CloudTrail ({err}); requiere evidencia.",
            evidencia=f"Comando: {cmd}\nSalida: {resp.get('stdout', '')}\nError: {err}",
            objetivo=target,
        )

    stdout = resp.get("stdout", "").strip()
    try:
        data = json.loads(stdout)
    except Exception:
        data = None

    trail_list = (data.get("trailList") if isinstance(data, dict) else []) or []
    evidencia_texto = f"Comando: {cmd}\nTrails de auditoría detectados ({len(trail_list)}):\n{json.dumps(trail_list, indent=2)}"

    if not trail_list:
        estado = "no cumple"
        detalles = "No se detectaron pistas de auditoría (trails) de CloudTrail configuradas en la cuenta."
    else:
        multiregion = [t for t in trail_list if t.get("IsMultiRegionTrail") is True]
        if multiregion:
            estado = "cumple"
            detalles = f"CloudTrail configurado y activo con {len(multiregion)} pista(s) multirregión."
        else:
            estado = "parcial"
            detalles = f"CloudTrail configurado ({len(trail_list)} trails), pero ninguno es multirregión."

    return ResultadoVerificacion(
        control_id=CONTROL_ID,
        nombre=NOMBRE,
        modo="nube",
        estado=estado,
        detalles=detalles,
        evidencia=evidencia_texto,
        objetivo=target,
    )
