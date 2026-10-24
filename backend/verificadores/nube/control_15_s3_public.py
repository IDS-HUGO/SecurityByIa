"""Verificador Nube para Control 15: Bloqueo de acceso público en buckets S3."""

import json
from typing import Any, Callable, Dict
from ..base import ResultadoVerificacion, redactar_secretos

CONTROL_ID = "15"
NOMBRE = "Acceso público bloqueado en buckets y almacenamiento de objetos"


def verificar_s3_public(
    ejecutor: Callable[[str], Dict[str, Any]],
    target: str = "aws",
) -> ResultadoVerificacion:
    """Ejecuta get-public-access-block para verificar que el bloqueo de acceso público esté activo."""
    cmd = "aws s3api get-public-access-block --output json"
    resp = ejecutor(cmd)

    if resp.get("status") != "ok" or resp.get("exit_code") != 0:
        err = resp.get("stderr") or resp.get("error") or "Fallo de ejecución o credenciales no configuradas"
        return ResultadoVerificacion(
            control_id=CONTROL_ID,
            nombre=NOMBRE,
            modo="nube",
            estado="requiere evidencia",
            detalles=f"No se pudo consultar la configuración de acceso público de S3 ({err}); requiere evidencia.",
            evidencia=f"Comando: {cmd}\nSalida: {resp.get('stdout', '')}\nError: {err}",
            objetivo=target,
        )

    stdout = resp.get("stdout", "").strip()
    try:
        data = json.loads(stdout)
    except Exception:
        data = None

    if not data or not isinstance(data, dict):
        return ResultadoVerificacion(
            control_id=CONTROL_ID,
            nombre=NOMBRE,
            modo="nube",
            estado="requiere evidencia",
            detalles="Sin respuesta concluyente de configuración de PublicAccessBlock; requiere evidencia manual.",
            evidencia=f"Comando: {cmd}\nSalida:\n{stdout}",
            objetivo=target,
        )

    config = data.get("PublicAccessBlockConfiguration") or data
    block_acls = bool(config.get("BlockPublicAcls"))
    block_policy = bool(config.get("BlockPublicPolicy"))
    ignore_acls = bool(config.get("IgnorePublicAcls"))
    restrict_buckets = bool(config.get("RestrictPublicBuckets"))

    evidencia_texto = f"Comando: {cmd}\nConfiguración PublicAccessBlock:\n{json.dumps(config, indent=2)}"

    if block_acls and block_policy and ignore_acls and restrict_buckets:
        estado = "cumple"
        detalles = "Bloqueo de acceso público S3 completamente habilitado en las 4 directivas."
    elif block_acls or block_policy:
        estado = "parcial"
        detalles = "Bloqueo de acceso público S3 parcialmente activo; faltan directivas de restricción."
    else:
        estado = "no cumple"
        detalles = "El almacenamiento S3 no tiene activado el bloqueo general de acceso público."

    return ResultadoVerificacion(
        control_id=CONTROL_ID,
        nombre=NOMBRE,
        modo="nube",
        estado=estado,
        detalles=detalles,
        evidencia=evidencia_texto,
        objetivo=target,
    )
