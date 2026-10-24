"""Verificador Nube para Control 18: Bases de datos no accesibles públicamente."""

import json
from typing import Any, Callable, Dict
from ..base import ResultadoVerificacion, redactar_secretos

CONTROL_ID = "18"
NOMBRE = "Bases de datos no accesibles directamente desde internet"


def verificar_db_no_publica(
    ejecutor: Callable[[str], Dict[str, Any]],
    target: str = "aws",
) -> ResultadoVerificacion:
    """Ejecuta describe-db-instances para verificar que PubliclyAccessible sea false."""
    cmd = "aws rds describe-db-instances --query DBInstances[*].{ID:DBInstanceIdentifier,Public:PubliclyAccessible} --output json"
    resp = ejecutor(cmd)

    if resp.get("status") != "ok" or resp.get("exit_code") != 0:
        err = resp.get("stderr") or resp.get("error") or "Fallo de ejecución o credenciales no configuradas"
        return ResultadoVerificacion(
            control_id=CONTROL_ID,
            nombre=NOMBRE,
            modo="nube",
            estado="requiere evidencia",
            detalles=f"No se pudo consultar el acceso público de RDS ({err}); requiere evidencia.",
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
            detalles="No se detectaron instancias RDS activas para evaluar; requiere evidencia.",
            evidencia=f"Comando: {cmd}\nSalida:\n{stdout}",
            objetivo=target,
        )

    publicas = [item.get("ID") for item in data if item.get("Public") is True]

    evidencia_texto = f"Comando: {cmd}\nInstancias evaluadas:\n{json.dumps(data, indent=2)}"

    if publicas:
        estado = "no cumple"
        detalles = f"Se detectaron bases de datos configuradas con acceso público (PubliclyAccessible=true): {', '.join(str(p) for p in publicas)}."
    else:
        estado = "cumple"
        detalles = f"Todas las bases de datos RDS ({len(data)}) tienen el acceso público desactivado (PubliclyAccessible=false)."

    return ResultadoVerificacion(
        control_id=CONTROL_ID,
        nombre=NOMBRE,
        modo="nube",
        estado=estado,
        detalles=detalles,
        evidencia=evidencia_texto,
        objetivo=target,
    )
