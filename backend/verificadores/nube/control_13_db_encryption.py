"""Verificador Nube para Control 13: Cifrado de bases de datos RDS."""

import json
from typing import Any, Callable, Dict, Optional
from ..base import ResultadoVerificacion, redactar_secretos

CONTROL_ID = "13"
NOMBRE = "Cifrado en reposo para bases de datos relacionales"


def verificar_cifrado_db(
    ejecutor: Callable[[str], Dict[str, Any]],
    target: str = "aws",
) -> ResultadoVerificacion:
    """Ejecuta aws rds describe-db-clusters o describe-db-instances para verificar StorageEncrypted."""
    cmd = "aws rds describe-db-instances --query DBInstances[*].{ID:DBInstanceIdentifier,Encrypted:StorageEncrypted} --output json"
    resp = ejecutor(cmd)

    if resp.get("status") != "ok" or resp.get("exit_code") != 0:
        err = resp.get("stderr") or resp.get("error") or "Fallo de ejecución o credenciales no configuradas"
        return ResultadoVerificacion(
            control_id=CONTROL_ID,
            nombre=NOMBRE,
            modo="nube",
            estado="requiere evidencia",
            detalles=f"No se pudo consultar el cifrado de RDS ({err}); requiere evidencia.",
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
            detalles="No se encontraron instancias de base de datos en la cuenta o región; requiere evidencia de configuración.",
            evidencia=f"Comando: {cmd}\nSalida:\n{stdout}",
            objetivo=target,
        )

    sin_cifrado = [item.get("ID") for item in data if not item.get("Encrypted")]

    evidencia_texto = f"Comando: {cmd}\nInstancias evaluadas ({len(data)}):\n{json.dumps(data, indent=2)}"

    if sin_cifrado:
        estado = "no cumple"
        detalles = f"Se detectaron bases de datos sin cifrado en reposo: {', '.join(str(i) for i in sin_cifrado)}."
    else:
        estado = "cumple"
        detalles = f"Todas las instancias RDS ({len(data)}) tienen cifrado en reposo activado (StorageEncrypted=true)."

    return ResultadoVerificacion(
        control_id=CONTROL_ID,
        nombre=NOMBRE,
        modo="nube",
        estado=estado,
        detalles=detalles,
        evidencia=evidencia_texto,
        objetivo=target,
    )
