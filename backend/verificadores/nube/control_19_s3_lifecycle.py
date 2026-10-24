"""Verificador Nube para Control 19: Políticas de ciclo de vida en almacenamiento."""

import json
from typing import Any, Callable, Dict
from ..base import ResultadoVerificacion, redactar_secretos

CONTROL_ID = "19"
NOMBRE = "Políticas de ciclo de vida en almacenamiento (retención y expiración)"


def verificar_s3_lifecycle(
    ejecutor: Callable[[str], Dict[str, Any]],
    target: str = "aws",
) -> ResultadoVerificacion:
    """Ejecuta get-bucket-lifecycle-configuration para verificar reglas de expiración y retención."""
    cmd = "aws s3api get-bucket-lifecycle-configuration --output json"
    resp = ejecutor(cmd)

    if resp.get("status") != "ok" or resp.get("exit_code") != 0:
        err = resp.get("stderr") or resp.get("error") or "Fallo de ejecución o credenciales no configuradas"
        # Si el error indica NoSuchLifecycleConfiguration, no cumple
        if "NoSuchLifecycleConfiguration" in err:
            return ResultadoVerificacion(
                control_id=CONTROL_ID,
                nombre=NOMBRE,
                modo="nube",
                estado="no cumple",
                detalles="El bucket no tiene ninguna regla de ciclo de vida o retención configurada (NoSuchLifecycleConfiguration).",
                evidencia=f"Comando: {cmd}\nSalida: {resp.get('stdout', '')}\nError: {err}",
                objetivo=target,
            )
        return ResultadoVerificacion(
            control_id=CONTROL_ID,
            nombre=NOMBRE,
            modo="nube",
            estado="requiere evidencia",
            detalles=f"No se pudo consultar la configuración de ciclo de vida ({err}); requiere evidencia.",
            evidencia=f"Comando: {cmd}\nSalida: {resp.get('stdout', '')}\nError: {err}",
            objetivo=target,
        )

    stdout = resp.get("stdout", "").strip()
    try:
        data = json.loads(stdout)
    except Exception:
        data = None

    rules = (data.get("Rules") if isinstance(data, dict) else []) or []
    evidencia_texto = f"Comando: {cmd}\nReglas de ciclo de vida detectadas ({len(rules)}):\n{json.dumps(rules, indent=2)}"

    if not rules:
        estado = "no cumple"
        detalles = "No se encontraron reglas activas de ciclo de vida en el almacenamiento."
    else:
        activas = [r for r in rules if r.get("Status") == "Enabled"]
        if activas:
            estado = "cumple"
            detalles = f"Se detectaron {len(activas)} regla(s) de ciclo de vida activas (expiración/transición)."
        else:
            estado = "parcial"
            detalles = f"Reglas de ciclo de vida presentes pero deshabilitadas ({len(rules)})."

    return ResultadoVerificacion(
        control_id=CONTROL_ID,
        nombre=NOMBRE,
        modo="nube",
        estado=estado,
        detalles=detalles,
        evidencia=evidencia_texto,
        objetivo=target,
    )
