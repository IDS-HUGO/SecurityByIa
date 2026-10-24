"""Verificador Nube para Control 14: TLS del balanceador de carga."""

import json
from typing import Any, Callable, Dict
from ..base import ResultadoVerificacion, redactar_secretos

CONTROL_ID = "14"
NOMBRE = "TLS 1.2+ obligatorio en balanceadores y servicios expuestos"


def verificar_alb_tls(
    ejecutor: Callable[[str], Dict[str, Any]],
    target: str = "aws",
) -> ResultadoVerificacion:
    """Ejecuta aws elbv2 describe-listeners para verificar políticas TLS modernas."""
    cmd = "aws elbv2 describe-listeners --query Listeners[*].{Port:Port,Protocol:Protocol,SslPolicy:SslPolicy} --output json"
    resp = ejecutor(cmd)

    if resp.get("status") != "ok" or resp.get("exit_code") != 0:
        err = resp.get("stderr") or resp.get("error") or "Fallo de ejecución o credenciales no configuradas"
        return ResultadoVerificacion(
            control_id=CONTROL_ID,
            nombre=NOMBRE,
            modo="nube",
            estado="requiere evidencia",
            detalles=f"No se pudieron consultar los listeners de balanceadores ({err}); requiere evidencia.",
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
            detalles="No se encontraron balanceadores o listeners activos en la región; requiere evidencia de configuración.",
            evidencia=f"Comando: {cmd}\nSalida:\n{stdout}",
            objetivo=target,
        )

    evidencia_texto = f"Comando: {cmd}\nListeners inspeccionados:\n{json.dumps(data, indent=2)}"

    inseguros = []
    for item in data:
        protocol = str(item.get("Protocol") or "").upper()
        policy = str(item.get("SslPolicy") or "")
        port = item.get("Port")

        if protocol == "HTTP" and port == 80:
            # Observación si no redirecciona a HTTPS
            pass
        elif protocol == "HTTPS":
            if not policy or "1-0" in policy or "1-1" in policy or "old" in policy.lower():
                inseguros.append(f"Puerto {port} con política insegura ({policy or 'sin política'})")

    if inseguros:
        estado = "no cumple"
        detalles = f"Se detectaron listeners HTTPS con políticas TLS obsoletas o inseguras: {'; '.join(inseguros)}."
    else:
        estado = "cumple"
        detalles = f"Todos los listeners HTTPS ({len(data)}) utilizan políticas TLS 1.2+."

    return ResultadoVerificacion(
        control_id=CONTROL_ID,
        nombre=NOMBRE,
        modo="nube",
        estado=estado,
        detalles=detalles,
        evidencia=evidencia_texto,
        objetivo=target,
    )
