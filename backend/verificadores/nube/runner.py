"""Orquestador de verificadores en vivo en Modo Nube."""

import os
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional
try:
    from proxy import client as proxy_client
except ImportError:
    from backend.proxy import client as proxy_client

from ..base import ResultadoVerificacion, redactar_secretos, registrar_bitacora
from .allowlist import validar_comando_nube
from .control_13_db_encryption import verificar_cifrado_db
from .control_14_alb_tls import verificar_alb_tls
from .control_15_s3_public import verificar_s3_public
from .control_18_db_public import verificar_db_no_publica
from .control_19_s3_lifecycle import verificar_s3_lifecycle
from .control_c06_backups import verificar_respaldos
from .control_c09_cloudtrail import verificar_cloudtrail

_VERIFICADORES_NUBE = {
    "13": verificar_cifrado_db,
    "14": verificar_alb_tls,
    "15": verificar_s3_public,
    "18": verificar_db_no_publica,
    "19": verificar_s3_lifecycle,
    "C6": verificar_respaldos,
    "C9": verificar_cloudtrail,
}


def _crear_ejecutor_nube(credentials: Optional[Dict[str, str]] = None) -> Callable[[str], Dict[str, Any]]:
    """Crea una función de ejecución que valida comandos contra la lista blanca y enruta por el proxy F8."""
    def ejecutar(comando: str) -> Dict[str, Any]:
        valido, motivo = validar_comando_nube(comando)
        if not valido:
            return {"status": "error", "error": motivo, "exit_code": 1, "stdout": "", "stderr": motivo}

        # Si el proxy está configurado, las credenciales pasan por el proxy de F8
        if proxy_client.proxy_configured():
            try:
                return proxy_client.cloud_execute(comando, credentials=credentials)
            except proxy_client.ProxyUnavailable as exc:
                return {
                    "status": "error",
                    "error": f"Proxy de secretos F8 no disponible (fail-closed): {exc}",
                    "exit_code": 1,
                    "stdout": "",
                    "stderr": str(exc),
                }
            except Exception as exc:
                return {
                    "status": "error",
                    "error": f"Fallo al ejecutar vía proxy F8: {exc}",
                    "exit_code": 1,
                    "stdout": "",
                    "stderr": str(exc),
                }

        # Sin proxy configurado: si hay credenciales en el entorno o pasadas
        env = os.environ.copy()
        if credentials:
            if credentials.get("aws_access_key_id"):
                env["AWS_ACCESS_KEY_ID"] = credentials["aws_access_key_id"]
            if credentials.get("aws_secret_access_key"):
                env["AWS_SECRET_ACCESS_KEY"] = credentials["aws_secret_access_key"]
            if credentials.get("aws_session_token"):
                env["AWS_SESSION_TOKEN"] = credentials["aws_session_token"]
            if credentials.get("aws_default_region"):
                env["AWS_DEFAULT_REGION"] = credentials["aws_default_region"]

        tokens = comando.split()
        try:
            res = subprocess.run(tokens, capture_output=True, text=True, timeout=20, env=env)
            return {
                "status": "ok" if res.returncode == 0 else "error",
                "stdout": redactar_secretos(res.stdout),
                "stderr": redactar_secretos(res.stderr),
                "exit_code": res.returncode,
            }
        except FileNotFoundError:
            return {
                "status": "error",
                "error": "aws cli no se encuentra instalado",
                "exit_code": 127,
                "stdout": "",
                "stderr": "aws cli no instalado",
            }
        except Exception as exc:
            return {
                "status": "error",
                "error": str(exc),
                "exit_code": 1,
                "stdout": "",
                "stderr": str(exc),
            }

    return ejecutar


def ejecutar_verificadores_nube(
    target: str,
    autorizacion_confirmada: bool,
    controles: Optional[List[str]] = None,
    credentials: Optional[Dict[str, str]] = None,
    usuario: str = "analista",
) -> List[ResultadoVerificacion]:
    """Ejecuta los verificadores en modo nube garantizando solo comandos de lectura permitidos y autorización."""
    target_limpio = str(target or "aws-cloud").strip()
    ids_a_ejecutar = [c for c in controles if c in _VERIFICADORES_NUBE] if controles else list(_VERIFICADORES_NUBE.keys())

    # Exigir confirmación explícita de autorización
    if not autorizacion_confirmada:
        resultados: List[ResultadoVerificacion] = []
        for cid in ids_a_ejecutar:
            res = ResultadoVerificacion(
                control_id=cid,
                nombre=f"Control {cid}",
                modo="nube",
                estado="requiere evidencia",
                detalles="Prueba bloqueada: Se exige confirmar autorización explícita sobre el objetivo/cuenta antes de cualquier prueba en vivo.",
                evidencia="Prueba no ejecutada por falta de autorización.",
                objetivo=target_limpio,
            )
            registrar_bitacora(res, usuario=usuario, autorizacion_confirmada=False)
            resultados.append(res)
        return resultados

    ejecutor = _crear_ejecutor_nube(credentials=credentials)
    resultados = []

    for i, cid in enumerate(ids_a_ejecutar):
        fn = _VERIFICADORES_NUBE[cid]
        try:
            res = fn(ejecutor, target=target_limpio)
        except Exception as exc:
            res = ResultadoVerificacion(
                control_id=cid,
                nombre=f"Control {cid}",
                modo="nube",
                estado="requiere evidencia",
                detalles=f"Excepción al ejecutar verificador de nube: {exc}",
                evidencia=f"Error: {exc}",
                objetivo=target_limpio,
            )

        # Regla: Si un control no se puede verificar, déjalo en «requiere evidencia» en lugar de marcarlo como cumple.
        if res.estado not in ("cumple", "parcial", "no cumple", "requiere evidencia"):
            res.estado = "requiere evidencia"

        registrar_bitacora(res, usuario=usuario, autorizacion_confirmada=True)
        resultados.append(res)
        if i < len(ids_a_ejecutar) - 1:
            time.sleep(0.1)

    return resultados
