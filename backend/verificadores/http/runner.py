"""Orquestador de verificadores en vivo en Modo HTTP."""

import time
from typing import List, Optional
from ..base import ResultadoVerificacion, registrar_bitacora
from .control_01_cors import verificar_cors
from .control_03_errors import verificar_errores_sensibles
from .control_07_ratelimit import verificar_rate_limit
from .control_10_cookies import verificar_cookies
from .control_14_tls import verificar_tls
from .control_16_headers import verificar_headers

_VERIFICADORES = {
    "1": verificar_cors,
    "3": verificar_errores_sensibles,
    "7": verificar_rate_limit,
    "10": verificar_cookies,
    "14": verificar_tls,
    "16": verificar_headers,
}


def ejecutar_verificadores_http(
    url: str,
    autorizacion_confirmada: bool,
    controles: Optional[List[str]] = None,
    usuario: str = "analista",
    timeout: int = 10,
) -> List[ResultadoVerificacion]:
    """Ejecuta los verificadores HTTP sobre una URL objetivo con solicitudes seguras y de baja frecuencia.
    
    Exige obligatoriamente confirmación explícita de autorización sobre el objetivo.
    """
    url_limpia = str(url or "").strip()
    if not (url_limpia.startswith("http://") or url_limpia.startswith("https://")):
        url_limpia = "https://" + url_limpia

    ids_a_ejecutar = [c for c in controles if c in _VERIFICADORES] if controles else list(_VERIFICADORES.keys())

    # Exigir confirmación de autorización
    if not autorizacion_confirmada:
        resultados: List[ResultadoVerificacion] = []
        for cid in ids_a_ejecutar:
            fn = _VERIFICADORES[cid]
            dummy = fn.__doc__ or f"Control {cid}"
            res = ResultadoVerificacion(
                control_id=cid,
                nombre=f"Control {cid}",
                modo="http",
                estado="requiere evidencia",
                detalles="Prueba bloqueada: Se exige confirmar autorización explícita sobre el objetivo antes de ejecutar verificaciones en vivo.",
                evidencia="Prueba no ejecutada por falta de autorización.",
                objetivo=url_limpia,
            )
            registrar_bitacora(res, usuario=usuario, autorizacion_confirmada=False)
            resultados.append(res)
        return resultados

    resultados = []
    for i, cid in enumerate(ids_a_ejecutar):
        fn = _VERIFICADORES[cid]
        try:
            resultado = fn(url_limpia, timeout=timeout)
        except Exception as exc:
            resultado = ResultadoVerificacion(
                control_id=cid,
                nombre=f"Control {cid}",
                modo="http",
                estado="requiere evidencia",
                detalles=f"Excepción no controlada durante verificación: {exc}",
                evidencia=f"Error: {exc}",
                objetivo=url_limpia,
            )
        registrar_bitacora(resultado, usuario=usuario, autorizacion_confirmada=True)
        resultados.append(resultado)
        # Pausa suave de baja frecuencia entre verificadores consecutivos
        if i < len(ids_a_ejecutar) - 1:
            time.sleep(0.2)

    return resultados
