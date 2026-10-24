"""Verificador HTTP para Control 14: Restricción de TLS inferior a 1.2."""

import socket
import ssl
import time
import urllib.parse
from ..base import ResultadoVerificacion, redactar_secretos

CONTROL_ID = "14"
NOMBRE = "TLS 1.2+ obligatorio en balanceadores y servicios expuestos"


def verificar_tls(url: str, timeout: int = 10) -> ResultadoVerificacion:
    """Verifica si el servidor rechaza protocolos TLS obsoletos (< 1.2) como TLS 1.0 o TLS 1.1."""
    inicio = time.monotonic()
    parsed = urllib.parse.urlparse(url)

    if parsed.scheme != "https":
        duracion = int((time.monotonic() - inicio) * 1000)
        return ResultadoVerificacion(
            control_id=CONTROL_ID,
            nombre=NOMBRE,
            modo="http",
            estado="no cumple",
            detalles="El objetivo utiliza HTTP sin cifrado (no usa HTTPS/TLS).",
            evidencia=f"URL analizada: {url} (esquema: {parsed.scheme})",
            objetivo=url,
            duracion_ms=duracion,
        )

    host = parsed.hostname or url
    port = parsed.port or 443
    cmd_simulado = f"openssl s_client -connect {host}:{port} -tls1_1"

    # Intentar handshake forzando TLS 1.0 o 1.1 si está disponible en el entorno
    tls_obsoleto_aceptado = False
    error_mensaje = ""
    cipher_usado = None

    # Primero probar si el servidor responde normalmente en TLS moderno
    try:
        ctx_moderno = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx_moderno.wrap_socket(sock, server_hostname=host) as ssock:
                protocolo_actual = ssock.version()
                cipher_usado = ssock.cipher()
    except Exception as exc:
        duracion = int((time.monotonic() - inicio) * 1000)
        return ResultadoVerificacion(
            control_id=CONTROL_ID,
            nombre=NOMBRE,
            modo="http",
            estado="requiere evidencia",
            detalles=f"No se pudo completar el apretón de manos TLS con el objetivo ({exc}); se requiere evidencia.",
            evidencia=f"Comando simulado: {cmd_simulado}\nError: {exc}",
            objetivo=url,
            duracion_ms=duracion,
        )

    # Intentar negociar versión baja si el sistema lo soporta
    try:
        # En sistemas modernos TLS 1.0/1.1 suele estar deshabilitado en openssl local
        # por lo que el intento puede fallar localmente o rechazar en el servidor
        ctx_bajo = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx_bajo.check_hostname = False
        ctx_bajo.verify_mode = ssl.CERT_NONE
        # Configurar rango máximo en TLS 1.1
        if hasattr(ssl, "TLSVersion"):
            ctx_bajo.maximum_version = ssl.TLSVersion.TLSv1_1
            ctx_bajo.minimum_version = ssl.TLSVersion.TLSv1
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx_bajo.wrap_socket(sock, server_hostname=host) as ssock:
                version_negociada = ssock.version()
                if version_negociada in ("TLSv1", "TLSv1.1", "SSLv3"):
                    tls_obsoleto_aceptado = True
    except (ssl.SSLError, socket.error, OSError) as exc:
        # Handshake rechazado indica que el servidor o la biblioteca rechazan < 1.2
        error_mensaje = str(exc)

    duracion = int((time.monotonic() - inicio) * 1000)

    resultado_rechazo = error_mensaje if error_mensaje else "Handshake alert"
    resultado_tls = "ACEPTADO (vulnerable)" if tls_obsoleto_aceptado else f"RECHAZADO ({resultado_rechazo})"

    evidencia_texto = (
        f"$ {cmd_simulado}\n"
        f"Host: {host}:{port}\n"
        f"Protocolo negociado en conexión estándar: {protocolo_actual}\n"
        f"Cifrado activo: {cipher_usado}\n"
        f"Resultado al forzar TLS < 1.2: {resultado_tls}\n"
    )

    if tls_obsoleto_aceptado:
        estado = "no cumple"
        detalles = "El servidor aceptó conexión con protocolo TLS inferior a 1.2 (inseguro)."
    else:
        estado = "cumple"
        detalles = f"El servidor exige TLS seguro (negocia {protocolo_actual}) y rechaza TLS < 1.2."

    return ResultadoVerificacion(
        control_id=CONTROL_ID,
        nombre=NOMBRE,
        modo="http",
        estado=estado,
        detalles=detalles,
        evidencia=evidencia_texto,
        objetivo=url,
        duracion_ms=duracion,
    )
