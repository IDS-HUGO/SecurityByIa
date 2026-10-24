"""Lista permitida estricta de comandos de lectura (describe y get) para el modo nube."""

from typing import Any, Tuple

# Prefijos permitidos: solo comandos describe y get para los controles auditados
ALLOWED_COMMAND_PREFIXES = (
    "aws rds describe-db-clusters",
    "aws rds describe-db-instances",
    "aws s3api get-bucket-policy-status",
    "aws s3api get-public-access-block",
    "aws s3api get-bucket-acl",
    "aws s3api get-bucket-lifecycle-configuration",
    "aws elbv2 describe-listeners",
    "aws elbv2 describe-load-balancers",
    "aws elb describe-load-balancers",
    "aws cloudtrail describe-trails",
    "aws cloudtrail get-trail-status",
    "aws backup describe-backup-vault",
    "aws backup list-recovery-points-by-backup-vault",
)

DISALLOWED_MUTATING_WORDS = (
    "delete", "put", "create", "update", "modify", "terminate", "stop",
    "start", "reboot", "attach", "detach", "authorize", "revoke", "set-",
    "add", "remove", "restore", "copy", "import", "export", "run-", "apply",
)


def validar_comando_nube(comando: Any) -> Tuple[bool, str]:
    """Valida que el comando pertenezca a la lista permitida de lectura de describe y get."""
    if isinstance(comando, list):
        cmd_str = " ".join(str(c) for c in comando).strip()
    else:
        cmd_str = str(comando or "").strip()

    cmd_lower = cmd_str.lower()
    if not cmd_lower:
        return False, "Comando vacío."

    # Validar prefijo permitido
    coincide_prefijo = any(cmd_lower.startswith(prefix) for prefix in ALLOWED_COMMAND_PREFIXES)
    if not coincide_prefijo:
        return False, (
            "Comando rechazado: el modo nube solo acepta comandos 'describe' y 'get' "
            "de la lista permitida (cifrado BD, acceso público buckets, ciclo de vida, "
            "BD pública, TLS balanceador, CloudTrail y respaldos)."
        )

    # Validar ausencia de palabras o parámetros de mutación
    tokens = cmd_lower.split()
    for word in DISALLOWED_MUTATING_WORDS:
        for token in tokens:
            if token == word or token == f"--{word}" or token.startswith(f"--{word}="):
                return False, f"Comando rechazado: parámetro o subcomando peligroso detectado ('{word}')."

    return True, cmd_str
