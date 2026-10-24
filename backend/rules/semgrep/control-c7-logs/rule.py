# Casos que deben detectar (C7)
import logging

logger = logging.getLogger(__name__)

logger.info(f"login ok para user con token {access_token}")  # ruleid: py-log-sensitive-ctl7
logger.error(f"fallo con password {password}")  # ruleid: py-log-sensitive-ctl7
print(authorization_header)  # ruleid: py-log-sensitive-ctl7
logger.warning(  # ruleid: py-log-sensitive-literal-ctl7
    "token=%s", session_token)

# Casos seguros: logs sin valores sensibles
logger.info("login ok para user_id=%s", user_id)
print("proceso finalizado")
