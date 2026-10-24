import logging

logger = logging.getLogger(__name__)


def auditar(user, access_token):
    logger.info(f"login ok con token {access_token}")
    logger.info("login ok para user_id=%s", user)
