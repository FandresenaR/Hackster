import os
import sys
import logging
from pwn_init import PWN_CTX, PWN_READY, PWN_ERROR

# Configuration du logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("pwn_context")

# Exportation pour le reste de l'application
PWN_CONTEXT = PWN_CTX
PWN_ERROR = None if PWN_READY else PWN_ERROR or "pwntools n'est pas initialisé correctement"

# Log du statut final
if PWN_CONTEXT:
    logger.debug("Initialisation pwntools réussie")
else:
    logger.error("Contexte pwntools invalide")
