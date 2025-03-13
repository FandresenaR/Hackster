import os
import sys
import logging

# Configuration de l'environnement pour pwntools
os.environ['PWNLIB_NOTERM'] = '1'
os.environ['PYTHONIOENCODING'] = 'utf-8'

# Initialisation du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pwn_init")

# Import au niveau du module - plus robuste avec détails d'erreur
try:
    from pwn import *
    logger.info("Import pwn réussi")
    PWN_IMPORT_SUCCESS = True
except ImportError as e:
    logger.error(f"Erreur d'import pwntools: {str(e)}")
    PWN_IMPORT_SUCCESS = False
    PWN_IMPORT_ERROR = str(e)
except Exception as e:
    logger.error(f"Erreur inattendue lors de l'import: {str(e)}")
    PWN_IMPORT_SUCCESS = False
    PWN_IMPORT_ERROR = str(e)

# Singleton pour garantir l'initialisation unique
class PwnToolsContext:
    _instance = None
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
            logger.info("Nouvelle instance PwnToolsContext créée")
        return cls._instance
    
    def __init__(self):
        if PwnToolsContext._instance is not None:
            return
            
        self.context = None
        self.error = None
        self.ready = False
        self.initialize()
    
    def initialize(self):
        logger.info("Initialisation de PwnToolsContext...")
        try:
            # Utiliser l'import global
            if not PWN_IMPORT_SUCCESS:
                raise ImportError(PWN_IMPORT_ERROR)
            
            # Configurer le contexte
            global context
            ctx = context.copy()
            logger.info(f"Contexte original: {ctx}")
            
            ctx.update(
                arch='amd64',
                os='linux',
                bits=64,
                endian='little',
                terminal=['gnome-terminal', '-e']
            )
            logger.info(f"Contexte mis à jour: {ctx}")
            
            # Tester les fonctionnalités de base
            try:
                test_shellcode = shellcraft.amd64.linux.sh()
                logger.info("✅ Shellcraft fonctionne")
                test_asm = asm(test_shellcode)
                logger.info("✅ ASM fonctionne")
            except Exception as e:
                logger.error(f"Test de fonctionnalité échoué: {str(e)}")
                raise
            
            # Tout est OK
            self.context = ctx
            self.ready = True
            self.error = None
            logger.info("✅ Initialisation pwntools réussie")
            
        except Exception as e:
            self.ready = False
            self.context = None
            self.error = f"Erreur pwntools: {str(e)}"
            logger.error(f"❌ Erreur d'initialisation pwntools: {str(e)}")

# Variables d'export
def get_pwn():
    return PwnToolsContext.get_instance().context

def is_ready():
    return PwnToolsContext.get_instance().ready

def get_error():
    return PwnToolsContext.get_instance().error

# Initialisation immédiate
PWN_INSTANCE = PwnToolsContext.get_instance()
PWN_READY = PWN_INSTANCE.ready
PWN_CTX = PWN_INSTANCE.context
PWN_ERROR = PWN_INSTANCE.error

# Log final de l'état
logger.info(f"État final - Ready: {PWN_READY}, Context: {'OK' if PWN_CTX else 'None'}, Error: {PWN_ERROR}")
