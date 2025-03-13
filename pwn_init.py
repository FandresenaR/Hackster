import os
import sys
import logging

# Configuration de l'environnement pour pwntools
os.environ['PWNLIB_NOTERM'] = '1'
os.environ['PYTHONIOENCODING'] = 'utf-8'

# Import au niveau du module
try:
    from pwn import *
    PWN_IMPORT_SUCCESS = True
except Exception as e:
    PWN_IMPORT_SUCCESS = False
    PWN_IMPORT_ERROR = str(e)

# Singleton pour garantir l'initialisation unique
class PwnToolsContext:
    _instance = None
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def __init__(self):
        if PwnToolsContext._instance is not None:
            return
            
        self.context = None
        self.error = None
        self.ready = False
        self.initialize()
    
    def initialize(self):
        try:
            # Utiliser l'import global
            if not PWN_IMPORT_SUCCESS:
                raise ImportError(PWN_IMPORT_ERROR)
            
            # Configurer le contexte
            ctx = context.copy()
            ctx.update(
                arch='amd64',
                os='linux',
                bits=64,
                endian='little',
                terminal=['gnome-terminal', '-e']
            )
            
            # Tester les fonctionnalités
            test_shellcode = ctx.shellcraft.amd64.linux.sh()
            test_asm = ctx.asm(test_shellcode)
            
            # Tout est OK
            self.context = ctx
            self.ready = True
            self.error = None
            
        except Exception as e:
            self.ready = False
            self.context = None
            self.error = f"Erreur pwntools: {str(e)}"
            print(f"Erreur pwntools: {e}")

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
