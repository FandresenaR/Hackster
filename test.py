from pwn import *
from pwnlib.context import context
import logging

# Désactiver les logs verbeux
logging.getLogger('pwnlib').setLevel(logging.ERROR)

# Test du contexte
print("Configuration du contexte :")
print(f"Architecture : {context.arch}")
print(f"OS : {context.os}")
print(f"Endianness : {context.endian}")
print(f"Bits : {context.bits}")