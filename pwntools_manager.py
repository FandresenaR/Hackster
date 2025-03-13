import os
os.environ['PWNLIB_NOTERM'] = '1'

try:
    from pwn import *
    PWN = True
    PWNTOOLS = context
    PWNTOOLS.update(arch='amd64', os='linux', bits=64, endian='little')
    PWNTOOLS_ERROR = None
except Exception as e:
    PWN = False
    PWNTOOLS = None
    PWNTOOLS_ERROR = str(e)

def get_pwntools():
    if PWN:
        return PWNTOOLS
    return None

def get_error():
    return PWNTOOLS_ERROR
