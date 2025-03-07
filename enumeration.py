import socket
import requests
from concurrent.futures import ThreadPoolExecutor

def scan_port(host, port):
    """Scan d'un port avec gestion d'erreurs"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            result = s.connect_ex((host, port))
            return port if result == 0 else None
    except Exception as e:
        return None

def get_service_banner(host, port, timeout=2):
    """Récupère la bannière d'un service"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            probes = [
                b'HEAD / HTTP/1.0\r\n\r\n',
                b'GET / HTTP/1.0\r\n\r\n',
                b'\r\n',
                b'HELP\r\n',
                b'VERSION\r\n'
            ]
            for probe in probes:
                try:
                    s.send(probe)
                    banner = s.recv(1024).decode('utf-8', errors='ignore')
                    if banner:
                        return banner.strip()
                except:
                    continue
            return "Service détecté, pas de bannière"
    except:
        return None