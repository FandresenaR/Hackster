import streamlit as st
import socket
import threading
import queue
import time
import re
import vulners
import dns.resolver
import requests
import io
import shodan

# Custom CSS for modern, structured, and hacker-friendly design
def load_css():
    st.markdown("""
    <style>
    body {
        background-color: #0a0a0a;
        color: #00ff00;
        font-family: 'Courier New', monospace;
    }
    .main-container {
        background-color: #1a1a1a;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 0 10px rgba(0, 255, 0, 0.1);
    }
    .title {
        color: #00ff00;
        text-align: center;
        font-size: 2.5em;
        text-shadow: 0 0 5px #00ff00;
    }
    .subtitle {
        color: #00cc00;
        text-align: center;
        margin-bottom: 30px;
    }
    .input-box {
        background-color: #262626;
        border: 2px solid #00ff00;
        border-radius: 5px;
        padding: 10px;
        color: #00ff00;
    }
    .output-box, .alt-output-box, .shodan-output-box {
        background-color: #131313;
        border-radius: 5px;
        padding: 15px;
        margin-top: 20px;
        font-size: 0.9em;
    }
    .output-box {
        border: 1px solid #00ff00;
        height: 400px;
        overflow-y: auto;
    }
    .alt-output-box {
        border: 1px solid #00cc00;
        height: 300px;
        overflow-y: auto;
    }
    .shodan-output-box {
        border: 1px solid #00aaff;  /* Light blue for Shodan */
        height: 300px;
        overflow-y: auto;
    }
    .section-header {
        color: #00ff00;
        font-weight: bold;
        margin-top: 10px;
        border-bottom: 1px dashed #00ff00;
        padding-bottom: 5px;
    }
    .sub-item {
        margin-left: 20px;
        padding-left: 5px;
    }
    .stButton>button {
        background-color: #00ff00;
        color: #000000;
        border: none;
        border-radius: 5px;
        padding: 10px 20px;
        font-weight: bold;
    }
    .stButton>button:hover {
        background-color: #00cc00;
        box-shadow: 0 0 10px #00ff00;
    }
    </style>
    """, unsafe_allow_html=True)

# Validate input
def validate_input(target):
    url_pattern = re.compile(r'^(https?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/.*)?$')
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    return url_pattern.match(target) or ip_pattern.match(target)

# Infer OS from banner
def infer_os_from_banner(banner):
    os_patterns = {
        "ubuntu": r"Ubuntu",
        "debian": r"Debian",
        "centos": r"CentOS",
        "redhat": r"Red Hat|RHEL",
        "windows": r"Microsoft|Windows|IIS",
        "apache": r"Apache",
        "nginx": r"nginx",
    }
    for os, pattern in os_patterns.items():
        if re.search(pattern, banner, re.IGNORECASE):
            return os.capitalize()
    return "Unknown"

# Check vulnerabilities with Vulners
def check_vuln(banner, inferred_os, output_queue, vulners_api):
    try:
        service_results = vulners_api.search(banner, limit=5)
        if service_results:
            output_queue.put("**Service Vulnerabilities:**")
            for vuln in service_results:
                output_queue.put(f"  - {vuln['id']} - {vuln['title']}")
                output_queue.put(f"    Description: {vuln.get('description', 'N/A')[:100]}...")
                if 'href' in vuln:
                    output_queue.put(f"    Reference: {vuln['href']}")

        if inferred_os != "Unknown":
            os_query = f"{inferred_os} kernel"
            os_results = vulners_api.search(os_query, limit=3)
            if os_results:
                output_queue.put(f"**OS Vulnerabilities ({inferred_os}):**")
                for vuln in os_results:
                    output_queue.put(f"  - {vuln['id']} - {vuln['title']}")
                    output_queue.put(f"    Description: {vuln.get('description', 'N/A')[:100]}...")
                    if 'href' in vuln:
                        output_queue.put(f"    Reference: {vuln['href']}")
    except Exception as e:
        output_queue.put(f"  - Vulners API Error: {str(e)}")

# Socket-based port scan
def scan_port(target, port, output_queue, vulners_api):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            output_queue.put(f"**Port {port} Open:**")
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode(errors='ignore').strip()
                if banner:
                    output_queue.put(f"  - Banner: {banner}")
                    inferred_os = infer_os_from_banner(banner)
                    output_queue.put(f"  - Inferred OS: {inferred_os}")
                    check_vuln(banner, inferred_os, output_queue, vulners_api)
                else:
                    output_queue.put("  - No banner available")
            except:
                output_queue.put("  - No banner available")
        sock.close()
    except Exception as e:
        output_queue.put(f"  - Error scanning port {port}: {str(e)}")

# Shodan enumeration
def shodan_enumerate(target, shodan_output_queue, shodan_api_key):
    shodan_output_queue.put("**Shodan Enumeration:**")
    shodan_output_queue.put("  - Starting Shodan scan...")
    try:
        api = shodan.Shodan(shodan_api_key)
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):  # IP address
            host = api.host(target)
        else:  # Domain
            host = api.search(target)
            if host.get('matches'):
                host = host['matches'][0]  # Use first match for simplicity
            else:
                shodan_output_queue.put("  - No Shodan data found for domain.")
                shodan_output_queue.put("  - Shodan scan completed.")
                return

        os = host.get('os', 'Unknown')
        shodan_output_queue.put(f"  - Inferred OS: {os}")
        
        services = host.get('data', [])
        if services:
            shodan_output_queue.put("  - Services Detected:")
            for service in services:
                port = service.get('port', 'N/A')
                product = service.get('product', 'Unknown')
                version = service.get('version', 'Unknown')
                shodan_output_queue.put(f"    - Port {port}: {product} {version}")
        
        vulns = host.get('vulns', [])
        if vulns:
            shodan_output_queue.put("**Shodan Vulnerabilities:**")
            for vuln_id in vulns:
                vuln = api.exploits.search(vuln_id)
                if vuln.get('matches'):
                    vuln_info = vuln['matches'][0]
                    shodan_output_queue.put(f"  - {vuln_id} - {vuln_info.get('title', 'No title')}")
                    shodan_output_queue.put(f"    Description: {vuln_info.get('description', 'N/A')[:100]}...")
                    if 'references' in vuln_info:
                        shodan_output_queue.put(f"    Reference: {vuln_info['references'][0] if vuln_info['references'] else 'N/A'}")
        else:
            shodan_output_queue.put("  - No vulnerabilities found in Shodan.")
    except shodan.APIError as e:
        shodan_output_queue.put(f"  - Shodan API Error: {str(e)}")
    except Exception as e:
        shodan_output_queue.put(f"  - Shodan scan failed: {str(e)}")
    shodan_output_queue.put("  - Shodan scan completed.")

# Subdomain enumeration
def enumerate_subdomains(domain, alt_output_queue):
    alt_output_queue.put("**Subdomain Enumeration:**")
    alt_output_queue.put("  - Starting subdomain enumeration...")
    subdomains = [
        "www", "mail", "ftp", "test", "dev", "api", "staging", "admin", "login", 
        "web", "secure", "shop", "blog", "portal", "vpn", "dns", "ns1", "mx"
    ]
    found_subdomains = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    try:
        for sub in subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                answers = resolver.resolve(subdomain, 'A')
                for rdata in answers:
                    alt_output_queue.put(f"  - Found subdomain: {subdomain} -> {rdata.address}")
                    found_subdomains.append(subdomain)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                alt_output_queue.put(f"  - Checked {subdomain} - Not found")
            except Exception as e:
                alt_output_queue.put(f"  - Error checking {subdomain}: {str(e)}")
        if not found_subdomains:
            alt_output_queue.put("  - No subdomains found from the wordlist.")
    except Exception as e:
        alt_output_queue.put(f"  - Subdomain enumeration failed: {str(e)}")
    alt_output_queue.put("  - Subdomain enumeration completed.")

# GitHub recon
def github_recon(domain, alt_output_queue, github_token=None):
    alt_output_queue.put("**GitHub Recon:**")
    alt_output_queue.put("  - Starting GitHub recon...")
    try:
        search_url = f"https://api.github.com/search/code?q={domain}"
        headers = {"Accept": "application/vnd.github.v3+json"}
        if github_token:
            headers["Authorization"] = f"token {github_token}"
        response = requests.get(search_url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("total_count", 0) > 0:
                alt_output_queue.put("  - GitHub findings:")
                for item in data["items"][:3]:
                    alt_output_queue.put(f"    - Repo: {item['repository']['full_name']}")
                    alt_output_queue.put(f"    - File: {item['name']} - {item['html_url']}")
            else:
                alt_output_queue.put("  - No GitHub leaks found.")
        elif response.status_code == 403:
            alt_output_queue.put("  - GitHub API rate limit exceeded. Use a token for more requests.")
        else:
            alt_output_queue.put(f"  - GitHub API error: {response.status_code} - {response.text}")
    except Exception as e:
        alt_output_queue.put(f"  - GitHub recon failed: {str(e)}")
    alt_output_queue.put("  - GitHub recon completed.")

# Perform advanced scan
def perform_advanced_scan(target, output_queue, alt_output_queue, shodan_output_queue, vulners_api, github_token=None, shodan_api_key=None):
    common_ports = [21, 22, 23, 25, 80, 110, 143, 443, 3389]
    output_queue.put("**Port Scan & Vulnerability Results:**")
    output_queue.put("  - Starting port enumeration on {target}...")
    threads = []
    for port in common_ports:
        t = threading.Thread(target=scan_port, args=(target, port, output_queue, vulners_api))
        t.start()
        threads.append(t)
    
    if "." in target and not re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
        threading.Thread(target=enumerate_subdomains, args=(target, alt_output_queue)).start()
        threading.Thread(target=github_recon, args=(target, alt_output_queue, github_token)).start()
    else:
        alt_output_queue.put("**Additional Recon Results:**")
        alt_output_queue.put("  - Target is an IP, skipping domain-specific recon.")
    
    if shodan_api_key:
        threading.Thread(target=shodan_enumerate, args=(target, shodan_output_queue, shodan_api_key)).start()
    else:
        shodan_output_queue.put("**Shodan Enumeration:**")
        shodan_output_queue.put("  - Shodan API key not provided, skipping scan.")
    
    for t in threads:
        t.join()
    output_queue.put("  - Port scan completed.")

# Main Streamlit app
def main():
    load_css()
    
    st.markdown("<h1 class='title'>Pentest Automation Tool</h1>", unsafe_allow_html=True)
    st.markdown("<p class='subtitle'>Expert Edition with Shodan & Vulners</p>", unsafe_allow_html=True)

    with st.container():
        st.markdown("<div class='main-container'>", unsafe_allow_html=True)
        
        target = st.text_input("Enter Website URL or IP Address", "", placeholder="example.com or 192.168.1.1", 
                             help="Enter a valid URL or IP to scan")
        
        api_key = st.text_input("Enter Vulners API Key", "", type="password", 
                               help="Get your free API key from vulners.com")
        
        github_token = st.text_input("Enter GitHub Token (Optional)", "", type="password", 
                                    help="Get a token from github.com/settings/tokens")
        
        shodan_api_key = st.text_input("Enter Shodan API Key (Optional)", "", type="password", 
                                      help="Get your free API key from shodan.io")
        
        if st.button("Start Expert Scan"):
            if not target:
                st.error("Please enter a target!")
            elif not validate_input(target):
                st.error("Invalid URL or IP format!")
            elif not api_key:
                st.error("Please enter a Vulners API key!")
            else:
                st.success(f"Performing expert scan on {target} with Vulners, Shodan, and more...")
                
                output_q = queue.Queue()
                alt_output_q = queue.Queue()
                shodan_output_q = queue.Queue()
                scan_output = st.empty()
                alt_scan_output = st.empty()
                shodan_scan_output = st.empty()
                vulners_api = vulners.Vulners(api_key=api_key)

                scan_thread = threading.Thread(target=perform_advanced_scan, args=(target, output_q, alt_output_q, shodan_output_q, vulners_api, github_token, shodan_api_key))
                scan_thread.start()

                # Store results persistently
                scan_results = ""
                alt_results = ""
                shodan_results = ""
                while scan_thread.is_alive() or not output_q.empty() or not alt_output_q.empty() or not shodan_output_q.empty():
                    while not output_q.empty():
                        item = output_q.get()
                        scan_results += item + "\n"
                    while not alt_output_q.empty():
                        item = alt_output_q.get()
                        alt_results += item + "\n"
                    while not shodan_output_q.empty():
                        item = shodan_output_q.get()
                        shodan_results += item + "\n"
                    scan_output.markdown(f"<div class='output-box'>{scan_results}</div>", 
                                       unsafe_allow_html=True)
                    alt_scan_output.markdown(f"<div class='alt-output-box'>{alt_results}</div>", 
                                           unsafe_allow_html=True)
                    shodan_scan_output.markdown(f"<div class='shodan-output-box'>{shodan_results}</div>", 
                                              unsafe_allow_html=True)
                    time.sleep(1)  # Increased sleep for stability

                scan_thread.join()
                # Final update after thread completes
                while not output_q.empty():
                    scan_results += output_q.get() + "\n"
                while not alt_output_q.empty():
                    alt_results += output_q.get() + "\n"
                while not shodan_output_q.empty():
                    shodan_results += output_q.get() + "\n"
                
                # Display final results with download buttons
                scan_output.markdown(f"<div class='output-box'>{scan_results}</div>", 
                                   unsafe_allow_html=True)
                # Download for Port Scan & Vuln Results
                scan_txt = io.BytesIO(scan_results.encode('utf-8'))
                st.download_button(
                    label="Download Port Scan & Vuln Results (.txt)",
                    data=scan_txt,
                    file_name=f"port_scan_{target.replace('.', '_')}_{time.strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain"
                )

                alt_scan_output.markdown(f"<div class='alt-output-box'>{alt_results}</div>", 
                                       unsafe_allow_html=True)
                # Download for Additional Recon Results
                alt_txt = io.BytesIO(alt_results.encode('utf-8'))
                st.download_button(
                    label="Download Additional Recon Results (.txt)",
                    data=alt_txt,
                    file_name=f"additional_recon_{target.replace('.', '_')}_{time.strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain"
                )

                shodan_scan_output.markdown(f"<div class='shodan-output-box'>{shodan_results}</div>", 
                                          unsafe_allow_html=True)
                # Download for Shodan Results
                shodan_txt = io.BytesIO(shodan_results.encode('utf-8'))
                st.download_button(
                    label="Download Shodan Results (.txt)",
                    data=shodan_txt,
                    file_name=f"shodan_scan_{target.replace('.', '_')}_{time.strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain"
                )

        st.markdown("</div>", unsafe_allow_html=True)

if __name__ == "__main__":
    main()
