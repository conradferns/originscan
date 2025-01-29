import shodan
import requests
import socket
import dns.resolver

# Shodan API Key (Replace with your actual API key)
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"
ORG_NAME = "Company"

# Find Company' assets using Shodan
def find_Company_assets():
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        query = f'org:"{ORG_NAME}"'
        results = api.search(query)

        print(f"Found {results['total']} assets for {ORG_NAME}\n")
        assets = [result['ip_str'] for result in results['matches']]
        
        for result in results['matches']:
            print(f"IP: {result['ip_str']}, Ports: {result.get('ports', [])}")
        
        return assets

    except shodan.APIError as e:
        print(f"Shodan API error: {e}")
        return []

# Find Company' subdomains and resolve their IPs
def find_origin_ip_via_subdomains(domain):
    subdomains = ["dev", "staging", "internal", "vpn", "mail", "test", "api"]
    origin_ips = []

    for sub in subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            print(f"Subdomain {subdomain} resolves to {ip}")
            origin_ips.append(ip)
        except socket.gaierror:
            pass  # Ignore unresolved subdomains

    return origin_ips

# Fetch Company' SSL certificates and resolve IPs
def find_origin_ip_via_certstream(domain):
    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        response = requests.get(url)

        if response.status_code == 200:
            certs = response.json()
            unique_domains = list(set(entry["name_value"] for entry in certs))
            print(f"SSL Transparency Log Domains for {domain}: {unique_domains}")

            return unique_domains
    except Exception as e:
        print(f"Error fetching Certstream logs: {e}")
    
    return []

# Check if headers leak the origin IP
def find_origin_ip_via_headers(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        headers = response.headers

        for header in ["X-Forwarded-For", "X-Real-IP"]:
            if header in headers:
                print(f"⚠️ {domain} exposes origin IP via {header}: {headers[header]}")
                return headers[header]

    except requests.exceptions.RequestException:
        print(f"Could not retrieve headers from {domain}")

    return None

# Perform a PTR (Reverse DNS) lookup
def find_origin_ip_via_ptr(ip):
    try:
        result = dns.resolver.resolve_address(ip)
        print(f"PTR Record for {ip}: {result[0].to_text()}")
        return result[0].to_text()
    except dns.resolver.NXDOMAIN:
        print(f"No PTR record found for {ip}")
    except Exception as e:
        print(f"PTR lookup error: {e}")

    return None

# Find MX and SPF records that may expose backend IPs
def find_origin_ip_via_mx(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        for record in mx_records:
            print(f"Mail server for {domain}: {record.exchange}")
        
        spf_records = dns.resolver.resolve(domain, 'TXT')
        for record in spf_records:
            if "v=spf1" in record.to_text():
                print(f"SPF Record for {domain}: {record.to_text()}")

    except Exception as e:
        print(f"DNS lookup error: {e}")

# Check for misconfigurations in security headers and open ports
def check_origin_ip(ip):
    try:
        url = f"http://{ip}"
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            headers = response.headers
            print(f"Checking security headers for {ip}:\n")
            if 'X-Frame-Options' not in headers:
                print(f"⚠️ {ip} is missing X-Frame-Options header (Clickjacking risk)")
            if 'Content-Security-Policy' not in headers:
                print(f"⚠️ {ip} is missing Content-Security-Policy header")

        # Check for open ports manually
        open_ports = [80, 443, 22, 3389]  # Common ports
        for port in open_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"⚠️ {ip} has port {port} open")
            sock.close()

    except requests.exceptions.RequestException:
        print(f"Could not connect to {ip}")

# Main execution function
def main():
    domain = "Company.com"

    # Find Company' assets via Shodan
    shodan_assets = find_Company_assets()

    # Find origin IPs via multiple methods
    certstream_domains = find_origin_ip_via_certstream(domain)
    subdomain_ips = find_origin_ip_via_subdomains(domain)

    # Combine all IPs found
    all_ips = set(shodan_assets + subdomain_ips)

    # Perform additional checks
    for ip in all_ips:
        print(f"\n🔍 Analyzing {ip}")
        ptr_hostname = find_origin_ip_via_ptr(ip)
        check_origin_ip(ip)  # Check misconfigurations

    # Find exposed IPs in headers
    leaked_ip = find_origin_ip_via_headers(domain)

    # Find mail servers (may expose backend IPs)
    find_origin_ip_via_mx(domain)

if __name__ == "__main__":
    main()
