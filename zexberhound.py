import requests
import argparse
from bs4 import BeautifulSoup
import subprocess

def get_whois(domain):
    whois_url = f"https://jsonwhois.com/api/v1/whois?domain={domain}"
    response = requests.get(whois_url)
    return response.json()

def scan_ports(ip, ports):
    results = {}
    for port in ports:
        try:
            response = requests.get(f"http://{ip}:{port}", timeout=5)
            results[port] = response.status_code
        except requests.RequestException as e:
            results[port] = str(e)
    return results

def banner_grab(ip, port):
    try:
        result = subprocess.run(["nmap", "-sV", "-p", port, ip], capture_output=True, text=True, timeout=10)
        return result.stdout
    except Exception as e:
        return str(e)

def enum_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}"
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    subdomains = [a['href'].split('/')[0] for a in soup.find_all('a', href=True)]
    return subdomains

def main():
    parser = argparse.ArgumentParser(description="Infoscan - Advanced Information Gathering and Scanning Tool")
    parser.add_argument("domain", help="The domain to gather information about")
    parser.add_argument("ip", help="The IP address to scan")
    parser.add_argument("ports", nargs='+', type=int, help="The ports to scan")
    parser.add_argument("--subdomains", action="store_true", help="Enumerate subdomains")
    parser.add_argument("--banner", action="store_true", help="Grab banner information")

    args = parser.parse_args()

    if args.subdomains:
        subdomains = enum_subdomains(args.domain)
        print(f"Subdomains for {args.domain}:")
        for subdomain in subdomains:
            print(subdomain)

    whois_info = get_whois(args.domain)
    print(f"WHOIS Information for {args.domain}:")
    print(whois_info)

    port_scan_results = scan_ports(args.ip, args.ports)
    print(f"Port Scan Results for {args.ip}:")
    for port, result in port_scan_results.items():
        print(f"Port {port}: {result}")

    if args.banner:
        for port in args.ports:
            banner = banner_grab(args.ip, port)
            print(f"Banner Information for {args.ip}:{port}")
            print(banner)

if __name__ == "__main__":
    main()