import argparse
import socket
import whois
import dns.resolver
import concurrent.futures
import csv
import json
import ssl
import requests
import re
from datetime import datetime
import logging
from pathlib import Path
from typing import Dict, List, Any
import OpenSSL
from bs4 import BeautifulSoup
import paramiko
import ftplib
import dns.zone
import dns.query

class NetworkAnalyzer:
    def __init__(self, target: str, output_dir: str = "reports"):
        """Initialize the network analyzer."""
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.output_dir / 'analysis.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

        # Initialize results dictionary
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scans': {}
        }

    def whois_lookup(self) -> Dict:
        """Perform WHOIS lookup on the target domain."""
        try:
            self.logger.info(f"Performing WHOIS lookup for {self.target}")
            w = whois.whois(self.target)

            # Save WHOIS data
            whois_file = self.output_dir / f"{self.target}_whois.txt"
            with open(whois_file, 'w') as f:
                for key, value in w.items():
                    f.write(f"{key}: {value}\n")

            self.results['scans']['whois'] = dict(w)
            return dict(w)
        except Exception as e:
            self.logger.error(f"WHOIS lookup failed: {str(e)}")
            return None

    def dns_lookup(self) -> Dict:
        """Perform various DNS lookups."""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        results = {}

        try:
            for record in record_types:
                try:
                    self.logger.info(f"Querying {record} records for {self.target}")
                    answers = dns.resolver.resolve(self.target, record)
                    results[record] = [str(answer) for answer in answers]
                except dns.resolver.NoAnswer:
                    results[record] = []
                except Exception as e:
                    self.logger.error(f"Error querying {record} records: {str(e)}")
                    results[record] = []

            # Save DNS results
            dns_file = self.output_dir / f"{self.target}_dns.csv"
            with open(dns_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Record Type', 'Values'])
                for record_type, values in results.items():
                    writer.writerow([record_type, ', '.join(values)])

            self.results['scans']['dns'] = results
            return results
        except Exception as e:
            self.logger.error(f"DNS lookup failed: {str(e)}")
            return None

    def port_scan(self, ports: List[int] = None) -> Dict:
        """Scan common ports on the target."""
        if ports is None:
            ports = [20, 21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080]

        results = {}

        try:
            ip = socket.gethostbyname(self.target)

            def scan_port(port):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                return port, result == 0

            self.logger.info(f"Starting port scan on {self.target}")
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_to_port = {executor.submit(scan_port, port): port for port in ports}
                for future in concurrent.futures.as_completed(future_to_port):
                    port, is_open = future.result()
                    results[port] = is_open

                    # If port is open, try to get service version
                    if is_open:
                        service_info = self.service_version_scan(port)
                        if service_info:
                            results[port] = service_info

            # Save port scan results
            scan_file = self.output_dir / f"{self.target}_ports.csv"
            with open(scan_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Port', 'Status', 'Service', 'Version'])
                for port, info in sorted(results.items()):
                    if isinstance(info, dict):
                        writer.writerow([port, 'Open', info.get('service', 'unknown'),
                                      info.get('version', 'unknown')])
                    else:
                        writer.writerow([port, 'Open' if info else 'Closed', '', ''])

            self.results['scans']['ports'] = results
            return results
        except Exception as e:
            self.logger.error(f"Port scan failed: {str(e)}")
            return None

    def ssl_certificate_check(self) -> Dict:
        """Check SSL/TLS certificate information."""
        try:
            self.logger.info(f"Checking SSL certificate for {self.target}")
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()

                    cert_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serialNumber': cert['serialNumber'],
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter']
                    }

                    self.results['scans']['ssl'] = cert_info
                    return cert_info
        except Exception as e:
            self.logger.error(f"SSL certificate check failed: {str(e)}")
            return None

    def http_headers_check(self) -> Dict:
        """Check HTTP security headers."""
        try:
            self.logger.info(f"Checking HTTP headers for {self.target}")
            response = requests.head(f"https://{self.target}", verify=True)
            headers = dict(response.headers)

            security_headers = {
                'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Not Set'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Not Set'),
                'X-Frame-Options': headers.get('X-Frame-Options', 'Not Set'),
                'X-XSS-Protection': headers.get('X-XSS-Protection', 'Not Set'),
                'Content-Security-Policy': headers.get('Content-Security-Policy', 'Not Set'),
                'Referrer-Policy': headers.get('Referrer-Policy', 'Not Set')
            }

            self.results['scans']['http_headers'] = security_headers
            return security_headers
        except Exception as e:
            self.logger.error(f"HTTP headers check failed: {str(e)}")
            return None

    def subdomain_enumeration(self) -> List[Dict]:
        """Perform subdomain enumeration using DNS."""
        try:
            self.logger.info(f"Performing subdomain enumeration for {self.target}")
            common_subdomains = ['www', 'mail', 'remote', 'blog', 'webmail', 'server',
                               'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'api', 'dev',
                               'staging', 'test', 'portal', 'admin']

            found_subdomains = []
            for subdomain in common_subdomains:
                try:
                    hostname = f"{subdomain}.{self.target}"
                    answers = dns.resolver.resolve(hostname, 'A')
                    if answers:
                        found_subdomains.append({
                            'subdomain': hostname,
                            'ip': [str(answer) for answer in answers]
                        })
                except dns.resolver.NXDOMAIN:
                    continue
                except Exception as e:
                    self.logger.error(f"Error checking subdomain {hostname}: {str(e)}")

            self.results['scans']['subdomains'] = found_subdomains
            return found_subdomains
        except Exception as e:
            self.logger.error(f"Subdomain enumeration failed: {str(e)}")
            return []

    def service_version_scan(self, port: int) -> Dict:
        """Attempt to identify service versions running on open ports."""
        try:
            self.logger.info(f"Checking service version on port {port}")
            service_info = {'port': port, 'service': 'unknown', 'version': 'unknown'}

            if port == 22:  # SSH
                transport = paramiko.Transport((self.target, port))
                transport.get_banner()
                service_info['service'] = 'SSH'
                service_info['version'] = transport.remote_version
                transport.close()
            elif port == 21:  # FTP
                with ftplib.FTP() as ftp:
                    banner = ftp.connect(self.target, port, timeout=5)
                    service_info['service'] = 'FTP'
                    service_info['version'] = banner
            elif port in [80, 443]:  # HTTP/HTTPS
                protocol = 'https' if port == 443 else 'http'
                response = requests.get(f"{protocol}://{self.target}:{port}/",
                                     verify=False, timeout=5)
                server = response.headers.get('Server', 'unknown')
                service_info['service'] = f"HTTP{'S' if port == 443 else ''}"
                service_info['version'] = server

            return service_info
        except Exception as e:
            self.logger.error(f"Service version scan failed for port {port}: {str(e)}")
            return None

    def check_dns_zone_transfer(self) -> List[str]:
        """Attempt to check for DNS zone transfer vulnerability."""
        try:
            self.logger.info(f"Checking DNS zone transfer for {self.target}")
            ns_records = dns.resolver.resolve(self.target, 'NS')
            transfer_results = []

            for ns in ns_records:
                ns_name = str(ns)
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_name, self.target))
                    if zone:
                        transfer_results.append(f"Zone transfer possible from {ns_name}")
                except Exception:
                    transfer_results.append(f"Zone transfer not allowed from {ns_name}")

            self.results['scans']['zone_transfer'] = transfer_results
            return transfer_results
        except Exception as e:
            self.logger.error(f"DNS zone transfer check failed: {str(e)}")
            return []

    def crawl_robots_txt(self) -> Dict:
        """Analyze robots.txt file."""
        try:
            self.logger.info(f"Analyzing robots.txt for {self.target}")
            response = requests.get(f"https://{self.target}/robots.txt")
            if response.status_code == 200:
                lines = response.text.split('\n')
                disallowed = [line.split(': ')[1] for line in lines
                            if line.startswith('Disallow:')]
                allowed = [line.split(': ')[1] for line in lines
                          if line.startswith('Allow:')]

                robots_info = {
                    'disallowed_paths': disallowed,
                    'allowed_paths': allowed,
                    'raw_content': response.text
                }

                self.results['scans']['robots_txt'] = robots_info
                return robots_info
        except Exception as e:
            self.logger.error(f"Robots.txt analysis failed: {str(e)}")
            return None

    def generate_report(self) -> str:
        """Generate a comprehensive HTML report of all findings."""
        report_file = self.output_dir / f"{self.target}_report.html"

        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Analysis Report - {target}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1, h2, h3 { color: #333; }
                .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
                .warning { color: #c00; }
                .success { color: #0c0; }
                table { border-collapse: collapse; width: 100%; margin: 10px 0; }
                th, td { padding: 8px; text-align: left; border: 1px solid #ddd; }
                th { background-color: #f2f2f2; }
                .metadata { color: #666; font-size: 0.9em; }
            </style>
        </head>
        <body>
            <h1>Network Analysis Report</h1>
            <div class="metadata">
                <p>Target: {target}</p>
                <p>Date: {date}</p>
            </div>

            {content}

            <div class="section">
                <h2>Security Recommendations</h2>
                <ul>
                    {recommendations}
                </ul>
            </div>
        </body>
        </html>
        """

        try:
            # Perform all scans
            results = {
                'whois': self.whois_lookup(),
                'dns': self.dns_lookup(),
                'ports': self.port_scan(),
                'ssl': self.ssl_certificate_check(),
                'http_headers': self.http_headers_check(),
                'subdomains': self.subdomain_enumeration(),
                'zone_transfer': self.check_dns_zone_transfer(),
                'robots_txt': self.crawl_robots_txt()
            }

            content = []
            recommendations = []

            # Generate sections for each scan result
            for scan_type, data in results.items():
                if data:
                    content.append(self._generate_section(
                        title=scan_type.replace('_', ' ').title(),
                        data=data
                    ))

                    # Add recommendations based on scan results
                    if scan_type == 'ssl' and 'notAfter' in data:
                        cert_expiry = datetime.strptime(data['notAfter'], '%b %d %H:%M:%S %Y GMT')
                        if (cert_expiry - datetime.now()).days < 30:
                            recommendations.append("SSL Certificate is expiring soon. Plan for renewal.")

                    elif scan_type == 'http_headers':
                        if 'Strict-Transport-Security' not in data:
                            recommendations.append("HSTS header is missing. Consider implementing HSTS.")
                        if 'X-Frame-Options' not in data:
                            recommendations.append("X-Frame-Options header is missing. Consider implementing clickjacking protection.")

                    elif scan_type == 'zone_transfer':
                        if any("possible" in result for result in data):
                            recommendations.append("DNS Zone transfer is possible. Disable zone transfers to unauthorized servers.")

            # Generate the final report
            report_content = html_template.format(
                target=self.target,
                date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                content='\n'.join(content),
                recommendations='\n'.join(f"<li>{r}</li>" for r in recommendations)
            )

            # Save the HTML report
            with open(report_file, 'w') as f:
                f.write(report_content)

            # Save raw results as JSON
            with open(self.output_dir / f"{self.target}_raw_results.json", 'w') as f:
                json.dump(self.results, f, indent=2)

            self.logger.info(f"Report generated successfully: {report_file}")
            return str(report_file)
        except Exception as e:
            self.logger.error(f"Report generation failed: {str(e)}")
            return None

# Main function
def main():
    parser = argparse.ArgumentParser(description='Enhanced Network Analysis Tool')
    parser.add_argument('target', help='Target domain or IP address')
    parser.add_argument('--output', '-o', default='reports', help='Output directory for reports')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--ports', '-p', type=int, nargs='+',
                       help='Specific ports to scan (default: common ports)')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    analyzer = NetworkAnalyzer(args.target, args.output)
    report_path = analyzer.generate_report()

    if report_path:
        print(f"\nReport generated successfully: {report_path}")
        print("\nReport files saved:")
        print(f"- HTML Report: {args.output}/{args.target}_report.html")
        print(f"- Raw Results: {args.output}/{args.target}_raw_results.json")
        print(f"- Analysis Log: {args.output}/analysis.log")
        print("\nPlease use this tool responsibly and only on systems you own or have permission to test.")

if __name__ == '__main__':
    main()
