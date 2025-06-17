#!/usr/bin/env python3
import os
import sys
import requests
import subprocess
from urllib.parse import urlparse
import argparse
import concurrent.futures
import json
import time
from bs4 import BeautifulSoup

# Banner
def banner():
    print("""
    \033[91m
     ____            _      ____        _   
    |  _ \ ___  _ __| |_   / ___| _ __ | |_ 
    | |_) / _ \| '__| __|  \___ \| '_ \| __|
    |  __/ (_) | |  | |_    ___) | |_) | |_ 
    |_|   \___/|_|   \__|  |____/| .__/ \__|
                                 |_|        
    \033[94m
    Advanced WebPentest Tool for Kali Linux
    Version 2.0 | Integrated with Kali Tools
    \033[0m
    """)

class WebPentestTool:
    def __init__(self, target, output=None, wordlist=None, cookies=None):
        self.target = self.normalize_target(target)
        self.domain = urlparse(self.target).netloc
        self.output = output
        self.wordlist = wordlist or "/usr/share/wordlists/dirb/common.txt"
        self.cookies = cookies
        self.results = {
            'vulnerabilities': [],
            'directories': [],
            'technologies': [],
            'subdomains': []
        }
        self.session = requests.Session()
        if cookies:
            self.session.cookies.update(cookies)
    
    def normalize_target(self, target):
        if not target.startswith(('http://', 'https://')):
            return f'http://{target}'
        return target
    
    def check_live(self):
        try:
            response = self.session.get(self.target, timeout=10)
            return response.status_code < 400
        except Exception as e:
            print(f"\033[91m[!] Target is not reachable: {e}\033[0m")
            return False
    
    def dir_scan(self):
        if not os.path.exists(self.wordlist):
            print(f"\033[91m[!] Wordlist {self.wordlist} not found!\033[0m")
            return
            
        print(f"\033[94m[+] Scanning for directories on {self.target}\033[0m")
        
        def check_dir(directory):
            url = f"{self.target}/{directory}"
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    print(f"\033[92m[+] Found: {url}\033[0m")
                    self.results['directories'].append(url)
            except:
                pass
                
        with open(self.wordlist) as f:
            directories = [line.strip() for line in f if line.strip()]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(check_dir, directories)
    
    def xss_scan(self):
        print(f"\033[94m[+] Checking for XSS vulnerabilities\033[0m")
        
        # Get all forms from the page
        try:
            response = self.session.get(self.target)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            if not forms:
                print("\033[93m[-] No forms found to test for XSS\033[0m")
                return
                
            test_payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "'\"><script>alert('XSS')</script>"
            ]
            
            for form in forms:
                action = form.get('action', self.target)
                method = form.get('method', 'get').lower()
                inputs = form.find_all('input')
                
                for payload in test_payloads:
                    data = {}
                    for input_tag in inputs:
                        name = input_tag.get('name')
                        if name:
                            data[name] = payload
                    
                    if method == 'get':
                        response = self.session.get(action, params=data)
                    else:
                        response = self.session.post(action, data=data)
                    
                    if payload in response.text:
                        print(f"\033[91m[!] Possible XSS vulnerability found in form {action} with payload: {payload}\033[0m")
                        self.results['vulnerabilities'].append({
                            'type': 'XSS',
                            'form': action,
                            'payload': payload
                        })
                        
        except Exception as e:
            print(f"\033[91m[!] XSS scan error: {e}\033[0m")
    
    def sql_scan(self):
        print(f"\033[94m[+] Checking for SQL injection vulnerabilities\033[0m")
        
        # Use sqlmap through subprocess for more thorough testing
        try:
            report_file = f"/tmp/sqlmap_{self.domain.replace('.', '_')}.json"
            cmd = [
                "sqlmap",
                "-u", self.target,
                "--batch",
                "--crawl=1",
                "--level=2",
                "--risk=2",
                "--output-dir=/tmp",
                "--dump-format=JSON",
                "--flush-session"
            ]
            
            if self.cookies:
                cookie_str = "; ".join([f"{k}={v}" for k,v in self.cookies.items()])
                cmd.extend(["--cookie", cookie_str])
            
            print("\033[93m[+] Running sqlmap (this may take some time)...\033[0m")
            subprocess.run(cmd, check=True)
            
            if os.path.exists(report_file):
                with open(report_file) as f:
                    data = json.load(f)
                    for entry in data.get('results', []):
                        if entry.get('vulnerable'):
                            print(f"\033[91m[!] SQLi vulnerability found: {entry['url']}\033[0m")
                            self.results['vulnerabilities'].append({
                                'type': 'SQL Injection',
                                'url': entry['url'],
                                'parameter': entry['parameter'],
                                'payload': entry['payload']
                            })
            
        except Exception as e:
            print(f"\033[91m[!] SQL scan error: {e}\033[0m")
    
    def nikto_scan(self):
        print(f"\033[94m[+] Running Nikto scan\033[0m")
        try:
            report_file = f"/tmp/nikto_{self.domain.replace('.', '_')}.json"
            cmd = [
                "nikto",
                "-h", self.target,
                "-Format", "json",
                "-output", report_file
            ]
            
            print("\033[93m[+] Running Nikto (this may take some time)...\033[0m")
            subprocess.run(cmd, check=True)
            
            if os.path.exists(report_file):
                with open(report_file) as f:
                    data = json.load(f)
                    for item in data.get('vulnerabilities', []):
                        print(f"\033[91m[!] {item['description']}\033[0m")
                        self.results['vulnerabilities'].append({
                            'type': 'Nikto Finding',
                            'description': item['description'],
                            'url': item['url']
                        })
            
        except Exception as e:
            print(f"\033[91m[!] Nikto scan error: {e}\033[0m")
    
    def subdomain_scan(self):
        print(f"\033[94m[+] Scanning for subdomains\033[0m")
        wordlist = "/usr/share/wordlists/dns/subdomains-top1million-5000.txt"
        
        if not os.path.exists(wordlist):
            print("\033[91m[!] Subdomain wordlist not found\033[0m")
            return
            
        def check_subdomain(subdomain):
            url = f"http://{subdomain}.{self.domain}"
            try:
                response = requests.get(url, timeout=5)
                if response.status_code < 400:
                    print(f"\033[92m[+] Found subdomain: {url}\033[0m")
                    self.results['subdomains'].append(url)
            except:
                pass
                
        with open(wordlist) as f:
            subdomains = [line.strip() for line in f if line.strip()]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(check_subdomain, subdomains)
    
    def detect_tech(self):
        print(f"\033[94m[+] Detecting technologies\033[0m")
        try:
            response = self.session.get(self.target)
            headers = response.headers
            
            # Check for common headers
            if 'X-Powered-By' in headers:
                tech = headers['X-Powered-By']
                print(f"\033[92m[+] Technology detected: {tech}\033[0m")
                self.results['technologies'].append(tech)
            
            # Check for common server software
            if 'Server' in headers:
                server = headers['Server']
                print(f"\033[92m[+] Server detected: {server}\033[0m")
                self.results['technologies'].append(server)
            
            # Check HTML for framework signatures
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for WordPress
            if 'wp-content' in response.text:
                print("\033[92m[+] WordPress detected\033[0m")
                self.results['technologies'].append('WordPress')
            
            # Check for jQuery
            scripts = soup.find_all('script')
            for script in scripts:
                if 'jquery' in str(script).lower():
                    print("\033[92m[+] jQuery detected\033[0m")
                    self.results['technologies'].append('jQuery')
                    break
            
        except Exception as e:
            print(f"\033[91m[!] Technology detection error: {e}\033[0m")
    
    def run_all(self):
        print(f"\033[93m[+] Starting comprehensive scan for {self.target}\033[0m")
        start_time = time.time()
        
        if not self.check_live():
            return False
            
        self.detect_tech()
        self.dir_scan()
        self.subdomain_scan()
        self.xss_scan()
        self.sql_scan()
        self.nikto_scan()
        
        duration = time.time() - start_time
        print(f"\n\033[92m[+] Scan completed in {duration:.2f} seconds\033[0m")
        
        if self.results['vulnerabilities']:
            print("\n\033[91m[!] Vulnerabilities found:\033[0m")
            for vuln in self.results['vulnerabilities']:
                print(f"- {vuln['type']}: {vuln.get('description', vuln.get('url', 'Details in report'))}")
        
        if self.output:
            with open(self.output, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"\033[92m[+] Results saved to {self.output}\033[0m")
        
        return True

def parse_cookies(cookie_str):
    if not cookie_str:
        return None
    cookies = {}
    for item in cookie_str.split(';'):
        if '=' in item:
            key, value = item.strip().split('=', 1)
            cookies[key] = value
    return cookies

def main():
    banner()
    
    parser = argparse.ArgumentParser(description='Advanced WebPentest Tool for Kali Linux')
    parser.add_argument('-t', '--target', required=True, help='Target URL or domain')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist for directory scanning')
    parser.add_argument('-c', '--cookies', help='Session cookies (format: "name1=value1; name2=value2")')
    args = parser.parse_args()
    
    cookies = parse_cookies(args.cookies)
    
    tool = WebPentestTool(
        target=args.target,
        output=args.output,
        wordlist=args.wordlist,
        cookies=cookies
    )
    
    tool.run_all()

if __name__ == "__main__":
    main()