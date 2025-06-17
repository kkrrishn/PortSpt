# PortSpt
A powerful all-in-one penetration testing tool for Kali Linux that combines security scanning (SQLi, XSS, Nikto, sqlmap) with performance optimization (unused plugins, duplicate code). 
# Advanced Web Pentesting Toolkit for Kali Linux

![Python](https://img.shields.io/badge/python-3.8+-blue)
![Kali](https://img.shields.io/badge/Kali-Linux-red)
![License](https://img.shields.io/badge/license-MIT-green)
![PortSpot](https://img.shields.io/badge/integration-PortSpot-orange)

A Swiss Army knife for web penetration testing, combining automated vulnerability scanning with deep performance analysis and PortSpot integration for comprehensive network assessment.

## 🔥 Features

### 🛡️ Integrated Security Scanning
- **SQL Injection Testing** (sqlmap integration)
- **Vulnerability Assessment** (Nikto integration)
- **XSS Detection** with advanced form handling
- **Subdomain Enumeration** with smart brute-forcing
- **CMS Fingerprinting** (WordPress, Joomla, Drupal)

### ⚡ Performance Optimization
- Unused plugin/library detection
- Duplicate code identification
- Render-blocking resource analysis
- Asset compression recommendations

### 🌐 PortSpot Integration
- Automated port scanning
- Service fingerprinting
- Vulnerability correlation
- Network mapping visualization

### 📊 Reporting
- JSON report generation
- Color-coded terminal output
- HTML executive summaries
- PortSpot-compatible exports

## 🚀 Installation

```bash
# Clone repository
git clone https://github.com/yourusername/PortSpt.git
cd PortSpt

# Install dependencies
sudo apt update && sudo apt install -y \
  python3-requests \
  python3-bs4 \
  nikto \
  sqlmap \
  nmap \
  PortSpot

# Make script executable
chmod +x webpentest.py

# Basic scan
./PortSpt.py -t http://example.com

# Full scan with PortSpot integration
./PortSpt.py -t http://example.com --portspot --deep


🛠️ Advanced Options
Parameter	Description	Example
-t URL	Target URL	-t http://test.com
-w PATH	Custom wordlist	-w ~/wordlists/custom.txt
-c COOKIES	Session cookies	-c "PHPSESSID=1234"
-o FILE	Output file	-o report.json
--portspot	Enable PortScan	--portspot
--brute	Enable brute force	--brute
--proxy PROXY	Use proxy	--proxy http://127.0.0.1:8080
📌 Sample Workflow
Initial Recon

./PortSpt.py -t http://target.com --portspot -o initial_scan.json
Authenticated Scan

./PortSpt.py -t http://target.com/admin -c "session_cookie=value" --deep
Brute Force Discovery


./PortSpt.py -t http://target.com --brute -w /usr/share/wordlists/dirbuster.txt
📊 PortSpot Integration
#The tool automatically:

Maps open ports to discovered web services

Correlates vulnerabilities with network services

Generates interactive network diagrams

Exports data to PortSpot for team collaboration

https://example.com/portspot-diagram.png

📝 Sample Report
{
  "target": "http://example.com",
  "ports": [80, 443, 8080],
  "vulnerabilities": [
    {
      "type": "SQLi",
      "url": "/product.php?id=1",
      "confidence": "high",
      "port": 80
    }
  ],
  "performance": {
    "unused_js": ["jquery.old.js"],
    "duplicate_code": ["main.js", "old/main.js"]
  }
}
🛠️ Future Roadmap
Enhanced CMS scanning modules

Cloud infrastructure detection

API security testing

Automated exploit chaining

Real-time collaboration via PortSpot

🤝 Contributing
Fork the repository

Create your feature branch (git checkout -b feature/AmazingFeature)

Commit your changes (git commit -m 'Add some AmazingFeature')

Push to the branch (git push origin feature/AmazingFeature)

Open a Pull Request

📜 License
Distributed under the MIT License. See LICENSE for more information.

📧 Contact


Project Link: https://github.com/kkrrishn/PortSpt



