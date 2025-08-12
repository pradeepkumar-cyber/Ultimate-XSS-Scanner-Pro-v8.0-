# 🚀 Ultimate XSS Scanner Pro v8.0  

![License](https://img.shields.io/badge/License-MIT-green)
![Python](https://img.shields.io/badge/Python-3.x-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali%20%7C%20Ubuntu-orange)
![Security](https://img.shields.io/badge/Security-Testing%20Tool-red)

---

## 📌 About
**Ultimate XSS Scanner Pro v8.0** is an **AI-powered** Cross-Site Scripting (XSS) vulnerability scanner  
for **ethical hackers, penetration testers, and bug bounty hunters**.  

✅ Finds XSS vulnerabilities using **AI-generated payloads**  
✅ Detects **DOM-based** & **reflected XSS**  
✅ Checks for **CSP bypasses**  
✅ Generates **beautiful HTML & JSON reports**  

---

## ✨ Features
- 🤖 AI-based payload generation
- 🔍 DOM-based & reflected XSS detection
- 🛡 CSP analysis & bypass detection
- ⚡ Multi-threaded scanning
- 📊 HTML & JSON reports
- 🌐 Subdomain enumeration
- 📂 URL collection from multiple sources
- 🔍 WAF detection
- ✅ False positive reduction

---

## ⚙️ Quick Install (Copy & Paste)
```bash
# 1. Clone the tool
git clone https://github.com/yourusername/ultimate-xss-scanner-pro.git
cd ultimate-xss-scanner-pro

# 2. Install Python dependencies
pip3 install -r requirements.txt

# 3. Install Go (if not installed)
sudo apt install golang -y

# 4. Install required Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# 5. Add Go tools to PATH
export PATH=$PATH:$(go env GOPATH)/bin
source ~/.bashrc

## 🖥 Usage

### 🔹 Basic Scan
```bash
python3 xss_scanner.py example.com

## 🖥 Usage

### 🔹 Basic Scan
```bash
python3 xss_scanner.py example.com


#Full Scan (with subdomain enumeration)
```bash
python3 xss_scanner.py example.com --full

