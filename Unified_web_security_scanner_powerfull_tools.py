#!/usr/bin/env python3
"""
UNIFIED MERN SECURITY SCANNER - ALL IN ONE TOOLKIT
Developed by: CHOWDHURY-VAI CYBER TEAM 💔 & DARK IBRAHIM 💔
Contact: https://t.me/darkvaiadmin
Channel: https://t.me/windowspremiumkey  
Website: https://crackyworld.com/
Team: https://cyberteam.chowdhuryvai.top/
"""

import requests
import json
import os
import sys
import time
import threading
import sqlite3
import hashlib
import base64
import re
import random
import string
import socket
import ssl
import urllib.parse
from datetime import datetime
from urllib.parse import urlparse
import asyncio
import aiohttp

# Color codes for terminal
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    # Extended Colors
    PURPLE = '\033[95m'
    ORANGE = '\033[38;5;214m'
    PINK = '\033[38;5;205m'
    GOLD = '\033[38;5;220m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_BLUE = '\033[44m'
    BG_YELLOW = '\033[43m'

class UnifiedSecurityScanner:
    def __init__(self):
        self.base_url = ""
        self.scanner_type = ""
        self.results = []
        self.vulnerabilities = []
        
    def print_main_banner(self):
        banner = f"""
{Colors.RED}{'█' * 80}
{Colors.CYAN}
▓█████▄  ██▀███   ▒█████   █    ██   ██████  ██░ ██  ██▓ ███▄    █   ▄████ 
▒██▀ ██▌▓██ ▒ ██▒▒██▒  ██▒ ██  ▓██▒▒██    ▒ ▓██░ ██▒▓██▒ ██ ▀█   █  ██▒ ▀█▒
░██   █▌▓██ ░▄█ ▒▒██░  ██▒▓██  ▒██░░ ▓██▄   ▒██▀▀██░▒██▒▓██  ▀█ ██▒▒██░▄▄▄░
░▓█▄   ▌▒██▀▀█▄  ▒██   ██░▓▓█  ░██░  ▒   ██▒░▓█ ░██ ░██░▓██▒  ▐▌██▒░▓█  ██▓
░▒████▓ ░██▓ ▒██▒░ ████▓▒░▒▒█████▓ ▒██████▒▒░▓█▒░██▓░██░▒██░   ▓██░░▒▓███▀▒
 ▒▒▓  ▒ ░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░▒▓▒ ▒ ▒ ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░▓  ░ ▒░   ▒ ▒  ░▒   ▒ 
 ░ ▒  ▒   ░▒ ░ ▒░  ░ ▒ ▒░ ░░▒░ ░ ░ ░ ░▒  ░ ░ ▒ ░▒░ ░ ▒ ░░ ░░   ░ ▒░  ░   ░ 
 ░ ░  ░   ░░   ░ ░ ░ ░ ▒   ░░░ ░ ░ ░  ░  ░   ░  ░░ ░ ▒ ░   ░   ░ ░ ░ ░   ░ 
   ░       ░         ░ ░     ░           ░   ░  ░  ░ ░           ░       ░ 
{Colors.RED}
╔═╗┌─┐┌┬┐┬┌┐┌┌─┐  ╔═╗┌─┐┌─┐┬─┐┌─┐┌┬┐┬┌─┐┌┐┌  ╔═╗┌─┐┌┬┐┌─┐┬─┐┌─┐┌─┐┬ ┬
╠╣ ├─┤ ││││││├┤   ╠╣ │ ││ │├┬┘├─┤ │ ││ ││││  ║  │ │ ││├┤ ├┬┘├─┤└─┐├─┤
╚  ┴ ┴─┴┘┴┘└┘└─┘  ╚  └─┘└─┘┴└─┴ ┴ ┴ ┴└─┘┘└┘  ╚═╝└─┘─┴┘└─┘┴└─┴ ┴└─┘┴ ┴
{Colors.GREEN}
    UNIFIED SECURITY SCANNER - ALL IN ONE TOOLKIT
    {Colors.YELLOW}CHOWDHURY-VAI CYBER TEAM 💔 | DARK IBRAHIM 💔{Colors.END}
    
{Colors.CYAN}    🔥 Contact: https://t.me/darkvaiadmin
    📢 Channel: https://t.me/windowspremiumkey  
    🌐 Website: https://crackyworld.com/
    👥 Team: https://cyberteam.chowdhuryvai.top/{Colors.END}
{'█' * 80}{Colors.END}
        """
        print(banner)

    def print_tool_menu(self):
        menu = f"""
{Colors.BOLD}{Colors.CYAN}🛠️ AVAILABLE SECURITY TOOLS:{Colors.END}

{Colors.GREEN}[1]{Colors.END} Advanced MERN Security Scanner Pro - Ultimate Edition
{Colors.GREEN}[2]{Colors.END} Advanced MERN Authentication Security Scanner  
{Colors.GREEN}[3]{Colors.END} Ultimate Security Scanner - Most Powerful Version
{Colors.GREEN}[4]{Colors.END} Professional Security Scanner - All-in-One

{Colors.YELLOW}[5]{Colors.END} Run All Scanners (Comprehensive Audit)
{Colors.RED}[0]{Colors.END} Exit

{Colors.BLUE}Select an option (0-5): {Colors.END}"""
        print(menu)

    def get_user_input(self):
        try:
            choice = input().strip()
            return choice
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}[!] Operation cancelled by user.{Colors.END}")
            sys.exit(0)

    def get_target_url(self):
        print(f"\n{Colors.BLUE}🎯 Enter target URL (e.g., https://example.com): {Colors.END}", end="")
        try:
            url = input().strip()
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            return url
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}[!] Operation cancelled by user.{Colors.END}")
            sys.exit(0)

# =============================================================================
# TOOL 1: Advanced MERN Security Scanner Pro - Ultimate Edition
# =============================================================================

class AdvancedSecurityScannerPro:
    def __init__(self, base_url):
        self.base_url = base_url
        self.results = []
        self.vulnerabilities = []
        self.session = requests.Session()
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_dir = f"security_reports/{self.scan_id}"
        
        os.makedirs(self.report_dir, exist_ok=True)
        
        self.payloads = {
            "sql_injection": [
                {"name": "Time-Based Blind", "payload": "admin' AND 1=1--"},
                {"name": "Boolean-Based", "payload": "' OR '1'='1' --"},
            ],
            "xss": [
                {"name": "Basic Script", "payload": "<script>alert('XSS')</script>"},
                {"name": "IMG Onerror", "payload": "<img src=x onerror=alert('XSS')>"},
            ]
        }

    def print_banner(self):
        banner = f"""
{Colors.CYAN}{'='*80}
    ADVANCED MERN SECURITY SCANNER PRO - ULTIMATE EDITION
    Target: {self.base_url}
    Scan ID: {self.scan_id}
{'='*80}{Colors.END}
        """
        print(banner)

    def log_result(self, test_name, status, details, severity="INFO", payload=""):
        result = {
            "timestamp": datetime.now().isoformat(),
            "test": test_name,
            "status": status,
            "details": details,
            "severity": severity,
            "payload": payload
        }
        self.results.append(result)
        
        if status == "VULNERABLE":
            color = Colors.RED
            self.vulnerabilities.append(result)
        elif status == "SAFE":
            color = Colors.GREEN
        elif status == "WARNING":
            color = Colors.YELLOW
        else:
            color = Colors.BLUE
        
        print(f"{color}[{status}]{Colors.END} {test_name}: {details}")

    def test_sql_injection(self):
        print(f"\n{Colors.BOLD}[*] Testing SQL Injection...{Colors.END}")
        endpoints = ["/api/auth/login", "/api/login", "/login"]
        
        for endpoint in endpoints:
            url = self.base_url.rstrip('/') + endpoint
            for payload in self.payloads["sql_injection"]:
                try:
                    response = self.session.post(
                        url,
                        json={"username": payload["payload"], "password": "test"},
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        response_text = response.text.lower()
                        if "error" in response_text or "sql" in response_text:
                            self.log_result(
                                f"SQL Injection - {payload['name']}",
                                "VULNERABLE",
                                f"Possible SQL injection at {endpoint}",
                                "HIGH",
                                payload["payload"]
                            )
                    time.sleep(0.2)
                except Exception as e:
                    self.log_result(f"SQL Injection - {payload['name']}", "ERROR", f"Request failed: {str(e)}", "INFO")

    def test_xss(self):
        print(f"\n{Colors.BOLD}[*] Testing XSS Vulnerabilities...{Colors.END}")
        endpoints = ["/search", "/contact", "/comment"]
        
        for endpoint in endpoints:
            url = self.base_url.rstrip('/') + endpoint
            for payload in self.payloads["xss"]:
                try:
                    test_url = url + "?q=" + payload["payload"]
                    response = self.session.get(test_url, timeout=10)
                    
                    if payload["payload"] in response.text:
                        self.log_result(
                            f"XSS - {payload['name']}",
                            "VULNERABLE",
                            f"XSS vulnerability found at {endpoint}",
                            "HIGH",
                            payload["payload"]
                        )
                    time.sleep(0.2)
                except Exception as e:
                    self.log_result(f"XSS - {payload['name']}", "ERROR", f"Request failed: {str(e)}", "INFO")

    def generate_report(self):
        print(f"\n{Colors.BOLD}[*] Generating Report...{Colors.END}")
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Advanced Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; text-align: center; }}
        .vulnerability {{ background: #ffeaea; padding: 10px; margin: 5px 0; border-left: 4px solid #e74c3c; }}
        .safe {{ background: #eaffea; padding: 10px; margin: 5px 0; border-left: 4px solid #2ecc71; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Advanced Security Scan Report</h1>
        <p>Target: {self.base_url} | Scan ID: {self.scan_id}</p>
    </div>
    <h2>Scan Results</h2>
"""
        for result in self.results:
            status_class = "vulnerability" if result['status'] == "VULNERABLE" else "safe"
            html_content += f"""
    <div class="{status_class}">
        <h3>{result['test']} - {result['status']}</h3>
        <p>{result['details']}</p>
        <small>Payload: {result.get('payload', 'N/A')} | {result['timestamp']}</small>
    </div>
"""
        html_content += "</body></html>"
        
        report_path = os.path.join(self.report_dir, "advanced_report.html")
        with open(report_path, 'w') as f:
            f.write(html_content)
        
        return report_path

    def run_scan(self):
        self.print_banner()
        print(f"\n{Colors.BOLD}[*] Starting Advanced Security Scan Pro...{Colors.END}")
        
        start_time = time.time()
        
        self.test_sql_injection()
        self.test_xss()
        
        report_path = self.generate_report()
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n{Colors.GREEN}{'='*80}")
        print(f"[✓] ADVANCED SCAN COMPLETED IN {duration:.2f} SECONDS!")
        print(f"{'='*80}{Colors.END}")
        print(f"  📊 Total Tests: {len(self.results)}")
        print(f"  🔴 Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"  📄 Report: {report_path}")
        
        return report_path

# =============================================================================
# TOOL 2: Advanced MERN Authentication Security Scanner
# =============================================================================

class AuthenticationSecurityScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.results = []
        self.vulnerabilities = []
        self.session = requests.Session()
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_dir = f"security_reports/{self.scan_id}"
        
        os.makedirs(self.report_dir, exist_ok=True)
        
        self.sql_payloads = [
            {"name": "Basic OR 1=1", "username": "' OR '1'='1", "password": "anything"},
            {"name": "Comment Attack", "username": "admin'--", "password": "anything"},
        ]
        
        self.auth_bypass_payloads = [
            {"name": "Empty Credentials", "username": "", "password": ""},
            {"name": "SQL Auth Bypass", "username": "' OR '1'='1'--", "password": "anything"},
        ]

    def print_banner(self):
        banner = f"""
{Colors.CYAN}{'='*80}
    ADVANCED MERN AUTHENTICATION SECURITY SCANNER
    Target: {self.base_url}
    Scan ID: {self.scan_id}
{'='*80}{Colors.END}
        """
        print(banner)

    def log_result(self, test_name, status, details, severity="INFO"):
        result = {
            "timestamp": datetime.now().isoformat(),
            "test": test_name,
            "status": status,
            "details": details,
            "severity": severity
        }
        self.results.append(result)
        
        if status == "VULNERABLE":
            color = Colors.RED
            self.vulnerabilities.append(result)
        elif status == "SAFE":
            color = Colors.GREEN
        elif status == "WARNING":
            color = Colors.YELLOW
        else:
            color = Colors.BLUE
        
        print(f"{color}[{status}]{Colors.END} {test_name}: {details}")

    def test_sql_injection(self):
        print(f"\n{Colors.BOLD}[*] Testing SQL Injection on Authentication...{Colors.END}")
        
        api_endpoints = ["/api/auth/login", "/api/login", "/user/login"]
        
        for endpoint in api_endpoints:
            url = self.base_url.rstrip('/') + endpoint
            
            for payload in self.sql_payloads:
                try:
                    response = self.session.post(
                        url,
                        json={
                            "username": payload["username"],
                            "password": payload["password"]
                        },
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if data.get('token') or data.get('success'):
                                self.log_result(
                                    f"SQL Injection: {payload['name']}",
                                    "VULNERABLE",
                                    f"Authentication bypassed at {endpoint}!",
                                    "CRITICAL"
                                )
                        except:
                            pass
                    
                    time.sleep(0.3)
                    
                except Exception as e:
                    self.log_result(
                        f"SQL Injection: {payload['name']}",
                        "ERROR",
                        f"Request failed: {str(e)}",
                        "INFO"
                    )

    def test_auth_bypass(self):
        print(f"\n{Colors.BOLD}[*] Testing Authentication Bypass...{Colors.END}")
        
        api_endpoints = ["/api/auth/login", "/api/login", "/user/login"]
        
        for endpoint in api_endpoints:
            url = self.base_url.rstrip('/') + endpoint
            
            for payload in self.auth_bypass_payloads:
                try:
                    response = self.session.post(
                        url,
                        json={
                            "username": payload["username"],
                            "password": payload["password"]
                        },
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if data.get('token') or data.get('success'):
                                self.log_result(
                                    f"Auth Bypass: {payload['name']}",
                                    "VULNERABLE",
                                    f"Authentication bypassed at {endpoint}!",
                                    "CRITICAL"
                                )
                        except:
                            pass
                    
                    time.sleep(0.3)
                    
                except Exception as e:
                    self.log_result(
                        f"Auth Bypass: {payload['name']}",
                        "ERROR",
                        f"Request failed: {str(e)}",
                        "INFO"
                    )

    def test_brute_force(self):
        print(f"\n{Colors.BOLD}[*] Testing Brute Force Protection...{Colors.END}")
        
        url = self.base_url.rstrip('/') + "/api/auth/login"
        attempts = 5
        successful_attempts = 0
        
        for i in range(attempts):
            try:
                response = self.session.post(
                    url,
                    json={
                        "username": "testuser",
                        "password": f"wrongpass{i}"
                    },
                    timeout=5
                )
                
                if response.status_code != 429:
                    successful_attempts += 1
                    
            except:
                pass
        
        if successful_attempts == attempts:
            self.log_result(
                "Brute Force Protection",
                "VULNERABLE",
                f"No rate limiting detected!",
                "HIGH"
            )
        else:
            self.log_result(
                "Brute Force Protection",
                "SAFE",
                "Rate limiting detected",
                "INFO"
            )

    def generate_report(self):
        print(f"\n{Colors.BOLD}[*] Generating Authentication Scan Report...{Colors.END}")
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; text-align: center; }}
        .vulnerability {{ background: #ffeaea; padding: 10px; margin: 5px 0; border-left: 4px solid #e74c3c; }}
        .safe {{ background: #eaffea; padding: 10px; margin: 5px 0; border-left: 4px solid #2ecc71; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Authentication Security Scan Report</h1>
        <p>Target: {self.base_url} | Scan ID: {self.scan_id}</p>
    </div>
    <h2>Authentication Test Results</h2>
"""
        for result in self.results:
            status_class = "vulnerability" if result['status'] == "VULNERABLE" else "safe"
            html_content += f"""
    <div class="{status_class}">
        <h3>{result['test']} - {result['status']}</h3>
        <p>{result['details']}</p>
        <small>Severity: {result['severity']} | {result['timestamp']}</small>
    </div>
"""
        html_content += "</body></html>"
        
        report_path = os.path.join(self.report_dir, "authentication_report.html")
        with open(report_path, 'w') as f:
            f.write(html_content)
        
        return report_path

    def run_scan(self):
        self.print_banner()
        print(f"\n{Colors.BOLD}[*] Starting Authentication Security Scan...{Colors.END}")
        
        start_time = time.time()
        
        self.test_sql_injection()
        self.test_auth_bypass()
        self.test_brute_force()
        
        report_path = self.generate_report()
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n{Colors.GREEN}{'='*80}")
        print(f"[✓] AUTHENTICATION SCAN COMPLETED IN {duration:.2f} SECONDS!")
        print(f"{'='*80}{Colors.END}")
        print(f"  📊 Total Tests: {len(self.results)}")
        print(f"  🔴 Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"  📄 Report: {report_path}")
        
        return report_path

# =============================================================================
# TOOL 3: Ultimate Security Scanner - Most Powerful Version
# =============================================================================

class UltimateSecurityScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.results = []
        self.vulnerabilities = []
        self.session = requests.Session()
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        self.report_dir = f"security_reports/{self.scan_id}"
        
        os.makedirs(self.report_dir, exist_ok=True)
        
        self.payloads = {
            "sql_injection_advanced": [
                {"name": "Polyglot SQLi", "payload": "SLEEP(5) /*' OR '1'='1' UNION SELECT 1,2,3,4,5,6-- - */", "type": "polyglot"},
                {"name": "JSON SQLi", "payload": '{"username": {"$eq": "admin"}, "password": {"$ne": null}}', "type": "json"},
            ],
            "xss_advanced": [
                {"name": "Polyglot XSS", "payload": "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"+/+/onmouseover=1/+/[*/[]/+alert(1)//'>", "type": "polyglot"},
                {"name": "SVG XSS Advanced", "payload": "<svg onload=alert(document.domain)>", "type": "svg"},
            ]
        }

    def print_banner(self):
        banner = f"""
{Colors.PURPLE}{Colors.BOLD}
{'█' * 80}
    ULTIMATE SECURITY SCANNER - MOST POWERFUL VERSION
    Target: {self.base_url}
    Scan ID: {self.scan_id}
{'█' * 80}{Colors.END}
        """
        print(banner)

    def log_result(self, test_category, test_name, status, details, severity="INFO", payload="", cvss_score=0.0):
        result = {
            "timestamp": datetime.now().isoformat(),
            "category": test_category,
            "test": test_name,
            "status": status,
            "details": details,
            "severity": severity,
            "payload": payload,
            "cvss_score": cvss_score
        }
        
        self.results.append(result)
        
        if status == "VULNERABLE":
            color = Colors.RED
            self.vulnerabilities.append(result)
        elif status == "SAFE":
            color = Colors.GREEN
        elif status == "WARNING":
            color = Colors.YELLOW
        else:
            color = Colors.BLUE
        
        print(f"{color}[{severity}] {test_category} -> {test_name}{Colors.END}")
        print(f"   📝 Details: {details}")
        if payload:
            print(f"   🎯 Payload: {payload[:100]}...")

    def advanced_sql_injection_test(self):
        print(f"\n{Colors.BOLD}[🔍] Starting Advanced SQL Injection Detection...{Colors.END}")
        
        endpoints = self.discover_endpoints()
        
        for endpoint in endpoints:
            for payload in self.payloads["sql_injection_advanced"]:
                try:
                    url = self.base_url.rstrip('/') + endpoint
                    
                    start_time = time.time()
                    response = self.session.post(
                        url,
                        json={"username": payload["payload"], "password": "test123"},
                        timeout=15
                    )
                    response_time = time.time() - start_time
                    
                    detection_score = 0
                    reasons = []
                    
                    if response_time > 5:
                        detection_score += 30
                        reasons.append("Time-based delay detected")
                    
                    response_text_lower = response.text.lower()
                    sql_errors = ['sql', 'mysql', 'oracle', 'syntax error']
                    
                    for error in sql_errors:
                        if error in response_text_lower:
                            detection_score += 20
                            reasons.append(f"SQL error: {error}")
                            break
                    
                    success_indicators = ['token', 'success', 'true', 'welcome']
                    if any(indicator in response_text_lower for indicator in success_indicators):
                        detection_score += 50
                        reasons.append("Authentication bypass successful")
                    
                    if detection_score >= 50:
                        status = "VULNERABLE"
                        severity = "CRITICAL" if detection_score >= 70 else "HIGH"
                        self.log_result(
                            "SQL Injection", 
                            f"Advanced - {payload['name']}", 
                            status, 
                            f"SQLi detected: {', '.join(reasons)}", 
                            severity, 
                            payload["payload"],
                            min(detection_score/10, 10.0)
                        )
                    else:
                        self.log_result(
                            "SQL Injection", 
                            f"Advanced - {payload['name']}", 
                            "SAFE", 
                            "No SQL injection detected", 
                            "INFO", 
                            payload["payload"]
                        )
                    
                    time.sleep(0.3)
                    
                except Exception as e:
                    self.log_result("SQLi", payload["name"], "ERROR", f"Request failed: {str(e)}", "INFO")

    def advanced_xss_test(self):
        print(f"\n{Colors.BOLD}[🔍] Starting Advanced XSS Detection...{Colors.END}")
        
        endpoints = self.discover_endpoints()
        
        for endpoint in endpoints:
            for payload in self.payloads["xss_advanced"]:
                try:
                    url = self.base_url.rstrip('/') + endpoint
                    
                    response = self.session.post(
                        url,
                        data={"input": payload["payload"], "comment": payload["payload"]},
                        timeout=10
                    )
                    
                    if payload["payload"] in response.text:
                        self.log_result(
                            "XSS", 
                            f"Advanced - {payload['name']}", 
                            "VULNERABLE", 
                            f"XSS payload reflected at {endpoint}", 
                            "HIGH", 
                            payload["payload"],
                            7.5
                        )
                    else:
                        self.log_result(
                            "XSS", 
                            f"Advanced - {payload['name']}", 
                            "SAFE", 
                            "Payload not reflected", 
                            "INFO", 
                            payload["payload"]
                        )
                    
                    time.sleep(0.3)
                    
                except Exception as e:
                    self.log_result("XSS", payload["name"], "ERROR", f"Request failed: {str(e)}", "INFO")

    def discover_endpoints(self):
        print(f"\n{Colors.BOLD}[🎯] Discovering Endpoints...{Colors.END}")
        
        common_endpoints = [
            "/api/auth/login", "/api/login", "/auth/login", "/login",
            "/api/auth/register", "/api/register", "/register",
            "/api/user", "/api/users", "/api/profile"
        ]
        
        discovered_endpoints = []
        
        for endpoint in common_endpoints:
            url = self.base_url.rstrip('/') + endpoint
            try:
                response = self.session.head(url, timeout=5)
                if response.status_code != 404:
                    discovered_endpoints.append(endpoint)
                    print(f"{Colors.GREEN}[+] Found: {endpoint} ({response.status_code}){Colors.END}")
            except:
                pass
        
        return discovered_endpoints

    def generate_report(self):
        print(f"\n{Colors.BOLD}[📊] Generating Ultimate Security Report...{Colors.END}")
        
        total_tests = len(self.results)
        critical = len([r for r in self.vulnerabilities if r['severity'] == 'CRITICAL'])
        high = len([r for r in self.vulnerabilities if r['severity'] == 'HIGH'])
        risk_score = self.calculate_risk_score()
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Ultimate Security Scan Report - {self.scan_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #0f0f0f; color: #fff; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: linear-gradient(45deg, #ff0000, #0000ff); padding: 30px; border-radius: 10px; text-align: center; }}
        .risk-score {{ font-size: 2em; color: #ff0000; font-weight: bold; }}
        .vulnerability {{ background: #1a1a1a; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #ff0000; }}
        .high {{ border-left: 5px solid #ff6b00; }}
        .medium {{ border-left: 5px solid #ffeb00; }}
        .low {{ border-left: 5px solid #00ff00; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ ULTIMATE SECURITY SCAN REPORT</h1>
            <h2>Developed by CHOWDHURY-VAI CYBER TEAM & DARK IBRAHIM</h2>
            <div class="risk-score">Overall Risk Score: {risk_score}/100</div>
        </div>
        
        <h2>Scan Summary</h2>
        <p><strong>Target:</strong> {self.base_url}</p>
        <p><strong>Scan ID:</strong> {self.scan_id}</p>
        <p><strong>Total Tests:</strong> {total_tests}</p>
        <p><strong>Critical Vulnerabilities:</strong> {critical}</p>
        <p><strong>High Vulnerabilities:</strong> {high}</p>
        
        <h2>Contact Information</h2>
        <p><strong>Telegram:</strong> https://t.me/darkvaiadmin</p>
        <p><strong>Website:</strong> https://crackyworld.com/</p>
        <p><strong>Cyber Team:</strong> https://cyberteam.chowdhuryvai.top/</p>
        
        <h2>Detailed Findings</h2>
"""
        for result in self.results:
            severity_class = result['severity'].lower()
            html_content += f"""
        <div class="vulnerability {severity_class}">
            <h3>{result['test']} - {result['status']}</h3>
            <p><strong>Category:</strong> {result['category']}</p>
            <p><strong>Details:</strong> {result['details']}</p>
            <p><strong>CVSS Score:</strong> {result['cvss_score']}</p>
            <p><strong>Payload:</strong> {result.get('payload', 'N/A')}</p>
            <p><strong>Timestamp:</strong> {result['timestamp']}</p>
        </div>
"""
        html_content += "</div></body></html>"
        
        report_path = os.path.join(self.report_dir, "ultimate_report.html")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return report_path

    def calculate_risk_score(self):
        base_score = 0
        for vuln in self.vulnerabilities:
            if vuln['severity'] == 'CRITICAL':
                base_score += 15
            elif vuln['severity'] == 'HIGH':
                base_score += 10
            elif vuln['severity'] == 'MEDIUM':
                base_score += 5
        
        return min(base_score, 100)

    def run_scan(self):
        self.print_banner()
        print(f"\n{Colors.BOLD}[🚀] Starting Ultimate Security Scan...{Colors.END}")
        
        start_time = time.time()
        
        self.advanced_sql_injection_test()
        self.advanced_xss_test()
        
        report_path = self.generate_report()
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n{Colors.GREEN}{'█' * 80}")
        print(f"🎉 ULTIMATE SECURITY SCAN COMPLETED!")
        print(f"{'█' * 80}{Colors.END}")
        
        print(f"\n{Colors.BOLD}📈 SCAN STATISTICS:{Colors.END}")
        print(f"  ⏱️  Duration: {duration:.2f} seconds")
        print(f"  🧪 Tests Completed: {len(self.results)}")
        print(f"  🔴 Critical Vulnerabilities: {len([r for r in self.vulnerabilities if r['severity'] == 'CRITICAL'])}")
        print(f"  🟠 High Vulnerabilities: {len([r for r in self.vulnerabilities if r['severity'] == 'HIGH'])}")
        print(f"  ⚡ Overall Risk Score: {self.calculate_risk_score()}/100")
        print(f"  📄 Report: {report_path}")
        
        return report_path

# =============================================================================
# TOOL 4: Professional Security Scanner - All-in-One
# =============================================================================

class ProfessionalSecurityScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.results = []
        self.vulnerabilities = []
        self.session = requests.Session()
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_dir = f"security_reports/{self.scan_id}"
        
        os.makedirs(self.report_dir, exist_ok=True)
        
        self.payloads = {
            "sql_injection": [
                {"name": "Basic OR 1=1", "payload": "' OR '1'='1", "type": "auth_bypass"},
                {"name": "Comment Attack", "payload": "admin'--", "type": "auth_bypass"},
            ],
            "xss": [
                {"name": "Basic Script", "payload": "<script>alert('XSS')</script>", "type": "reflected"},
                {"name": "IMG Onerror", "payload": "<img src=x onerror=alert(1)>", "type": "dom"},
            ]
        }

    def print_banner(self):
        banner = f"""
{Colors.RED}{'='*80}
    PROFESSIONAL SECURITY SCANNER - ALL IN ONE
    Target: {self.base_url}
    Scan ID: {self.scan_id}
{'='*80}{Colors.END}
        """
        print(banner)

    def log_result(self, test_name, status, details, severity="INFO", payload=""):
        result = {
            "timestamp": datetime.now().isoformat(),
            "test": test_name,
            "status": status,
            "details": details,
            "severity": severity,
            "payload": payload
        }
        self.results.append(result)
        
        if status == "VULNERABLE":
            color = Colors.RED
            self.vulnerabilities.append(result)
        elif status == "SAFE":
            color = Colors.GREEN
        elif status == "WARNING":
            color = Colors.YELLOW
        else:
            color = Colors.BLUE
        
        print(f"{color}[{status}]{Colors.END} {test_name}: {details}")

    def test_sql_injection_comprehensive(self):
        print(f"\n{Colors.BOLD}[*] Testing SQL Injection...{Colors.END}")
        
        endpoints = ["/api/auth/login", "/api/login", "/login"]
        
        for endpoint in endpoints:
            url = self.base_url.rstrip('/') + endpoint
            
            for payload in self.payloads["sql_injection"]:
                try:
                    response = self.session.post(
                        url,
                        json={"username": payload["payload"], "password": "test123"},
                        timeout=15
                    )
                    
                    if response.status_code == 200:
                        response_text = response.text.lower()
                        success_indicators = ['token', 'success', 'true', 'welcome']
                        
                        if any(indicator in response_text for indicator in success_indicators):
                            self.log_result(
                                f"SQL Injection - {payload['name']}",
                                "VULNERABLE",
                                f"Authentication bypass at {endpoint}",
                                "CRITICAL",
                                payload["payload"]
                            )
                    
                    error_indicators = ['sql', 'mysql', 'oracle', 'syntax error']
                    if any(error in response_text for error in error_indicators):
                        self.log_result(
                            f"SQL Injection - {payload['name']}",
                            "VULNERABLE",
                            f"SQL error leaked at {endpoint}",
                            "HIGH",
                            payload["payload"]
                        )
                    
                    time.sleep(0.3)
                    
                except Exception as e:
                    self.log_result(f"SQL Injection - {payload['name']}", "ERROR", f"Request failed: {str(e)}", "INFO")

    def test_xss_comprehensive(self):
        print(f"\n{Colors.BOLD}[*] Testing XSS...{Colors.END}")
        
        endpoints = ["/api/auth/login", "/api/login", "/contact", "/search"]
        
        for endpoint in endpoints:
            url = self.base_url.rstrip('/') + endpoint
            
            for payload in self.payloads["xss"]:
                try:
                    if endpoint in ["/api/auth/login", "/api/login"]:
                        response = self.session.post(
                            url,
                            json={"username": payload["payload"], "password": "test123"},
                            timeout=10
                        )
                    else:
                        response = self.session.post(
                            url,
                            data={"username": payload["payload"], "comment": payload["payload"]},
                            timeout=10
                        )
                    
                    if payload["payload"] in response.text:
                        self.log_result(
                            f"XSS - {payload['name']}",
                            "VULNERABLE",
                            f"XSS payload reflected at {endpoint}",
                            "HIGH",
                            payload["payload"]
                        )
                    
                    time.sleep(0.3)
                    
                except Exception as e:
                    self.log_result(f"XSS - {payload['name']}", "ERROR", f"Request failed: {str(e)}", "INFO")

    def test_security_headers(self):
        print(f"\n{Colors.BOLD}[*] Testing Security Headers...{Colors.END}")
        
        try:
            response = self.session.get(self.base_url, timeout=10)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'XSS protection'
            }
            
            missing_headers = []
            
            for header, description in security_headers.items():
                header_found = False
                for existing_header in headers:
                    if existing_header.lower() == header.lower():
                        header_found = True
                        break
                
                if not header_found:
                    missing_headers.append(f"{header}")
            
            if missing_headers:
                self.log_result(
                    "Security Headers",
                    "WARNING",
                    f"Missing security headers: {', '.join(missing_headers)}",
                    "MEDIUM"
                )
            else:
                self.log_result(
                    "Security Headers",
                    "SAFE",
                    "All important security headers present",
                    "INFO"
                )
                
        except Exception as e:
            self.log_result("Security Headers", "ERROR", f"Failed to check headers: {str(e)}", "INFO")

    def generate_report(self):
        print(f"\n{Colors.BOLD}[*] Generating Professional Report...{Colors.END}")
        
        total_tests = len(self.results)
        critical_vulns = len([r for r in self.vulnerabilities if r['severity'] == 'CRITICAL'])
        high_vulns = len([r for r in self.vulnerabilities if r['severity'] == 'HIGH'])
        risk_score = self.calculate_risk_score()
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Professional Security Scan Report - {self.scan_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; text-align: center; }}
        .summary {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .summary-card {{ padding: 15px; border-radius: 5px; text-align: center; color: white; }}
        .critical {{ background: #e74c3c; }}
        .high {{ background: #e67e22; }}
        .total {{ background: #3498db; }}
        .vulnerability {{ background: #ffeaea; padding: 10px; margin: 5px 0; border-left: 4px solid #e74c3c; }}
        .safe {{ background: #eaffea; padding: 10px; margin: 5px 0; border-left: 4px solid #2ecc71; }}
        .warning {{ background: #fff3cd; padding: 10px; margin: 5px 0; border-left: 4px solid #ffc107; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Professional Security Scan Report</h1>
        <p>Target: {self.base_url} | Scan ID: {self.scan_id}</p>
    </div>
    
    <div class="summary">
        <div class="summary-card total">
            <h3>{total_tests}</h3>
            <p>Total Tests</p>
        </div>
        <div class="summary-card critical">
            <h3>{critical_vulns}</h3>
            <p>Critical</p>
        </div>
        <div class="summary-card high">
            <h3>{high_vulns}</h3>
            <p>High</p>
        </div>
        <div class="summary-card total">
            <h3>{risk_score}/100</h3>
            <p>Risk Score</p>
        </div>
    </div>
    
    <h2>Scan Results</h2>
"""
        for result in self.results:
            if result['status'] == "VULNERABLE":
                status_class = "vulnerability"
            elif result['status'] == "SAFE":
                status_class = "safe"
            else:
                status_class = "warning"
                
            html_content += f"""
    <div class="{status_class}">
        <h3>{result['test']} - {result['status']} [{result['severity']}]</h3>
        <p>{result['details']}</p>
        {f'<p><strong>Payload:</strong> {result["payload"]}</p>' if result.get('payload') else ''}
        <small>{result['timestamp']}</small>
    </div>
"""
        html_content += """
    <div style="margin-top: 40px; padding: 20px; background: #f8f9fa; border-radius: 5px;">
        <h3>Contact Information</h3>
        <p><strong>Developed by:</strong> CHOWDHURY-VAI CYBER TEAM 💔 & DARK IBRAHIM 💔</p>
        <p><strong>Telegram:</strong> https://t.me/darkvaiadmin</p>
        <p><strong>Website:</strong> https://crackyworld.com/</p>
        <p><strong>Cyber Team:</strong> https://cyberteam.chowdhuryvai.top/</p>
    </div>
</body>
</html>
"""
        
        report_path = os.path.join(self.report_dir, "professional_report.html")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return report_path

    def calculate_risk_score(self):
        score = 0
        for vuln in self.vulnerabilities:
            if vuln['severity'] == 'CRITICAL':
                score += 10
            elif vuln['severity'] == 'HIGH':
                score += 7
            elif vuln['severity'] == 'MEDIUM':
                score += 4
        
        return min(score, 100)

    def run_scan(self):
        self.print_banner()
        print(f"\n{Colors.BOLD}[*] Starting Professional Security Scan...{Colors.END}")
        
        start_time = time.time()
        
        self.test_sql_injection_comprehensive()
        self.test_xss_comprehensive()
        self.test_security_headers()
        
        report_path = self.generate_report()
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n{Colors.GREEN}{'='*80}")
        print(f"🎯 PROFESSIONAL SECURITY SCAN COMPLETED!")
        print(f"{'='*80}{Colors.END}")
        print(f"  ⏱️  Duration: {duration:.2f} seconds")
        print(f"  🧪 Total Tests: {len(self.results)}")
        print(f"  🔴 Critical Vulnerabilities: {len([r for r in self.vulnerabilities if r['severity'] == 'CRITICAL'])}")
        print(f"  🟠 High Vulnerabilities: {len([r for r in self.vulnerabilities if r['severity'] == 'HIGH'])}")
        print(f"  ⚡ Overall Risk Score: {self.calculate_risk_score()}/100")
        print(f"  📄 Report: {report_path}")
        
        return report_path

# =============================================================================
# MAIN EXECUTION
# =============================================================================

def main():
    unified_scanner = UnifiedSecurityScanner()
    unified_scanner.print_main_banner()
    
    while True:
        unified_scanner.print_tool_menu()
        choice = unified_scanner.get_user_input()
        
        if choice == '0':
            print(f"\n{Colors.GREEN}[+] Thank you for using Unified Security Scanner!{Colors.END}")
            break
            
        elif choice in ['1', '2', '3', '4', '5']:
            target_url = unified_scanner.get_target_url()
            
            if choice == '1':
                print(f"\n{Colors.CYAN}[+] Starting Advanced MERN Security Scanner Pro...{Colors.END}")
                scanner = AdvancedSecurityScannerPro(target_url)
                scanner.run_scan()
                
            elif choice == '2':
                print(f"\n{Colors.CYAN}[+] Starting Authentication Security Scanner...{Colors.END}")
                scanner = AuthenticationSecurityScanner(target_url)
                scanner.run_scan()
                
            elif choice == '3':
                print(f"\n{Colors.CYAN}[+] Starting Ultimate Security Scanner...{Colors.END}")
                scanner = UltimateSecurityScanner(target_url)
                scanner.run_scan()
                
            elif choice == '4':
                print(f"\n{Colors.CYAN}[+] Starting Professional Security Scanner...{Colors.END}")
                scanner = ProfessionalSecurityScanner(target_url)
                scanner.run_scan()
                
            elif choice == '5':
                print(f"\n{Colors.CYAN}[+] Starting Comprehensive Security Audit...{Colors.END}")
                
                # Run all scanners
                scanners = [
                    ("Advanced MERN Security Scanner Pro", AdvancedSecurityScannerPro),
                    ("Authentication Security Scanner", AuthenticationSecurityScanner),
                    ("Ultimate Security Scanner", UltimateSecurityScanner),
                    ("Professional Security Scanner", ProfessionalSecurityScanner)
                ]
                
                all_reports = []
                
                for scanner_name, scanner_class in scanners:
                    print(f"\n{Colors.YELLOW}[→] Running {scanner_name}...{Colors.END}")
                    try:
                        scanner = scanner_class(target_url)
                        report_path = scanner.run_scan()
                        all_reports.append((scanner_name, report_path))
                        time.sleep(2)  # Brief pause between scanners
                    except Exception as e:
                        print(f"{Colors.RED}[!] {scanner_name} failed: {str(e)}{Colors.END}")
                
                print(f"\n{Colors.GREEN}{'='*80}")
                print(f"🎉 COMPREHENSIVE AUDIT COMPLETED!")
                print(f"{'='*80}{Colors.END}")
                print(f"\n{Colors.BOLD}📋 ALL REPORTS GENERATED:{Colors.END}")
                for scanner_name, report_path in all_reports:
                    print(f"  📄 {scanner_name}: {report_path}")
                    
        else:
            print(f"\n{Colors.RED}[!] Invalid choice. Please select 0-5.{Colors.END}")
        
        print(f"\n{Colors.CYAN}{'='*50}{Colors.END}")
        continue_prompt = input(f"{Colors.BLUE}Press Enter to continue or 'q' to quit: {Colors.END}").strip().lower()
        if continue_prompt == 'q':
            print(f"\n{Colors.GREEN}[+] Thank you for using Unified Security Scanner!{Colors.END}")
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Operation cancelled by user.{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}[!] An error occurred: {str(e)}{Colors.END}")
