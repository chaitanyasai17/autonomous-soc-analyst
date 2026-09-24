"""WebSecurityScanner — safe, defensive, authorized security checks for web targets."""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import time
import urllib.parse
from datetime import datetime
from typing import Any, Dict, List, Tuple

import urllib.request
import urllib.error
import uuid

from app.core.exceptions import ValidationFailedError, PermissionDeniedError
from app.models.enums import RiskLevel

logger = logging.getLogger(__name__)

# Standard allowed private/internal host patterns
DEFAULT_ALLOWED_PATTERNS = [
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "testserver",
    "*.local",
    "*.internal",
    "*.corp",
]

# Sensitive patterns that should NEVER be logged or leaked
REDACTED_PATTERNS = [
    r"(?i)bearer\s+[a-z0-9_\-\.]+",
    r"(?i)password\s*=\s*[^\s&]+",
    r"(?i)api[-_]?key\s*=\s*[^\s&]+",
]

PORT_SERVICE_MAP: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


class WebSecurityScanner:
    """
    Authorized defensive web security testing engine.
    Performs passive, non-destructive configuration and syntax-resilience checks.
    """

    def __init__(self, target_url: str, custom_allowlist: List[str] | None = None, timeout: int = 5):
        raw_clean = target_url.strip()
        if "://" not in raw_clean:
            raw_clean = f"http://{raw_clean}"
        self.raw_target_url = raw_clean
        self.parsed_url = urllib.parse.urlparse(self.raw_target_url)

        self.target_host = (self.parsed_url.hostname or "").lower()
        self.target_port = self.parsed_url.port or (443 if self.parsed_url.scheme == "https" else 80)
        self.custom_allowlist = [p.lower().strip() for p in (custom_allowlist or [])]
        self.timeout = min(max(timeout, 2), 15)
        self.resolved_ip: str | None = None
        self.exposed_services: List[Dict[str, Any]] = []

    def validate_target_authorization(self) -> bool:
        """
        Enforce strict safety allowlist check and DNS verification.
        Only localhost, private RFC1918 subnets, or explicitly allowlisted hosts are permitted.
        """
        host = self.target_host
        if not host:
            raise ValidationFailedError("Invalid target URL: missing hostname or IP.")

        # Attempt DNS resolution / IP validation
        resolved_ip_str: str | None = None
        try:
            ip_obj = ipaddress.ip_address(host)
            resolved_ip_str = str(ip_obj)
        except ValueError:
            # It's a hostname (e.g. localhost or app.local)
            try:
                try:
                    addr_info = socket.getaddrinfo(host, None, socket.AF_INET)
                except Exception:
                    addr_info = socket.getaddrinfo(host, None)
                if addr_info:
                    resolved_ip_str = addr_info[0][4][0]
            except Exception:
                if host in ("localhost", "testserver"):
                    resolved_ip_str = "127.0.0.1"

        self.resolved_ip = resolved_ip_str

        # 1. Check explicit pattern matching on hostname (wildcard or exact match)
        for pattern in DEFAULT_ALLOWED_PATTERNS + self.custom_allowlist:
            if pattern.startswith("*.") and host.endswith(pattern[1:]):
                return True
            if host == pattern:
                return True

        # 2. Check IP address authorization if resolved
        if self.resolved_ip:
            try:
                ip_obj = ipaddress.ip_address(self.resolved_ip)
                if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local:
                    return True
            except ValueError:
                pass

        raise PermissionDeniedError(
            f"Target host '{host}' ({self.resolved_ip or 'unresolved'}) is not in authorized private/localhost scope. "
            "To test external domains, an administrator must explicitly register them in the Target Allowlist."
        )

    def _safe_request(
        self,
        url: str,
        method: str = "GET",
        headers: Dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> Tuple[int, Dict[str, str], str]:
        """Perform non-destructive HTTP request with timeout and size cap."""
        req_headers = {
            "User-Agent": "ASOC-Defensive-Scanner/1.0 (Defensive-Audit-Agent)",
            "Accept": "*/*",
        }
        if headers:
            req_headers.update(headers)

        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = resp.status
                resp_headers = {k.lower(): v for k, v in resp.getheaders()}
                # Cap body read to 256KB to avoid memory bloat
                body = resp.read(256 * 1024).decode("utf-8", errors="replace")
                return status, resp_headers, body
        except urllib.error.HTTPError as e:
            resp_headers = {k.lower(): v for k, v in e.headers.items()}
            body = e.read(64 * 1024).decode("utf-8", errors="replace")
            return e.code, resp_headers, body
        except Exception as exc:
            return 0, {}, str(exc)

    def _check_service_exposure(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Safe non-destructive TCP port connectivity check.
        Probes standard lab ports with a tight 0.4s socket timeout.
        """
        exposed: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        target_ip = self.resolved_ip or (
            "127.0.0.1" if self.target_host in ("localhost", "testserver") else self.target_host
        )

        ports_to_probe = [21, 22, 25, 53, 80, 443, 8080, 8443]
        if self.target_port not in ports_to_probe and 1 <= self.target_port <= 65535:
            ports_to_probe.append(self.target_port)
        ports_to_probe.sort()

        for port in ports_to_probe:
            service_name = PORT_SERVICE_MAP.get(port, f"TCP-{port}")
            is_open = False
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.4)
                    res = s.connect_ex((target_ip, port))
                    if res == 0:
                        is_open = True
            except Exception:
                is_open = False

            if is_open:
                exposed.append({
                    "port": port,
                    "service": service_name,
                    "state": "open",
                })
                if port == 21:
                    findings.append({
                        "title": "Cleartext File Transfer Protocol (FTP) Service Exposed",
                        "category": "Service Exposure",
                        "severity": RiskLevel.MEDIUM,
                        "confidence": 1.0,
                        "status": "CONFIRMED",
                        "endpoint": f":{port}",
                        "http_method": "TCP",
                        "evidence": f"Port {port} (FTP) is open and responding to TCP connections on {target_ip}.",
                        "description": "FTP transmits credentials and payload data in unencrypted plaintext across the network.",
                        "remediation": "Disable legacy FTP and migrate to SFTP (SSH File Transfer Protocol) or FTPS with enforced TLS.",
                        "cwe_id": "CWE-319",
                        "owasp_category": "A02:2021-Cryptographic Failures",
                        "mitre_technique_id": "T1040",
                        "risk_score": 50.0,
                    })
                elif port in (22, 25):
                    findings.append({
                        "title": f"Network Infrastructure Service Exposed ({service_name} Port {port})",
                        "category": "Service Exposure",
                        "severity": RiskLevel.LOW,
                        "confidence": 1.0,
                        "status": "CONFIRMED",
                        "endpoint": f":{port}",
                        "http_method": "TCP",
                        "evidence": f"Port {port} ({service_name}) is accepting TCP connections on {target_ip}.",
                        "description": f"Service {service_name} is active on port {port}. Administrative services should be isolated behind a management VLAN or VPN.",
                        "remediation": f"Ensure firewall rules restrict port {port} to authorized administrative management subnets.",
                        "cwe_id": "CWE-1008",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "mitre_technique_id": "T1021",
                        "risk_score": 20.0,
                    })

        self.exposed_services = exposed
        return exposed, findings

    def _check_benign_reflection(self, base_url: str) -> List[Dict[str, Any]]:
        """Safe benign query parameter reflection check (no malicious XSS payloads)."""
        findings = []
        probe_token = f"asoc_probe_{uuid.uuid4().hex[:8]}"
        probe_url = f"{base_url}/?asoc_probe={probe_token}"
        code, headers, body = self._safe_request(probe_url, method="GET")

        content_type = headers.get("content-type", "").lower()
        if probe_token in body and ("text/html" in content_type or "application/xhtml" in content_type):
            findings.append({
                "title": "Unsanitized Query Parameter Reflection Detected",
                "category": "Input Validation",
                "severity": RiskLevel.MEDIUM,
                "confidence": 0.85,
                "status": "LIKELY",
                "endpoint": "/?asoc_probe=...",
                "http_method": "GET",
                "parameter": "asoc_probe",
                "evidence": f"Benign probe token '{probe_token}' was reflected raw into HTML response body.",
                "description": "The application reflects URL query parameter values directly into response markup without contextual output encoding.",
                "remediation": "Apply context-aware output encoding (HTML entity encoding, attribute escaping) before reflecting user input.",
                "cwe_id": "CWE-79",
                "owasp_category": "A03:2021-Injection",
                "mitre_technique_id": "T1189",
                "risk_score": 55.0,
            })
        return findings

    def run_all_checks(self, profile: str = "standard") -> List[Dict[str, Any]]:
        """Run safe defensive audit checks based on selected scan profile."""
        self.validate_target_authorization()
        findings: List[Dict[str, Any]] = []

        # 1. Controlled Port / Service Exposure Check
        _, exposure_findings = self._check_service_exposure()
        findings.extend(exposure_findings)

        base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        status_code, headers, body = self._safe_request(base_url, method="GET")

        if status_code == 0:
            findings.append({
                "title": "Target Service Unreachable",
                "category": "TLS/Transport",
                "severity": RiskLevel.LOW,
                "confidence": 0.9,
                "status": "POTENTIAL",
                "endpoint": "/",
                "http_method": "GET",
                "evidence": f"Connection failed to {base_url}: {body}",
                "description": "Unable to establish HTTP/HTTPS connection to the target application.",
                "remediation": "Verify the target application server is running and accessible on the specified port.",
                "cwe_id": "CWE-400",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "mitre_technique_id": None,
                "risk_score": 10.0,
            })
            return findings

        # 2. HTTP/HTTPS & Transport Checks
        findings.extend(self._check_tls_and_transport(base_url, status_code, headers))

        # 3. Security Headers Checks
        findings.extend(self._check_security_headers(headers, base_url))

        # 4. Cookie Security Checks
        findings.extend(self._check_cookie_security(headers, base_url))

        # 5. CORS Checks
        findings.extend(self._check_cors_configuration(base_url))

        # 6. Information Disclosure Checks
        findings.extend(self._check_information_disclosure(headers, body, base_url))

        # 7. Safe Benign Reflection Probe
        findings.extend(self._check_benign_reflection(base_url))

        if profile in ("standard", "deep"):
            # 8. Safe Directory / File Exposure Checks
            findings.extend(self._check_file_and_directory_exposure(base_url))

        if profile == "deep":
            # 9. Safe Non-Destructive Input Validation Indicators
            findings.extend(self._check_input_validation_indicators(base_url))

        return findings

    def _check_tls_and_transport(self, base_url: str, status_code: int, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        findings = []
        if self.parsed_url.scheme == "http":
            findings.append({
                "title": "Insecure HTTP Protocol In Use",
                "category": "TLS/Transport",
                "severity": RiskLevel.MEDIUM,
                "confidence": 1.0,
                "status": "CONFIRMED",
                "endpoint": "/",
                "http_method": "GET",
                "evidence": f"Service accessible over unencrypted HTTP: {base_url}",
                "description": "Traffic transmitted over plain HTTP is vulnerable to eavesdropping and man-in-the-middle tampering.",
                "remediation": "Enable TLS encryption, obtain a valid certificate, and redirect all HTTP requests to HTTPS.",
                "cwe_id": "CWE-319",
                "owasp_category": "A02:2021-Cryptographic Failures",
                "mitre_technique_id": "T1040",
                "risk_score": 45.0,
            })
        return findings

    def _check_security_headers(self, headers: Dict[str, str], base_url: str) -> List[Dict[str, Any]]:
        findings = []

        # Content-Security-Policy (CSP)
        if "content-security-policy" not in headers:
            findings.append({
                "title": "Missing Content-Security-Policy (CSP) Header",
                "category": "Security Headers",
                "severity": RiskLevel.MEDIUM,
                "confidence": 1.0,
                "status": "CONFIRMED",
                "endpoint": "/",
                "http_method": "GET",
                "evidence": "Response headers omitted 'Content-Security-Policy'.",
                "description": "Content-Security-Policy restricts resource loading origins, mitigating Cross-Site Scripting (XSS) and data injection.",
                "remediation": "Define and deploy a restrictive Content-Security-Policy (e.g., default-src 'self').",
                "cwe_id": "CWE-693",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "mitre_technique_id": "T1189",
                "risk_score": 40.0,
            })

        # Strict-Transport-Security (HSTS)
        if self.parsed_url.scheme == "https" and "strict-transport-security" not in headers:
            findings.append({
                "title": "Missing HTTP Strict-Transport-Security (HSTS)",
                "category": "Security Headers",
                "severity": RiskLevel.LOW,
                "confidence": 1.0,
                "status": "CONFIRMED",
                "endpoint": "/",
                "http_method": "GET",
                "evidence": "HTTPS response omitted 'Strict-Transport-Security' header.",
                "description": "HSTS instructs browsers to only interact with the domain over HTTPS, preventing SSL-stripping attacks.",
                "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to HTTPS responses.",
                "cwe_id": "CWE-523",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "mitre_technique_id": None,
                "risk_score": 25.0,
            })

        # X-Content-Type-Options
        if headers.get("x-content-type-options", "").lower() != "nosniff":
            findings.append({
                "title": "Missing X-Content-Type-Options: nosniff",
                "category": "Security Headers",
                "severity": RiskLevel.LOW,
                "confidence": 1.0,
                "status": "CONFIRMED",
                "endpoint": "/",
                "http_method": "GET",
                "evidence": f"X-Content-Type-Options is {headers.get('x-content-type-options', 'missing')}.",
                "description": "Prevents the browser from MIME-sniffing a response away from the declared content-type.",
                "remediation": "Configure 'X-Content-Type-Options: nosniff' across all server responses.",
                "cwe_id": "CWE-16",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "mitre_technique_id": None,
                "risk_score": 20.0,
            })

        # X-Frame-Options
        xfo = headers.get("x-frame-options", "").upper()
        if xfo not in ("DENY", "SAMEORIGIN"):
            findings.append({
                "title": "Missing or Inadequate X-Frame-Options Protection",
                "category": "Security Headers",
                "severity": RiskLevel.LOW,
                "confidence": 1.0,
                "status": "CONFIRMED",
                "endpoint": "/",
                "http_method": "GET",
                "evidence": f"X-Frame-Options is '{headers.get('x-frame-options', 'not set')}'.",
                "description": "X-Frame-Options prevents the website from being framed, defending against clickjacking attacks.",
                "remediation": "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'.",
                "cwe_id": "CWE-1021",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "mitre_technique_id": None,
                "risk_score": 25.0,
            })

        return findings

    def _check_cookie_security(self, headers: Dict[str, str], base_url: str) -> List[Dict[str, Any]]:
        findings = []
        cookie_headers = [v for k, v in headers.items() if k == "set-cookie"]
        for cookie_str in cookie_headers:
            cookie_parts = [p.strip().lower() for p in cookie_str.split(";")]
            cookie_name = cookie_parts[0].split("=")[0] if cookie_parts else "cookie"

            # Check HttpOnly
            if "httponly" not in cookie_parts:
                findings.append({
                    "title": f"Cookie '{cookie_name}' Missing HttpOnly Flag",
                    "category": "Cookie Security",
                    "severity": RiskLevel.MEDIUM,
                    "confidence": 1.0,
                    "status": "CONFIRMED",
                    "endpoint": "/",
                    "http_method": "GET",
                    "evidence": f"Cookie '{cookie_name}' Set-Cookie attributes omit HttpOnly flag.",
                    "description": "HttpOnly prevents client-side scripts from reading cookies, defending against token theft via XSS.",
                    "remediation": "Add the 'HttpOnly' directive to session and sensitive authentication cookies.",
                    "cwe_id": "CWE-1004",
                    "owasp_category": "A07:2021-Identification and Authentication Failures",
                    "mitre_technique_id": "T1539",
                    "risk_score": 50.0,
                })

            # Check Secure flag
            if self.parsed_url.scheme == "https" and "secure" not in cookie_parts:
                findings.append({
                    "title": f"Cookie '{cookie_name}' Missing Secure Flag",
                    "category": "Cookie Security",
                    "severity": RiskLevel.MEDIUM,
                    "confidence": 1.0,
                    "status": "CONFIRMED",
                    "endpoint": "/",
                    "http_method": "GET",
                    "evidence": f"Cookie '{cookie_name}' Set-Cookie attributes omit Secure flag on HTTPS connection.",
                    "description": "Secure flag ensures cookies are only transmitted encrypted over TLS, preventing eavesdropping.",
                    "remediation": "Configure the 'Secure' attribute on all cookies issued over HTTPS.",
                    "cwe_id": "CWE-614",
                    "owasp_category": "A02:2021-Cryptographic Failures",
                    "mitre_technique_id": "T1539",
                    "risk_score": 45.0,
                })

            # Check SameSite
            has_samesite = any(p.startswith("samesite") for p in cookie_parts)
            if not has_samesite:
                findings.append({
                    "title": f"Cookie '{cookie_name}' Missing SameSite Attribute",
                    "category": "Cookie Security",
                    "severity": RiskLevel.LOW,
                    "confidence": 1.0,
                    "status": "CONFIRMED",
                    "endpoint": "/",
                    "http_method": "GET",
                    "evidence": f"Cookie '{cookie_name}' Set-Cookie attributes omit SameSite attribute.",
                    "description": "SameSite controls whether cookies are sent on cross-site requests, mitigating Cross-Site Request Forgery (CSRF).",
                    "remediation": "Set 'SameSite=Lax' or 'SameSite=Strict' on all state-tracking cookies.",
                    "cwe_id": "CWE-1275",
                    "owasp_category": "A01:2021-Broken Access Control",
                    "mitre_technique_id": None,
                    "risk_score": 30.0,
                })

        return findings

    def _check_cors_configuration(self, base_url: str) -> List[Dict[str, Any]]:
        findings = []
        test_origin = "https://hostile-threat-origin.test"
        _, cors_headers, _ = self._safe_request(
            base_url,
            method="OPTIONS",
            headers={"Origin": test_origin, "Access-Control-Request-Method": "POST"},
        )

        acao = cors_headers.get("access-control-allow-origin", "").strip()
        acac = cors_headers.get("access-control-allow-credentials", "").strip().lower()

        if acao == "*":
            findings.append({
                "title": "Overly Permissive CORS Policy (Wildcard Origin)",
                "category": "CORS",
                "severity": RiskLevel.LOW if acac != "true" else RiskLevel.HIGH,
                "confidence": 1.0,
                "status": "CONFIRMED",
                "endpoint": "/",
                "http_method": "OPTIONS",
                "evidence": f"Access-Control-Allow-Origin: * (Allow-Credentials: {acac or 'false'})",
                "description": "The endpoint allows any external website to read responses via cross-origin requests.",
                "remediation": "Restrict Access-Control-Allow-Origin to authorized corporate domains.",
                "cwe_id": "CWE-346",
                "owasp_category": "A01:2021-Broken Access Control",
                "mitre_technique_id": None,
                "risk_score": 75.0 if acac == "true" else 30.0,
            })
        elif acao.lower() == test_origin.lower():
            findings.append({
                "title": "Unsafe CORS Origin Reflection Detected",
                "category": "CORS",
                "severity": RiskLevel.HIGH if acac == "true" else RiskLevel.MEDIUM,
                "confidence": 1.0,
                "status": "CONFIRMED",
                "endpoint": "/",
                "http_method": "OPTIONS",
                "evidence": f"Reflected arbitrary Origin header '{test_origin}' in Access-Control-Allow-Origin.",
                "description": "The server dynamically reflects untrusted incoming Origin headers, allowing hostile sites to read authenticated responses.",
                "remediation": "Validate incoming Origin against a strict whitelist before echoing Access-Control-Allow-Origin.",
                "cwe_id": "CWE-346",
                "owasp_category": "A01:2021-Broken Access Control",
                "mitre_technique_id": "T1190",
                "risk_score": 80.0 if acac == "true" else 55.0,
            })

        return findings

    def _check_information_disclosure(self, headers: Dict[str, str], body: str, base_url: str) -> List[Dict[str, Any]]:
        findings = []

        # Server banner
        server = headers.get("server", "").strip()
        if server and any(c.isdigit() for c in server):
            findings.append({
                "title": "Server Banner Information Disclosure",
                "category": "Information Disclosure",
                "severity": RiskLevel.LOW,
                "confidence": 1.0,
                "status": "CONFIRMED",
                "endpoint": "/",
                "http_method": "GET",
                "evidence": f"Server header leaked version information: '{server}'.",
                "description": "Exposing detailed server software versions helps adversaries identify known CVEs.",
                "remediation": "Disable or sanitize the 'Server' header in reverse proxy / web server configuration.",
                "cwe_id": "CWE-200",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "mitre_technique_id": "T1592",
                "risk_score": 20.0,
            })

        # X-Powered-By
        powered = headers.get("x-powered-by", "").strip()
        if powered:
            findings.append({
                "title": "X-Powered-By Framework Disclosure",
                "category": "Information Disclosure",
                "severity": RiskLevel.LOW,
                "confidence": 1.0,
                "status": "CONFIRMED",
                "endpoint": "/",
                "http_method": "GET",
                "evidence": f"X-Powered-By header: '{powered}'.",
                "description": "Reveals underlying application technology and framework.",
                "remediation": "Remove the X-Powered-By response header.",
                "cwe_id": "CWE-200",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "mitre_technique_id": None,
                "risk_score": 15.0,
            })

        # Safe 404 error page check for debug stack traces
        err_url = f"{base_url}/asoc_test_probe_404_nonexistent_{int(time.time())}"
        err_code, _, err_body = self._safe_request(err_url, method="GET")
        if err_code in (404, 500):
            if any(term in err_body.lower() for term in ("traceback (most recent call last)", "syntaxerror:", "stack trace:", "at line ")):
                findings.append({
                    "title": "Verbose Error Page / Stack Trace Disclosure",
                    "category": "Information Disclosure",
                    "severity": RiskLevel.HIGH,
                    "confidence": 0.95,
                    "status": "CONFIRMED",
                    "endpoint": "/asoc_test_probe_404",
                    "http_method": "GET",
                    "evidence": "Error page contains framework call stack traces or unhandled exception details.",
                    "description": "Verbose error responses leak source code file paths, database structure, and internal logic to adversaries.",
                    "remediation": "Configure custom generic error handlers and disable debug modes in production.",
                    "cwe_id": "CWE-209",
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "mitre_technique_id": "T1592",
                    "risk_score": 70.0,
                })

        return findings

    def _check_file_and_directory_exposure(self, base_url: str) -> List[Dict[str, Any]]:
        findings = []
        safe_probes = [
            ("/.env", "Environment Configuration File", RiskLevel.CRITICAL, "CWE-552", 90.0),
            ("/.git/HEAD", "Git Repository Metadata", RiskLevel.HIGH, "CWE-527", 80.0),
            ("/robots.txt", "Robots Crawler Policy", RiskLevel.LOW, "CWE-200", 10.0),
            ("/swagger.json", "OpenAPI Documentation Schema", RiskLevel.LOW, "CWE-200", 20.0),
        ]

        for path, label, sev, cwe, score in safe_probes:
            probe_url = f"{base_url}{path}"
            code, h, b = self._safe_request(probe_url, method="HEAD")
            if code == 200:
                findings.append({
                    "title": f"Exposed Sensitive Resource: {label}",
                    "category": "Directory / File Exposure",
                    "severity": sev,
                    "confidence": 0.9,
                    "status": "CONFIRMED",
                    "endpoint": path,
                    "http_method": "HEAD",
                    "evidence": f"HTTP 200 OK returned when requesting {path}. Content-Type: {h.get('content-type', 'unknown')}.",
                    "description": f"The resource at '{path}' is publicly accessible without authentication.",
                    "remediation": f"Block public access to '{path}' in reverse proxy rules.",
                    "cwe_id": cwe,
                    "owasp_category": "A01:2021-Broken Access Control",
                    "mitre_technique_id": "T1190" if sev in (RiskLevel.HIGH, RiskLevel.CRITICAL) else None,
                    "risk_score": score,
                })

        return findings

    def _check_input_validation_indicators(self, base_url: str) -> List[Dict[str, Any]]:
        """Safe non-destructive syntax reflection checks."""
        findings = []
        # Safe syntax quote probe
        probe_url = f"{base_url}/?id=1%27&q=%27"
        code, _, body = self._safe_request(probe_url, method="GET")

        # Check for unhandled database error signatures
        db_signatures = [
            "you have an error in your sql syntax",
            "unclosed quotation mark after the character string",
            "sqlite3.operationalerror",
            "pg_query(): query failed",
            "ora-00933: sql command not properly ended",
        ]
        body_lower = body.lower()
        matched_sig = next((sig for sig in db_signatures if sig in body_lower), None)
        if matched_sig:
            findings.append({
                "title": "Potential SQL Injection Indicator (Database Error Reflection)",
                "category": "Input Validation",
                "severity": RiskLevel.HIGH,
                "confidence": 0.85,
                "status": "LIKELY",
                "endpoint": "/?id=1'",
                "http_method": "GET",
                "parameter": "id",
                "evidence": f"Response contains unhandled database exception signature: '{matched_sig}'.",
                "description": "The application returned raw database error messages when supplied with single-quote syntax characters.",
                "remediation": "Use parameterized queries / prepared statements and sanitize all user input.",
                "cwe_id": "CWE-89",
                "owasp_category": "A03:2021-Injection",
                "mitre_technique_id": "T1190",
                "risk_score": 85.0,
            })

        return findings
