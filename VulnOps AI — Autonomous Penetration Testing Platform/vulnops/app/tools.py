"""
VulnOps AI — Reconnaissance Tools

Every tool:
  • Is a plain synchronous Python function (AG2 compatible).
  • Performs ONLY safe, read-only checks (no destructive payloads).
  • Returns a structured dict with MITRE ATT&CK tactic / technique.
  • Publishes its finding to Kafka topic 'vulnops.findings' (fire-and-forget).
  • Emits a Jaeger span for tracing.
"""
import uuid
import datetime
from typing import Annotated, Dict, List

import requests
import urllib3

from tracer import get_tracer
import kafka_pub

# Suppress SSL warnings for targets with self-signed certs (demo environment)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

tracer = get_tracer("vulnops.tools")

# ─── Severity colour emoji ────────────────────────────────────────────────────
SEVERITY_ICON = {
    "critical":      "🔴",
    "high":          "🟠",
    "medium":        "🟡",
    "low":           "🟢",
    "informational": "⚪",
}


def _publish(campaign_id: str, findings: List[dict]) -> None:
    """Push each finding to Kafka for real-time visibility in Redpanda Console."""
    for f in findings:
        kafka_pub.publish(
            "vulnops.findings",
            {
                "campaign_id": campaign_id,
                "event_id":    str(uuid.uuid4()),
                "timestamp":   datetime.datetime.utcnow().isoformat(),
                **f,
            },
        )


# ─────────────────────────────────────────────────────────────────────────────
# Tool 1: scan_target_info
# ─────────────────────────────────────────────────────────────────────────────
def scan_target_info(
    target_url: Annotated[str, "Full URL of the target, e.g. http://example.com"],
    campaign_id: Annotated[str, "The current campaign UUID for tracing purposes"] = "none",
) -> Dict:
    """
    Perform initial reconnaissance: check if the target is live, measure
    response time, collect redirect chain, and identify content type.
    Maps to MITRE ATT&CK TA0043 / T1595 (Active Scanning).
    """
    with tracer.start_as_current_span("scan_target_info") as span:
        span.set_attribute("target.url", target_url)
        span.set_attribute("campaign.id", campaign_id)
        try:
            resp = requests.get(
                target_url, timeout=10, verify=False, allow_redirects=True
            )
            finding = {
                "id":                  "RI-001",
                "tool":                "scan_target_info",
                "title":               "Target Confirmed Live",
                "severity":            "informational",
                "detail":              (
                    f"Target responded HTTP {resp.status_code} in "
                    f"{round(resp.elapsed.total_seconds() * 1000)} ms. "
                    f"Final URL: {resp.url}. "
                    f"Redirects followed: {len(resp.history)}."
                ),
                "mitre_tactic":        "TA0043",
                "mitre_tactic_name":   "Reconnaissance",
                "mitre_technique":     "T1595",
                "mitre_technique_name":"Active Scanning",
                "remediation":         "N/A — informational.",
            }
            span.set_attribute("http.status_code", resp.status_code)
            _publish(campaign_id, [finding])
            return {
                "ok":           True,
                "target":       target_url,
                "status_code":  resp.status_code,
                "response_ms":  round(resp.elapsed.total_seconds() * 1000, 1),
                "final_url":    str(resp.url),
                "redirects":    len(resp.history),
                "content_type": resp.headers.get("content-type", "unknown"),
                "findings":     [finding],
            }
        except Exception as exc:
            span.set_attribute("error", True)
            return {"ok": False, "target": target_url, "error": str(exc), "findings": []}


# ─────────────────────────────────────────────────────────────────────────────
# Tool 2: check_http_headers
# ─────────────────────────────────────────────────────────────────────────────
def check_http_headers(
    target_url: Annotated[str, "Full URL to analyse HTTP response headers"],
    campaign_id: Annotated[str, "The current campaign UUID"] = "none",
) -> Dict:
    """
    Analyse HTTP response headers for technology disclosure vulnerabilities.
    Checks: Server, X-Powered-By, Via, X-AspNet-Version.
    Maps to MITRE ATT&CK TA0043 / T1592 (Gather Victim Host Information).
    """
    with tracer.start_as_current_span("check_http_headers") as span:
        span.set_attribute("target.url", target_url)
        try:
            resp = requests.get(
                target_url, timeout=10, verify=False, allow_redirects=True
            )
            h = {k.lower(): v for k, v in resp.headers.items()}
            findings = []

            checks = [
                ("server",            "HD-001", "Server Version Disclosure",
                 "Server header reveals the web server software and version."),
                ("x-powered-by",      "HD-002", "Technology Stack Disclosure",
                 "X-Powered-By header reveals backend language/framework."),
                ("via",               "HD-003", "Proxy / Load Balancer Disclosure",
                 "Via header reveals internal proxy infrastructure."),
                ("x-aspnet-version",  "HD-004", "ASP.NET Version Disclosure",
                 "X-AspNet-Version header reveals .NET framework version."),
            ]

            for header_key, fid, title, detail_prefix in checks:
                val = h.get(header_key, "")
                if val:
                    findings.append({
                        "id":    fid,
                        "tool":  "check_http_headers",
                        "title": title,
                        "severity": "low",
                        "detail": f"{detail_prefix} Value: '{val}'",
                        "mitre_tactic":         "TA0043",
                        "mitre_tactic_name":    "Reconnaissance",
                        "mitre_technique":      "T1592",
                        "mitre_technique_name": "Gather Victim Host Information",
                        "remediation": (
                            f"Remove or obscure the '{header_key}' response header "
                            f"in your web server / reverse proxy configuration."
                        ),
                    })

            span.set_attribute("findings.count", len(findings))
            _publish(campaign_id, findings)
            return {
                "ok":      True,
                "target":  target_url,
                "findings_count": len(findings),
                "findings": findings,
                "headers_observed": dict(list(h.items())[:15]),
            }
        except Exception as exc:
            span.set_attribute("error", True)
            return {"ok": False, "target": target_url, "error": str(exc), "findings": []}


# ─────────────────────────────────────────────────────────────────────────────
# Tool 3: check_security_headers
# ─────────────────────────────────────────────────────────────────────────────
def check_security_headers(
    target_url: Annotated[str, "Full URL to audit for missing security headers"],
    campaign_id: Annotated[str, "The current campaign UUID"] = "none",
) -> Dict:
    """
    Audit for missing HTTP security headers.
    Missing headers enable XSS, Clickjacking, MIME sniffing, and data leakage.
    Maps to MITRE ATT&CK TA0001 / T1190 (Exploit Public-Facing Application).
    """
    with tracer.start_as_current_span("check_security_headers") as span:
        span.set_attribute("target.url", target_url)
        try:
            resp = requests.get(
                target_url, timeout=10, verify=False, allow_redirects=True
            )
            h = {k.lower(): v for k, v in resp.headers.items()}
            findings = []

            required_headers = [
                {
                    "header": "x-frame-options",
                    "id": "SH-001",
                    "title": "Missing X-Frame-Options — Clickjacking Risk",
                    "severity": "medium",
                    "detail": (
                        "Without X-Frame-Options, attackers can embed this page "
                        "in an iframe to trick users into unintended clicks (Clickjacking)."
                    ),
                    "remediation": "Add: X-Frame-Options: DENY (or SAMEORIGIN) to all responses.",
                },
                {
                    "header": "content-security-policy",
                    "id": "SH-002",
                    "title": "Missing Content-Security-Policy — XSS Risk",
                    "severity": "high",
                    "detail": (
                        "No CSP header detected. Without CSP, Cross-Site Scripting (XSS) "
                        "attacks can execute arbitrary JavaScript in victim browsers."
                    ),
                    "remediation": (
                        "Implement a strict CSP. Start with: "
                        "Content-Security-Policy: default-src 'self'"
                    ),
                },
                {
                    "header": "x-content-type-options",
                    "id": "SH-003",
                    "title": "Missing X-Content-Type-Options — MIME Sniffing Risk",
                    "severity": "low",
                    "detail": (
                        "Without this header browsers may MIME-sniff responses, "
                        "potentially executing scripts disguised as other content types."
                    ),
                    "remediation": "Add: X-Content-Type-Options: nosniff",
                },
                {
                    "header": "strict-transport-security",
                    "id": "SH-004",
                    "title": "Missing Strict-Transport-Security (HSTS)",
                    "severity": "medium",
                    "detail": (
                        "Without HSTS, browsers may connect over HTTP, enabling "
                        "Man-in-the-Middle attacks and protocol downgrade."
                    ),
                    "remediation": (
                        "Add: Strict-Transport-Security: max-age=31536000; "
                        "includeSubDomains; preload"
                    ),
                },
                {
                    "header": "referrer-policy",
                    "id": "SH-005",
                    "title": "Missing Referrer-Policy — Data Leakage Risk",
                    "severity": "low",
                    "detail": (
                        "Without Referrer-Policy, full URLs (including sensitive query "
                        "parameters) may be leaked to third-party sites."
                    ),
                    "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
                },
                {
                    "header": "permissions-policy",
                    "id": "SH-006",
                    "title": "Missing Permissions-Policy",
                    "severity": "low",
                    "detail": (
                        "Without Permissions-Policy, embedded scripts can access "
                        "camera, microphone, geolocation without restriction."
                    ),
                    "remediation": (
                        "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()"
                    ),
                },
            ]

            for req in required_headers:
                if req["header"] not in h:
                    findings.append({
                        "id":    req["id"],
                        "tool":  "check_security_headers",
                        "title": req["title"],
                        "severity": req["severity"],
                        "detail":   req["detail"],
                        "mitre_tactic":         "TA0001",
                        "mitre_tactic_name":    "Initial Access",
                        "mitre_technique":      "T1190",
                        "mitre_technique_name": "Exploit Public-Facing Application",
                        "remediation":          req["remediation"],
                    })

            span.set_attribute("findings.count", len(findings))
            _publish(campaign_id, findings)
            return {
                "ok":         True,
                "target":     target_url,
                "checked":    len(required_headers),
                "missing":    len(findings),
                "findings_count": len(findings),
                "findings":   findings,
            }
        except Exception as exc:
            span.set_attribute("error", True)
            return {"ok": False, "target": target_url, "error": str(exc), "findings": []}


# ─────────────────────────────────────────────────────────────────────────────
# Tool 4: check_cors
# ─────────────────────────────────────────────────────────────────────────────
def check_cors(
    target_url: Annotated[str, "Full URL to test for CORS misconfiguration"],
    campaign_id: Annotated[str, "The current campaign UUID"] = "none",
) -> Dict:
    """
    Test for CORS misconfiguration by sending a cross-origin request.
    An open CORS policy allows any website to make authenticated requests
    to this server on behalf of a victim user.
    Maps to MITRE ATT&CK TA0009 / T1185 (Browser Session Hijacking).
    """
    with tracer.start_as_current_span("check_cors") as span:
        span.set_attribute("target.url", target_url)
        try:
            headers = {"Origin": "https://evil-attacker.com"}
            resp = requests.get(
                target_url, headers=headers, timeout=10, verify=False,
                allow_redirects=True
            )
            h = {k.lower(): v for k, v in resp.headers.items()}

            acao = h.get("access-control-allow-origin", "")
            acac = h.get("access-control-allow-credentials", "")

            findings = []

            if acao == "*":
                findings.append({
                    "id": "CORS-001",
                    "tool": "check_cors",
                    "title": "Open CORS — Wildcard Origin Allowed",
                    "severity": "medium",
                    "detail": (
                        "Access-Control-Allow-Origin: * permits any website to "
                        "read responses from this server via JavaScript."
                    ),
                    "mitre_tactic":         "TA0009",
                    "mitre_tactic_name":    "Collection",
                    "mitre_technique":      "T1185",
                    "mitre_technique_name": "Browser Session Hijacking",
                    "remediation": (
                        "Restrict CORS to trusted origins only. Replace * with your "
                        "specific allowed domain(s)."
                    ),
                })
            elif acao == "https://evil-attacker.com":
                findings.append({
                    "id": "CORS-002",
                    "tool": "check_cors",
                    "title": "CORS Reflects Attacker Origin",
                    "severity": "high",
                    "detail": (
                        "The server reflects the attacker-controlled Origin header "
                        "back in Access-Control-Allow-Origin. This is a critical "
                        "CORS misconfiguration allowing cross-site request forgery."
                    ),
                    "mitre_tactic":         "TA0009",
                    "mitre_tactic_name":    "Collection",
                    "mitre_technique":      "T1185",
                    "mitre_technique_name": "Browser Session Hijacking",
                    "remediation": (
                        "Implement an allowlist of trusted origins. "
                        "Never reflect the incoming Origin header without validation."
                    ),
                })

            if acac.lower() == "true" and findings:
                findings[0]["severity"] = "high"
                findings[0]["detail"] += (
                    " Additionally, Access-Control-Allow-Credentials: true is set, "
                    "enabling cross-origin authenticated requests — escalating this "
                    "to a High severity finding."
                )

            if not findings:
                findings.append({
                    "id": "CORS-OK",
                    "tool": "check_cors",
                    "title": "CORS Configuration Appears Restrictive",
                    "severity": "informational",
                    "detail": (
                        f"Access-Control-Allow-Origin value: '{acao or '(not set)'}'. "
                        f"No wildcard or reflected origin detected."
                    ),
                    "mitre_tactic": "N/A",
                    "mitre_tactic_name": "N/A",
                    "mitre_technique": "N/A",
                    "mitre_technique_name": "N/A",
                    "remediation": "N/A — no issue detected.",
                })

            span.set_attribute("cors.allow_origin", acao)
            span.set_attribute("findings.count", len(findings))
            _publish(campaign_id, findings)
            return {
                "ok": True,
                "target": target_url,
                "cors_allow_origin": acao or "(not set)",
                "cors_allow_credentials": acac or "(not set)",
                "findings_count": len(findings),
                "findings": findings,
            }
        except Exception as exc:
            span.set_attribute("error", True)
            return {"ok": False, "target": target_url, "error": str(exc), "findings": []}


# ─────────────────────────────────────────────────────────────────────────────
# Tool 5: check_sensitive_paths
# ─────────────────────────────────────────────────────────────────────────────
def check_sensitive_paths(
    target_url: Annotated[str, "Full base URL of the target (e.g. http://example.com)"],
    campaign_id: Annotated[str, "The current campaign UUID"] = "none",
) -> Dict:
    """
    Discover publicly accessible sensitive paths: admin panels, configuration
    files, backup files, and unauthenticated API endpoints.
    Maps to MITRE ATT&CK TA0043 / T1595 (Active Scanning — Vulnerability Scanning).
    """
    with tracer.start_as_current_span("check_sensitive_paths") as span:
        span.set_attribute("target.url", target_url)
        base = target_url.rstrip("/")

        paths_to_check = [
            ("/admin",           "Admin Panel Exposed",          "high",     "Admin panels must require authentication and not be publicly accessible."),
            ("/.env",            ".env File Exposed",            "critical", "Environment files may contain DB passwords, API keys, and secrets. Remove immediately."),
            ("/backup.zip",      "Backup Archive Exposed",       "high",     "Backup files expose source code and configuration. Remove from web root."),
            ("/.git/config",     "Git Repository Exposed",       "critical", "Exposed .git directory reveals source code history. Add .git to .htaccess deny rules."),
            ("/api/users",       "Unauthenticated User API",     "high",     "User listing endpoints must require authentication and authorisation."),
            ("/phpinfo.php",     "PHP Info Page Exposed",        "medium",   "phpinfo() reveals full server configuration. Remove or restrict to localhost."),
            ("/wp-admin",        "WordPress Admin Exposed",      "medium",   "Restrict /wp-admin to known IP ranges."),
            ("/server-status",   "Apache Server Status Exposed", "medium",   "Restrict /server-status to localhost."),
            ("/config.json",     "Config File Exposed",          "high",     "Configuration files must not be served from the web root."),
        ]

        findings = []
        results = []

        for path, title, severity, remediation in paths_to_check:
            url = base + path
            try:
                r = requests.get(url, timeout=6, verify=False, allow_redirects=False)
                is_exposed = r.status_code in (200, 301, 302, 403)
                results.append({
                    "path":        path,
                    "url":         url,
                    "status_code": r.status_code,
                    "exposed":     is_exposed,
                })
                if r.status_code == 200:
                    findings.append({
                        "id":    f"PATH-{len(findings)+1:03d}",
                        "tool":  "check_sensitive_paths",
                        "title": title,
                        "severity": severity,
                        "detail": (
                            f"Path '{path}' returned HTTP 200 OK — it is publicly accessible. "
                            f"Response size: {len(r.content)} bytes."
                        ),
                        "mitre_tactic":         "TA0043",
                        "mitre_tactic_name":    "Reconnaissance",
                        "mitre_technique":      "T1595",
                        "mitre_technique_name": "Active Scanning",
                        "remediation": remediation,
                    })
                elif r.status_code == 403:
                    findings.append({
                        "id":    f"PATH-{len(findings)+1:03d}",
                        "tool":  "check_sensitive_paths",
                        "title": f"{title} (Access Denied but Exists)",
                        "severity": "low",
                        "detail": (
                            f"Path '{path}' returned HTTP 403 — the resource exists "
                            f"but access is currently forbidden. This confirms the "
                            f"path is present and may be bypassable."
                        ),
                        "mitre_tactic":         "TA0043",
                        "mitre_tactic_name":    "Reconnaissance",
                        "mitre_technique":      "T1595",
                        "mitre_technique_name": "Active Scanning",
                        "remediation": f"{remediation} Additionally, verify the 403 cannot be bypassed.",
                    })
            except Exception:
                results.append({"path": path, "url": url, "status_code": -1, "exposed": False})

        span.set_attribute("paths.checked", len(paths_to_check))
        span.set_attribute("findings.count", len(findings))
        _publish(campaign_id, findings)

        return {
            "ok":             True,
            "target":         target_url,
            "paths_checked":  len(paths_to_check),
            "exposed_paths":  sum(1 for r in results if r["exposed"]),
            "findings_count": len(findings),
            "findings":       findings,
            "path_results":   results,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Tool 6: check_robots_txt
# ─────────────────────────────────────────────────────────────────────────────
def check_robots_txt(
    target_url: Annotated[str, "Full base URL of the target"],
    campaign_id: Annotated[str, "The current campaign UUID"] = "none",
) -> Dict:
    """
    Fetch and analyse robots.txt. Disallowed paths in robots.txt often reveal
    sensitive areas of the application that the operator tried to hide from
    search engines — which attackers can then target directly.
    Maps to MITRE ATT&CK TA0043 / T1596 (Search Open Technical Databases).
    """
    with tracer.start_as_current_span("check_robots_txt") as span:
        span.set_attribute("target.url", target_url)
        base = target_url.rstrip("/")
        robots_url = base + "/robots.txt"

        try:
            resp = requests.get(robots_url, timeout=8, verify=False)
            findings = []

            if resp.status_code == 200:
                content = resp.text
                disallowed = [
                    line.split(":", 1)[1].strip()
                    for line in content.splitlines()
                    if line.strip().lower().startswith("disallow:") and len(line.split(":", 1)) > 1
                ]
                disallowed = [p for p in disallowed if p and p != "/"]

                span.set_attribute("robots.disallowed_count", len(disallowed))

                if disallowed:
                    findings.append({
                        "id":    "ROB-001",
                        "tool":  "check_robots_txt",
                        "title": "robots.txt Reveals Sensitive Path Structure",
                        "severity": "low",
                        "detail": (
                            f"robots.txt lists {len(disallowed)} disallowed path(s): "
                            f"{', '.join(disallowed[:8])}. "
                            f"These are intended to be hidden but are publicly disclosed, "
                            f"giving attackers a roadmap to sensitive areas."
                        ),
                        "mitre_tactic":         "TA0043",
                        "mitre_tactic_name":    "Reconnaissance",
                        "mitre_technique":      "T1596",
                        "mitre_technique_name": "Search Open Technical Databases",
                        "remediation": (
                            "Do not use robots.txt as a security control. Protect "
                            "sensitive paths with proper authentication, not by listing "
                            "them in robots.txt."
                        ),
                    })
                else:
                    findings.append({
                        "id":    "ROB-OK",
                        "tool":  "check_robots_txt",
                        "title": "robots.txt Present — No Sensitive Paths Exposed",
                        "severity": "informational",
                        "detail": "robots.txt exists but does not list sensitive disallowed paths.",
                        "mitre_tactic": "N/A", "mitre_tactic_name": "N/A",
                        "mitre_technique": "N/A", "mitre_technique_name": "N/A",
                        "remediation": "N/A",
                    })
            else:
                findings.append({
                    "id":    "ROB-NF",
                    "tool":  "check_robots_txt",
                    "title": "robots.txt Not Found",
                    "severity": "informational",
                    "detail": f"robots.txt returned HTTP {resp.status_code}.",
                    "mitre_tactic": "N/A", "mitre_tactic_name": "N/A",
                    "mitre_technique": "N/A", "mitre_technique_name": "N/A",
                    "remediation": "N/A",
                })

            _publish(campaign_id, findings)
            return {
                "ok":             True,
                "target":         target_url,
                "robots_url":     robots_url,
                "status_code":    resp.status_code,
                "findings_count": len(findings),
                "findings":       findings,
            }
        except Exception as exc:
            span.set_attribute("error", True)
            return {"ok": False, "target": target_url, "error": str(exc), "findings": []}
