import json
import re

# -----------------------------
# Vulnerability name mapping
# -----------------------------
def map_vuln_type(alert_name: str) -> str:
    name = alert_name.lower()

    def contains(*keywords):
        return any(k in name for k in keywords)

    if contains("sql injection", "sqli", "mysql error", "sql syntax"):
        return "sqli"

    if contains("cross site scripting", "(possible) cross site scripting", "cross-site scripting", "xss", 
                "reflected xss", "stored xss", "dom xss",
                "cross frame scripting", "user controllable script source", 
                "user controllable tag parameter"):
        return "xss"

    if contains("xslt", "xslt injection", "xsl:"):
        return "xslt_injection"

    if contains("xxe", "xml external entity", "xml external"):
        return "xxe"

    if contains("command injection", "os command", "cmd injection", "system command"):
        return "cmd_injection"

    # Generic injection fallback
    if "alert:" in name and ("injection" in name or "inject" in name) or (contains("header injection", "http header injection", "parameter pollution", "http parameter pollution", "hpp")):
        return "injection_other"
    if contains("directory traversal", "path traversal"):
        return "dir_traversal"
        
    if contains("backup", "database backup", "dump file", ".bak", ".sql", 
                "[possible] backup", "possible database backup", "ws_ftp log", "[possible] ws_ftp log"):
        return "backup_file_exposed"
        
        
    if contains("sensitive file", ".git", ".hg", ".svn", "htaccess", 
                "web.config", "documentation files", "possible sensitive files",
                "jetbrains .idea", "sensitive data exposure", "directory listing", "index of /", "source code", "sourcecode", "internal path", "[possible] internal path", "path disclosure", "[possible] path disclosure"):
        return "sensitive_file_exposed"
        
    if contains("file inclusion", "local file inclusion", "lfi", "remote file inclusion", "rfi"):
        return "file_inclusion"

    # --- Server misconfiguration ---
    if contains("x-content-type-options", "x-frame-options", "content-security-policy", "csp", "hsts", 
                "permissions-policy", "subresource integrity", "sri", "missing content-type header",
                "missing anti-clickjacking header"):
        return "missing_security_headers"
    
    if contains("insecure http", "http usage"):
        return "insecure_http_usage"
    if contains("access-control-allow-origin", "cors", "cross origin resource sharing"):
        return "cors_misconfig"
    if contains("basic authentication", "insecure authentication", "insecure crossdomain", "crossdomain.xml", "asp.net debugging", "debugging enabled", "php errors enabled"):
        return "security_misconfig"
        
    if contains("ssl", "tls", "weak cipher", "insecure transportation security",
                "unicode transformation", "viewsstate is not encrypted", 
                "weak secret is used to sign jwt", "php session.use_only_cookies",
                "php allow_url_fopen", "php open_basedir"):
        return "misconfig"

    # --- Auth / Session ---
    if contains("session fixation", "session cookie", "cookies not marked as httponly", 
                "cookies with missing"):
        return "session_fixation"
    if contains("weak password", "password transmitted over http", "possible username or password"):
        return "weak_password_policy"

    # --- Information disclosure ---
    if contains("information leak", "information disclosure", "server leaks", 
                "microsoft iis tilde", "asp.net error message", "programming error messages",
                "web application firewall detected", "generic email address", 
                "reverse proxy detected", "[possible] internal ip address", "internal ip address", "prometheus metrics",
                "phpinfo pages", "stack trace disclosure", "sensitive information", "php info disclosure"):
        return "info_leak"
        
    if contains("version disclosure", "server:", "x-powered-by", "error page web server version", "server banner disclosure"):
        return "tech_stack_disclosure"
        

    # --- Package / Dependency ---
    if contains("vulnerable package", "vulnerable dependency", "vulnerable javascript", 
                "angularjs", "jquery", "bootstrap", "handlebars"):
        return "vulnerable_dependencies"
        
    if contains("outdated"):
        return "outdated_software"

    # --- Network / redirect ---
    if contains("open redirect", "open redirection"):
        return "open_redirect"
    if contains("ssrf", "server side request forgery"):
        return "ssrf"

    # --- RCE / CSRF ---
    if contains("remote code execution", "rce"):
        return "rce"
    if contains("csrf", "absence of anti-csrf"):
        return "csrf"
    
    if contains("user agent fuzzer"):
        return "user_agent_fuzzer"
    
    if contains("charset mismatch"):
        return "charset mismatch"
    
    if contains("modern web application"):
        return "modern_web"

    # If nothing matched
    # ปริ้นท์ชื่อ Alert ที่หลุดออกมาดู (เฉพาะตอนรัน debug)
    # print(f"⚠️  OTHER DETECTED → {name}") 
    return "other"


# -----------------------------
# Build raw_input field
# -----------------------------
def build_raw_input(alert: dict) -> str:
    parts = []

    parts.append(f"Alert: {alert.get('alert', '')}")
    parts.append(f"Severity: {alert.get('risk', '')}, Status: {alert.get('confidence', '')}")
    parts.append(f"Evidence: {alert.get('evidence')}")
    parts.append(f"Attack vector: {alert.get('attack', '')}")
    parts.append(f"Details: {alert.get('other', '')}")
    parts.append(f"Impact: {alert.get('description', '')}")
    parts.append(f"Response Header: {alert.get('responseHeader', '')}")

    return "\n".join(parts)


# -----------------------------
# Main transform function
# -----------------------------
def transform_alert(alert: dict) -> dict:
    vuln_type = map_vuln_type(alert.get("alert", ""))

    return {
        "instruction": "Classify and explain if the alert is false positive.",
        "source": "zap",
        "site": re.sub(r"^https?://", "", alert.get("_scanned_url", "")).strip("/"),
        "vuln_type": vuln_type,
        "severity": alert.get("risk", "").lower(),
        "url": alert.get("url", ""),
        "param": alert.get("param", ""),
        "payload": alert.get("attack", ""),
        "evidence": alert.get("evidence", ""),
        "raw_input": build_raw_input(alert),
        "reason": "",
        "label": "",
        "vuln_type_raw": vuln_type,
    }


# -----------------------------
# Convert input JSON → JSONL
# -----------------------------
def convert_to_jsonl(input_json_path: str, output_jsonl_path: str):
    with open(input_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # ✅ ใช้เฉพาะ alert ที่อยู่ใน "zap_alerts"
    if isinstance(data, dict) and "zap_alerts" in data:
        alerts = data["zap_alerts"]
    elif isinstance(data, list):
        alerts = data
    else:
        alerts = []

    with open(output_jsonl_path, "w", encoding="utf-8") as out:
        for alert in alerts:
            record = transform_alert(alert)
            out.write(json.dumps(record, ensure_ascii=False) + "\n")


# -----------------------------
# Example usage
# -----------------------------
if __name__ == "__main__":
    convert_to_jsonl(
        input_json_path=r"E:\thesis\automate-script\input.json",
        output_jsonl_path=r"E:\thesis\automate-script\output.jsonl"
    )
