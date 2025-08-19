#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess, json, os, sys, shutil, tempfile

SUBFINDER = "/home/kali/go/bin/subfinder"
NAABU     = shutil.which("naabu")  or "/usr/bin/naabu"
HTTPX     = shutil.which("httpx")  or "/usr/bin/httpx"

# common endpoints to probe on each base URL
COMMON_PATHS = [
    "/", "/robots.txt", "/sitemap.xml",
    "/login", "/admin", "/wp-login.php", "/wp-admin",
    "/phpinfo.php", "/.env", "/.git/HEAD",
    "/api", "/swagger-ui.html", "/graphql",
    "/actuator/health", "/metrics", "/server-status"
]

def alive_endpoints_with_httpx(urls):
    """Run httpx against list of URLs and return endpoint objects (url, status_code, webserver, tech)."""
    if not urls:
        return []
    with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
        tmp.write("\n".join(urls)); tmp.flush(); path = tmp.name
    cmd = [
        HTTPX, "-silent",
        "-follow-redirects",
        "-status-code",
        "-web-server",
        "-tech-detect",
        "-json",
        "-l", path
    ]
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if proc.returncode not in (0, 2):  # treat 2 (no input/filtered out) as non-fatal
        return []
    out = []
    for line in proc.stdout.splitlines():
        try:
            o = json.loads(line)
            out.append({
                "url": o.get("url"),
                "status_code": o.get("status_code"),
                "webserver": o.get("webserver"),
                "tech": o.get("tech", [])
            })
        except json.JSONDecodeError:
            pass
    return out

def hostport_to_base_urls(hp: str):
    """Convert 'host:port' into base URLs."""
    if ":" in hp:
        host, port = hp.rsplit(":", 1)
        if port == "80":  return [f"http://{host}"]
        if port == "443": return [f"https://{host}"]
        return [f"http://{host}:{port}", f"https://{host}:{port}"]
    return [f"http://{hp}", f"https://{hp}"]

def expand_with_paths(bases, paths):
    """Expand base URLs with a set of paths."""
    expanded = []
    for b in bases:
        b = b.rstrip("/")
        for p in paths:
            if not p.startswith("/"):
                p = "/" + p
            expanded.append(b + p)
    return sorted(set(expanded))

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "testphp.vulnweb.com"

    # subfinder
    try:
        subdomains = subprocess.check_output(
            [SUBFINDER, "-d", target, "-silent"], text=True
        ).splitlines()
    except Exception:
        print(json.dumps({"target": target, "subdomains": [], "ports": [], "endpoints": []}, ensure_ascii=False, indent=2))
        return
    subdomains = sorted({s.strip() for s in subdomains if s.strip()})
    if target not in subdomains:
        subdomains.append(target)

    # naabu (80,443) using -list
    with tempfile.NamedTemporaryFile("w+", delete=False) as tmp_list:
        tmp_list.write("\n".join(subdomains)); tmp_list.flush(); list_path = tmp_list.name
    proc = subprocess.run(
        [NAABU, "-silent", "-p", "80,443", "-verify", "-list", list_path],
        text=True, capture_output=True
    )
    ports = []
    if proc.returncode == 0:
        ports = sorted({line.strip() for line in proc.stdout.splitlines() if line.strip()})

    # Build candidate base URLs:
    if ports:
        bases = sorted(set(u for hp in ports for u in hostport_to_base_urls(hp)))
    else:
        # fallback: try subdomains directly on http/https
        bases = sorted(set(u for s in subdomains for u in (f"http://{s}", f"https://{s}")))

    # Expand bases with common paths and probe via httpx
    to_probe = expand_with_paths(bases, COMMON_PATHS)
    endpoints = alive_endpoints_with_httpx(to_probe)

    # print JSON result
    result = {
        "target": target,
        "subdomains": subdomains,
        "ports": ports,              # e.g. ["host:80", "host:443"]
        "endpoints": endpoints       # list of {url, status_code, webserver, tech}
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
