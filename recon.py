#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess, json, os, sys, shutil, tempfile, xml.etree.ElementTree as ET

SUBFINDER = "/home/kali/go/bin/subfinder"
NMAP      = shutil.which("nmap")  or "/usr/bin/nmap"
HTTPX     = shutil.which("httpx") or "/usr/bin/httpx"

# เปิด/ปิด full scan ได้ตรงนี้
ENABLE_FULL_SCAN = False

COMMON_PATHS = [
    "/", "/robots.txt", "/sitemap.xml",
    "/login", "/admin", "/wp-login.php", "/wp-admin",
    "/phpinfo.php", "/.env", "/.git/HEAD",
    "/api", "/swagger-ui.html", "/graphql",
    "/actuator/health", "/metrics", "/server-status"
]

# -------------------- helpers --------------------
def normalize_target_for_subfinder(s):
    if not s: return ""
    s = s.strip()
    if s.startswith(("http://","https://")): s = s.split("://",1)[1]
    if "@" in s: s = s.split("@",1)[1]
    s = s.split("/",1)[0].split("?",1)[0].split("#",1)[0]
    if ":" in s: s = s.split(":",1)[0]
    return s.lower()

def hostport_to_base_urls(hp):
    if ":" in hp:
        host, port = hp.rsplit(":", 1)
        if port == "80":  return [f"http://{host}"]
        if port == "443": return [f"https://{host}"]
        return [f"http://{host}:{port}", f"https://{host}:{port}"]
    return [f"http://{hp}", f"https://{hp}"]

def expand_with_paths(bases, paths):
    out = []
    for b in bases:
        b = b.rstrip("/")
        for p in paths:
            if not p.startswith("/"): p = "/" + p
            out.append(b + p)
    return sorted(set(out))

def parse_nmap_xml(xml_output):
    """
    คืน set(['host:port', ...]) สำหรับสถานะที่ถือว่า 'ใช้ได้'
    นับทั้ง 'open' และ 'open|filtered' เพื่อไม่ให้พลาด web ports หลัง CDN/ไฟร์วอลล์
    """
    ok_states = ("open", "open|filtered")
    open_ports = set()
    root = ET.fromstring(xml_output)
    for host in root.findall("host"):
        # address อาจมีหลายอัน เลือกตัวที่ addrtype='ipv4' ก่อน
        addr = None
        for a in host.findall("address"):
            if a.attrib.get("addrtype") == "ipv4":
                addr = a.attrib.get("addr")
                break
        if not addr:
            a = host.find("address")
            if a is not None:
                addr = a.attrib.get("addr")
        if not addr:
            continue
        for port in host.findall(".//port"):
            state = (port.find("state").attrib.get("state","")).lower()
            if any(state.startswith(s) for s in ok_states):
                pnum = port.attrib.get("portid")
                open_ports.add(f"{addr}:{pnum}")
    return open_ports

def run_nmap_mode(targets_file, args):
    cmd = [NMAP, "-Pn", "-T4", "-oX", "-", "-iL", targets_file] + args
    proc = subprocess.run(cmd, text=True, capture_output=True)
    return {
        "cmd": " ".join(cmd),
        "rc": proc.returncode,
        "stderr": proc.stderr.strip(),
        "ports": sorted(parse_nmap_xml(proc.stdout)) if proc.returncode == 0 else []
    }

def run_nmap_multiple_modes(targets_file, do_full=False):
    modes = {
        "fast_scan":     ["-F"],
        "top200_scan":   ["--top-ports", "200"],
        "service_scan":  ["-sV", "--top-ports", "200"],
        "web_core":      ["-sT", "-p", "80,443"],   # ยิง 80/443 ตรง ๆ เพิ่มความชัวร์
    }
    if do_full:
        modes["full_scan"] = ["-sV", "-p-"]

    results, union = {}, set()
    for name, args in modes.items():
        r = run_nmap_mode(targets_file, args)
        results[name] = r
        union |= set(r["ports"])
    results["all_open_ports"] = sorted(union)
    return results

def alive_endpoints_with_httpx(urls):
    if not urls: return []
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
    if proc.returncode not in (0, 2): return []
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
        except: pass
    return out

# -------------------- main --------------------
def main():
    raw_target = sys.argv[1] if len(sys.argv) > 1 else "https://testphp.vulnweb.com/"
    domain_for_subfinder = normalize_target_for_subfinder(raw_target)

    # subfinder
    try:
        subdomains = subprocess.check_output(
            [SUBFINDER, "-d", domain_for_subfinder, "-silent"],
            text=True, stderr=subprocess.STDOUT
        ).splitlines()
    except Exception:
        subdomains = []

    subdomains = sorted({s.strip().lower() for s in subdomains if s.strip()})
    if domain_for_subfinder not in subdomains:
        subdomains.append(domain_for_subfinder)
    seed_hosts = subdomains if subdomains else [domain_for_subfinder]

    # Nmap scans (หลายโหมด + รวมผล)
    with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
        tmp.write("\n".join(seed_hosts)); tmp.flush(); list_path = tmp.name
    nmap_results = run_nmap_multiple_modes(list_path, do_full=ENABLE_FULL_SCAN)

    # สร้าง base URLs จากพอร์ตที่ได้ ถ้าไม่มีเลยค่อย fallback
    ports = nmap_results.get("all_open_ports", [])
    if ports:
        bases = sorted(set(u for hp in ports for u in hostport_to_base_urls(hp)))
    else:
        bases = sorted(set(u for s in seed_hosts for u in (f"http://{s}", f"https://{s}")))

    to_probe = expand_with_paths(bases, COMMON_PATHS)
    endpoints = alive_endpoints_with_httpx(to_probe)

    # สรุปผล (คงรูปแบบ 'ports' เดิมไว้เป็น list[str] สำหรับ UI)
    result = {
        "meta": {
            "input": raw_target,
            "domain_for_subfinder": domain_for_subfinder,
        },
        "target": domain_for_subfinder,
        "subdomains": subdomains,
        "ports": ports,                      # <- list[str] 'host:port'
        "nmap_results": nmap_results,        # <- รายโหมด + stderr/debug
        "endpoints": endpoints
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
