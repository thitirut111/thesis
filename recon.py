#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess, json, os, sys, shutil, tempfile, xml.etree.ElementTree as ET

SUBFINDER = shutil.which("subfinder") or "/home/kali/go/bin/subfinder"
NMAP = shutil.which("nmap") or "/usr/bin/nmap"
HTTPX = shutil.which("httpx") or "/usr/bin/httpx"
ENABLE_FULL_SCAN = False
COMMON_PATHS = ["/", "/robots.txt", "/sitemap.xml", "/login", "/admin", "/wp-login.php", "/wp-admin", "/phpinfo.php", "/.env", "/.git/HEAD", "/api", "/swagger-ui.html", "/graphql", "/actuator/health", "/metrics", "/server-status"]
wordlist_path = '/home/kali/Desktop/project/wordlist.txt'

def normalize_target_for_subfinder(s):
    if not s: return ""
    s = s.strip()
    if s.startswith(("http://", "https://")): s = s.split("://", 1)[1]
    if "@" in s: s = s.split("@", 1)[1]
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if ":" in s: s = s.split(":", 1)[0]
    return s.lower()
    
def hostport_to_base_urls(hp):
    if ":" in hp:
        host, port = hp.rsplit(":", 1)
        if port == "80": return [f"http://{host}"]
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
    ok_states = ("open", "open|filtered")
    open_ports = set()
    root = ET.fromstring(xml_output)
    for host in root.findall("host"):
        addr = None
        for a in host.findall("address"):
            if a.attrib.get("addrtype") == "ipv4":
                addr = a.attrib.get("addr")
                break
        if not addr:
            a = host.find("address")
            if a is not None:
                addr = a.attrib.get("addr")
        if not addr: continue
        for port in host.findall(".//port"):
            state = (port.find("state").attrib.get("state", "")).lower()
            if any(state.startswith(s) for s in ok_states):
                pnum = port.attrib.get("portid")
                open_ports.add(f"{addr}:{pnum}")
    return open_ports
    
def run_nmap_mode(targets_file, args):
    cmd = [NMAP, "-Pn", "-T4", "-oX", "-", "-iL", targets_file] + args
    proc = subprocess.run(cmd, text=True, capture_output=True)
    return {"cmd": " ".join(cmd), "rc": proc.returncode, "stderr": proc.stderr.strip(), "ports": sorted(parse_nmap_xml(proc.stdout)) if proc.returncode == 0 else []}
    
def run_nmap_multiple_modes(targets_file, do_full=False):
    modes = {"fast_scan": ["-F"], "top200_scan": ["--top-ports", "200"], "service_scan": ["-sV", "--top-ports", "200"], "web_core": ["-sT", "-p", "80,443"]}
    if do_full: modes["full_scan"] = ["-sV", "-p-"]
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
    cmd = [HTTPX, "-silent", "-follow-redirects", "-status-code", "-web-server", "-tech-detect", "-json", "-l", path]
    proc = subprocess.run(cmd, text=True, capture_output=True)
    # cleanup the temp file created by httpx
    try:
        os.unlink(path)
    except Exception:
        pass
    if proc.returncode not in (0, 2): return []
    out = []
    for line in proc.stdout.splitlines():
        try:
            o = json.loads(line)
            out.append({"url": o.get("url"), "status_code": o.get("status_code"), "webserver": o.get("webserver"), "tech": o.get("tech", [])})
        except: pass
    return out
    
KATANA = shutil.which("katana") or "/usr/bin/katana"
def run_katana(base_urls):
    cmd = [KATANA, "-silent", "-jc"]
    input_data = "\n".join(base_urls)
    try:
        proc = subprocess.run(cmd, input=input_data, text=True, capture_output=True, check=True)
        seen = set() # ใช้ set เพื่อประสิทธิภาพในการกรองตัวซ้ำ
        for line in proc.stdout.splitlines():
            try:
                data = json.loads(line)
                url = data.get("endpoint", data.get("url"))
                if url:
                    seen.add(url) # เพิ่ม URL ที่พบเข้า set
            except json.JSONDecodeError:
                continue
        return sorted(list(seen)) # คืนค่าเป็น list ของ URL ที่ไม่ซ้ำกัน
    except Exception as e:
        sys.stderr.write(f"katana failed: {e}\n")
        return []

def run_ffuf(target_url, wordlist_path, threads=20, timeout=5):
    ffuf = shutil.which("ffuf")
    if not ffuf:
        # ไม่พบ ffuf
        return []

    fd, out_path = tempfile.mkstemp(prefix="ffuf_out_", suffix=".json", dir="/tmp")
    os.close(fd)

    cmd = [
        ffuf,
        "-w", wordlist_path,
        "-u", target_url,
        "-t", str(threads),
        "-timeout", str(timeout),
        "-of", "json",
        "-o", out_path,
        "-s"
    ]

    # รัน ffuf แบบเงียบ (ผลถูกเขียนลง out_path)
    rc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode

    results = []
    try:
        if rc != 0 or not os.path.exists(out_path):
            return []

        with open(out_path, "r", encoding="utf-8", errors="ignore") as fh:
            try:
                obj = json.load(fh)
            except Exception:
                return []

            seen = set()
            for r in obj.get("results", []):
                # ffuf JSON มักมี fields: 'url' (string), 'status' (int), 'length' (int) ฯล.
                url = r.get("url") or None
                # ใช้ key 'status' ของ ffuf เป็น status_code
                status = r.get("status")
                if not url:
                    continue
                if url in seen:
                    continue
                seen.add(url)
                results.append({"url": url, "status_code": status})
    finally:
        try:
            os.unlink(out_path)
        except Exception:
            pass

    return results

def main():
    raw_target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com/"
    domain_for_subfinder = normalize_target_for_subfinder(raw_target)

    # --- subfinder ---
    try:
        subdomains = subprocess.check_output([SUBFINDER, "-d", domain_for_subfinder, "-silent"], text=True, stderr=subprocess.STDOUT).splitlines()
    except Exception:
        subdomains = []
    subdomains = sorted({s.strip().lower() for s in subdomains if s.strip()})
    if domain_for_subfinder not in subdomains:
        subdomains.append(domain_for_subfinder)

    seed_hosts = subdomains if subdomains else [domain_for_subfinder]

    # --- write seed list for nmap ---
    with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
        tmp.write("\n".join(seed_hosts)); tmp.flush(); list_path = tmp.name

    # --- nmap scans ---
    nmap_results = run_nmap_multiple_modes(list_path, do_full=ENABLE_FULL_SCAN)
    # cleanup nmap list file
    try:
        os.unlink(list_path)
    except Exception:
        pass

    ports = nmap_results.get("all_open_ports", [])
    if ports:
        bases = sorted(set(u for hp in ports for u in hostport_to_base_urls(hp)))
    else:
        bases = sorted(set(u for s in seed_hosts for u in (f"http://{s}", f"https://{s}")))

    # --- [LOGIC ใหม่] ---
    
    # 1. รวบรวม URL จาก Common Paths และ Katana
    to_probe_common = expand_with_paths(bases, COMMON_PATHS)
    katana_urls = run_katana(bases) # <-- ได้ list[str] จากฟังก์ชันใหม่
    
    # รวม URL ทั้งหมดและลบตัวซ้ำ
    all_urls_to_probe = sorted(set(to_probe_common + katana_urls))

    # 2. รัน httpx เพื่อตรวจสอบสถานะ URL ทั้งหมด
    # httpx_results จะมีข้อมูล status_code, tech, webserver ที่สมบูรณ์
    httpx_results = alive_endpoints_with_httpx(all_urls_to_probe) # list of dicts

    # 3. รัน FFUF (ยังคงแยกกัน)
    fuzz_target = raw_target.rstrip("/") + "/FUZZ"
    fuzz_results = run_ffuf(fuzz_target, wordlist_path) # list of dicts

    # --- [LOGIC ใหม่] BUILD endpoints map ---
    endpoints_map = {}

    # 1) ใส่ผลจาก httpx (ที่รวม Katana+Common) เข้าไปก่อน
    for r in (httpx_results or []):
        try:
            url = r.get("url")
            if url:
                # เก็บ object ทั้งหมดที่ httpx คืนมา (มี tech, webserver ฯลฯ)
                endpoints_map[url] = r 
        except Exception:
            continue

    # 2) เพิ่ม/อัปเดต ด้วยผลจาก ffuf
    for item in (fuzz_results or []):
        try:
            url = item.get("url")
            status = item.get("status_code")
            if not url:
                continue
                
            if url in endpoints_map:
                # ถ้า httpx มีข้อมูลอยู่แล้ว เราจะเชื่อ httpx มากกว่า
                # แต่ถ้า httpx ไม่มี status (ซึ่งไม่น่าเกิด) ให้ใช้ของ ffuf
                if endpoints_map[url].get("status_code") is None and status is not None:
                    endpoints_map[url]["status_code"] = status
            else:
                # ถ้าเป็น URL ใหม่ที่ ffuf เจอ (httpx/katana ไม่เจอ) ให้เพิ่มเข้าไป
                endpoints_map[url] = {"url": url, "status_code": status}
        except Exception:
            continue
    # --- [จบ LOGIC ใหม่] ---

    # final endpoints list (sorted by url for deterministic output)
    endpoints_list = sorted(list(endpoints_map.values()), key=lambda x: (x.get("url") or ""))

    # --- สรุปผล ---
    result = {
        "meta": {"input": raw_target, "domain_for_subfinder": domain_for_subfinder},
        "target": domain_for_subfinder,
        "subdomains": subdomains,
        "ports": ports,
        # "nmap_results": nmap_results, # (เอาออกตามที่คุยกัน)
        "endpoints": endpoints_list
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
