# -*- coding: utf-8 -*-
from javax.swing import JPanel, JLabel, JTextField, JButton, JTextArea, JScrollPane
from java.awt import GridBagLayout, GridBagConstraints, Insets, Dimension
import subprocess
import os, sys, json, re, time, codecs
from threading import Thread

# ----- PATH SHIM -----
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# import zap_client (stdlib/Jython-safe)
try:
    import zap_client
    _ZAP_IMPORT_ERROR = None
except Exception:
    try:
        from imp import load_source
        zap_client = load_source('zap_client', os.path.join(BASE_DIR, 'zap_client.py'))
        _ZAP_IMPORT_ERROR = None
    except Exception as e:
        zap_client = None
        _ZAP_IMPORT_ERROR = e

# ====== CONFIG ======
SAVE_DIR = "/home/kali/thesis/alert_dump"
RESULT_PREFIX = "alert"     # => alert_YYYYMMDD_HHMMSS.json
SCAN_LIMIT = 20             # max URLs to send to ZAP

# ====== UTILS ======
def ensure_dir(path):
    try:
        if not os.path.isdir(path):
            os.makedirs(path)
        return True, None
    except Exception as e:
        return False, e

def generate_timestamp_filename(base_path, prefix="alert", ext=".json"):
    ts = time.strftime("%Y%m%d_%H%M%S")
    return os.path.join(base_path, "%s_%s%s" % (prefix, ts, ext))

def safe_quote(s):
    return '"' + ("%s" % s).replace('"', '\\"') + '"'

def is_url(s):
    try:
        s = "%s" % s
    except Exception:
        return False
    return s.startswith("http://") or s.startswith("https://")

def add_scheme_if_needed(host, preferred_scheme="https"):
    """เติมแค่ scheme เดียว (ไม่ใส่ทั้ง http/https เพื่อลดซ้ำ)"""
    h = "%s" % host
    if h.startswith("http://") or h.startswith("https://"):
        return [h]
    if not h.endswith("/"):
        h += "/"
    return ["%s://%s" % (preferred_scheme, h)]

# --- origin normalizer ---
from urlparse import urlparse
def normalize_origin(u):
    """
    ให้ค่าเป็น origin เดียว: scheme://host[:port]/
    - lowercase scheme/host
    - ตัดพอร์ตดีฟอลต์ (http:80, https:443)
    - บังคับปิดด้วย '/'
    """
    try:
        p = urlparse(u)
        scheme = (p.scheme or "http").lower()
        host = (p.hostname or "").lower()
        port = p.port
        if not host:
            return None
        if (scheme == "http" and port in (None, 80)) or (scheme == "https" and port in (None, 443)):
            netloc = host
        else:
            netloc = "%s:%s" % (host, port)
        return "%s://%s/" % (scheme, netloc)
    except Exception:
        return None

def host_from_url(u):
    try:
        part = u.split("://", 1)[1]
        return part.split("/", 1)[0]
    except Exception:
        return None

def extract_urls_from_recon_json(text, user_input, preferred_scheme="https"):
    """
    รองรับหลายรูปแบบของ recon.py:
      {
        "target": "http://example.com/",
        "subdomains": ["a.example.com","https://b.example.com/"],
        "ports": [],  # หรือ [{"host":"example.com","port":8080}]
        "endpoints": [{"url":"http://example.com/login","status_code":200}]
      }
    คืนค่าเป็นลิสต์ของ unique origins ที่ normalize แล้ว
    """
    raw_urls = []
    try:
        data = json.loads(text)
    except Exception:
        return []

    # endpoints
    for e in (data.get("endpoints") or []):
        try:
            u = e.get("url")
            sc = e.get("status_code")
            if u and (sc in (200, 301, 302, 403) or sc is None):
                raw_urls.append(u)
        except Exception:
            pass

    # target
    t = data.get("target")
    if t and is_url(t):
        raw_urls.append(t)

    # subdomains
    for sd in (data.get("subdomains") or []):
        if not sd:
            continue
        if is_url(sd):
            raw_urls.append(sd)
        else:
            raw_urls.extend(add_scheme_if_needed(sd, preferred_scheme))

    # ports
    ports = data.get("ports") or []
    base_host = None
    if t and is_url(t):
        base_host = host_from_url(t)
    if (not base_host) and user_input:
        base_host = host_from_url(user_input) if is_url(user_input) else user_input

    for p in ports:
        try:
            if isinstance(p, dict):
                host = p.get("host") or p.get("ip") or base_host
                port = p.get("port") or p.get("value")
                if host and port:
                    scheme = "https" if str(port) == "443" else preferred_scheme
                    raw_urls.append("%s://%s:%s/" % (scheme, host, port))
            else:
                if base_host and ("%s" % p).isdigit():
                    port = int("%s" % p)
                    scheme = "https" if port == 443 else preferred_scheme
                    raw_urls.append("%s://%s:%s/" % (scheme, base_host, port))
        except Exception:
            pass

    # Normalize + unique origin
    seen, uniq = set(), []
    for u in raw_urls:
        nu = normalize_origin(u)
        if nu and nu not in seen:
            seen.add(nu)
            uniq.append(nu)
    return uniq

# ====== UI ======
def create_panel():
    panel = JPanel()
    layout = GridBagLayout()
    panel.setLayout(layout)
    c = GridBagConstraints()

    # Label
    c.gridx = 0; c.gridy = 0
    c.anchor = c.WEST
    c.insets = Insets(10, 10, 5, 5)
    panel.add(JLabel("Target (domain or URL):"), c)

    # Input
    url_field = JTextField(30)
    c.gridx = 1
    c.weightx = 1.0
    c.fill = c.HORIZONTAL
    c.gridwidth = 1
    panel.add(url_field, c)

    # Output area
    output_area = JTextArea(18, 60)
    output_area.setEditable(False)
    output_area.setFocusable(False)
    scroll = JScrollPane(output_area)
    c.gridx = 0; c.gridy = 1
    c.gridwidth = 3
    c.weighty = 1.0
    c.fill = c.BOTH
    c.insets = Insets(10, 10, 5, 10)
    panel.add(scroll, c)

    def on_scan_click(event):
        def worker():
            if zap_client is None:
                output_area.setText("[!] Cannot import zap_client.py: %s\n" % str(_ZAP_IMPORT_ERROR))
                output_area.append("    - Check zap_client.py is in the same folder.\n")
                return

            target_input = url_field.getText().strip()
            if not target_input:
                output_area.setText("Please enter target.\n")
                return

            output_area.setText("Running recon...\n")

            env = os.environ.copy()
            env["PATH"] = os.path.expanduser("~/go/bin") + os.pathsep + env.get("PATH", "")

            try:
                # 1) run recon
                cmd = "python3 recon.py " + safe_quote(target_input)
                output_area.append("$ %s\n" % cmd)
                process = subprocess.Popen(
                    cmd, shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env
                )
                stdout, _ = process.communicate()
                text = stdout.decode("utf-8", "ignore")
                output_area.append(text + "\n")

                # parse recon JSON (ถ้า parse ไม่ได้จะเก็บ raw_text)
                recon_obj = None
                try:
                    recon_obj = json.loads(text)
                except Exception:
                    recon_obj = {"raw_text": text}

                # Determine preferred scheme from input
                preferred = "https"
                if is_url(target_input):
                    preferred = (target_input.split(":", 1)[0] or "https").lower()

                # 2) collect URLs (unique origins)
                targets = extract_urls_from_recon_json(text, target_input, preferred_scheme=preferred)
                if not targets:
                    # fallback: regex + normalize
                    raw = re.findall(r'https?://[^\s"<>]+', text)
                    seen = set(); targets = []
                    for u in raw:
                        nu = normalize_origin(u)
                        if nu and nu not in seen:
                            seen.add(nu)
                            targets.append(nu)

                if not targets:
                    output_area.append("[!] No URLs to scan.\n")
                    return

                # Apply limit and show true count
                to_scan = targets[:SCAN_LIMIT]
                output_area.append("[*] Sending %d URL(s) to ZAP (spider+recurse)...\n" % len(to_scan))

                # 3) ZAP deep-ish scan (spider then recurse)
                try:
                    z = zap_client.ZapClient(
                        base="http://127.0.0.1:8088",
                        apikey="4b4cqkmda9nqgjjcrdoflv79fn",
                        timeout=120
                    )
                    alerts = z.active_scan_urls(
                        to_scan,
                        spider_first=True,
                        recurse=True,
                        limit=SCAN_LIMIT,
                        sleep=1.0
                    )

                    # 4) save JSON bundle (UTF-8 + timestamp)
                    ok, err = ensure_dir(SAVE_DIR)
                    if not ok:
                        output_area.append("[!] Cannot create dir %s: %s\n" % (SAVE_DIR, str(err)))
                    else:
                        bundle = {
                            "meta": {
                                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                                "target_input": target_input,
                                "preferred_scheme": preferred,
                                "num_scan_targets": len(to_scan),
                                "save_dir": SAVE_DIR
                            },
                            "recon": recon_obj,
                            "scan_targets": to_scan,
                            "zap_alerts": alerts
                        }
                        out_path = generate_timestamp_filename(SAVE_DIR, prefix=RESULT_PREFIX, ext=".json")
                        try:
                            with codecs.open(out_path, "w", "utf-8") as f:
                                json.dump(bundle, f, ensure_ascii=False, indent=2)
                            output_area.append("[+] Saved alerts JSON -> %s\n" % out_path)
                        except Exception as e:
                            output_area.append("[!] Cannot write JSON file: %s\n" % str(e))

                    output_area.append("[+] Done. Total alerts: %d\n" % len(alerts))
                except Exception as e:
                    output_area.append("[!] ZAP error: %s\n" % str(e))

            except Exception as e:
                output_area.append("Error: " + str(e) + "\n")

        Thread(target=worker).start()

    # Button
    button = JButton("Scan", actionPerformed=on_scan_click)
    button.setPreferredSize(Dimension(120, 28))
    c.gridx = 2; c.gridy = 0
    c.weightx = 0
    c.fill = GridBagConstraints.NONE
    c.insets = Insets(10, 5, 5, 10)
    panel.add(button, c)

    return panel
