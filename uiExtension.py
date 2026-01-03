# -*- coding: utf-8 -*-
# uiExtension.py

from javax.swing import (
    JPanel, JLabel, JTextField, JButton, JTextArea, JScrollPane,
    JTable, JTabbedPane, JOptionPane, JProgressBar, BorderFactory
)
from javax.swing.table import DefaultTableModel, TableRowSorter
from javax.swing.border import TitledBorder
from java.awt import GridBagLayout, GridBagConstraints, Insets, Dimension, Font
import subprocess
import os, sys, json, re, time, codecs
from threading import Thread
from java.util import Comparator

# =========================
# PATH SHIM (import helpers)
# =========================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# import zap_client (Jython safe)
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

# =========================
# GLOBAL FONTS (ใหญ่ขึ้น)
# =========================
BASE_FONT   = Font("SansSerif", Font.PLAIN, 14)    # ตัวพื้น
BOLD_FONT   = Font("SansSerif", Font.BOLD, 14)     # ตัวหนา
HEADER_FONT = Font("SansSerif", Font.BOLD, 18)     # หัวข้อใหญ่
MONO_FONT   = Font("Monospaced", Font.PLAIN, 14)   # โมโนสเปซ

# =========================
# CONFIG
# =========================
SAVE_DIR = "/home/kali/thesis/alert_dump"
RESULT_PREFIX = "alert"       # => alert_YYYYMMDD_HHMMSS.json
SCAN_LIMIT = 20               # max URLs to send to ZAP

# ---- ZAP toggle (ตั้งค่า True เพื่อสแกนด้วย ZAP, False เพื่อข้าม) ----
ENABLE_ZAP = True
ZAP_BASE   = "http://127.0.0.1:8088"
ZAP_APIKEY = "4b4cqkmda9nqgjjcrdoflv79fn"
ZAP_TIMEOUT= 120

# =========================
# UTILS
# =========================
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
    h = "%s" % host
    if h.startswith("http://") or h.startswith("https://"):
        return [h]
    if not h.endswith("/"):
        h += "/"
    return ["%s://%s" % (preferred_scheme, h)]

from urlparse import urlparse
def normalize_origin(u):
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
    ดึง URL/ออริจินจากผล recon (รองรับ keys: target, subdomains, ports, endpoints)
    คืนค่าลิสต์ origins (scheme://host[:port]/) แบบ unique
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

    # Normalize + unique
    seen, uniq = set(), []
    for u in raw_urls:
        nu = normalize_origin(u)
        if nu and nu not in seen:
            seen.add(nu)
            uniq.append(nu)
    return uniq

# =========================
# TABLE RENDERING
# =========================
TABLE_COLUMNS = ["Risk", "Alert", "URL", "CWE", "Parameter", "Attack"]

def alerts_to_rows(alerts):
    rows = []
    for a in (alerts or []):
        try:
            risk   = a.get("risk", "") or a.get("riskcode", "")
            alert  = a.get("alert", "")
            url    = a.get("url", a.get("_scanned_url", ""))
            cwe    = a.get("cweid", "")
            param  = a.get("param", "")
            attack = a.get("attack", "")
            rows.append([risk, alert, url, cwe, param, attack])
        except Exception:
            pass
    return rows

_RISK_ORDER = {
    "High": 3, "Medium": 2, "Low": 1, "Informational": 0, "Info": 0, "": -1, None: -1
}

class RiskComparator(Comparator):
    def compare(self, a, b):
        av = _RISK_ORDER.get(str(a), _RISK_ORDER.get(a, -1))
        bv = _RISK_ORDER.get(str(b), _RISK_ORDER.get(b, -1))
        return (av > bv) - (av < bv)

class IntLikeComparator(Comparator):
    def compare(self, a, b):
        def to_int(x):
            try:
                return int(str(x).strip())
            except:
                return None
        ai, bi = to_int(a), to_int(b)
        if ai is not None and bi is not None:
            return (ai > bi) - (ai < bi)
        sa, sb = ("" if a is None else str(a)), ("" if b is None else str(b))
        return (sa > sb) - (sa < sb)

# =========================
# UI HELPERS
# =========================
def join_lines(items, bullet=False):
    out = []
    for x in (items or []):
        if x is None:
            continue
        s = "%s" % x
        if s.strip():
            out.append(("- " if bullet else "") + s.strip())
    return "\n".join(out) if out else "-"

def make_box(title):
    box = JPanel(GridBagLayout())
    box.setBorder(BorderFactory.createTitledBorder(title))
    return box

def add_g(panel, comp, x, y, w=1, h=1, wx=0.0, wy=0.0,
          fill=GridBagConstraints.BOTH,
          inset=Insets(6,6,6,6),
          anchor=GridBagConstraints.CENTER):
    c = GridBagConstraints()
    c.gridx = x; c.gridy = y; c.gridwidth = w; c.gridheight = h
    c.weightx = wx; c.weighty = wy; c.fill = fill; c.insets = inset; c.anchor = anchor
    panel.add(comp, c)

def mk_readonly_text(rows=10, cols=24, mono=True, size=14):
    ta = JTextArea(rows, cols)
    ta.setEditable(False)
    ta.setFont(Font("Monospaced" if mono else "SansSerif", Font.PLAIN, size))
    return ta

# =========================
# MAIN PANEL
# =========================
def create_panel():
    panel = JPanel()
    layout = GridBagLayout()
    panel.setLayout(layout)
    c = GridBagConstraints()

    # Row 0: Label + Input + Button
    c.gridx = 0; c.gridy = 0
    c.weightx = 0.0
    c.insets = Insets(10, 10, 5, 5)
    c.anchor = c.WEST
    label_target = JLabel("Target (domain or URL):")
    label_target.setFont(BASE_FONT)
    panel.add(label_target, c)

    url_field = JTextField(36)
    url_field.setFont(BASE_FONT)
    c.gridx = 1; c.gridy = 0
    c.weightx = 1.0
    c.fill = c.HORIZONTAL
    panel.add(url_field, c)

    scan_button = JButton("Scan")
    scan_button.setFont(BOLD_FONT)
    scan_button.setPreferredSize(Dimension(120, 28))
    c.gridx = 2; c.gridy = 0
    c.weightx = 0.0
    c.fill = GridBagConstraints.NONE
    c.insets = Insets(10, 8, 5, 10)
    panel.add(scan_button, c)

    # Row 1: Status + Progress
    status_label = JLabel("Idle.")
    status_label.setFont(BASE_FONT)
    c.gridx = 0; c.gridy = 1
    c.gridwidth = 1
    c.insets = Insets(0, 10, 5, 5)
    c.anchor = c.WEST
    panel.add(status_label, c)

    progress = JProgressBar()
    progress.setIndeterminate(False)
    progress.setPreferredSize(Dimension(180, 16))
    c.gridx = 1; c.gridy = 1
    c.gridwidth = 2
    c.weightx = 1.0
    c.fill = c.HORIZONTAL
    c.insets = Insets(0, 5, 5, 10)
    panel.add(progress, c)

    # Row 2: Tabs
    tabs = JTabbedPane()

    # ===== Summary tab =====
    summary_panel = JPanel(GridBagLayout())
    summary_wrapper = JPanel(GridBagLayout())
    summary_wrapper.setBorder(BorderFactory.createEmptyBorder(10,10,10,10))

    header = JLabel("target URL : -")
    header.setFont(HEADER_FONT)
    add_g(summary_wrapper, header, 0, 0, w=2, wx=1.0, fill=GridBagConstraints.HORIZONTAL)

    # Left column
    sub_box = make_box("Subdomains")
    sub_area = mk_readonly_text(10, 28, mono=True, size=14)
    add_g(sub_box, JScrollPane(sub_area), 0, 0, wx=1.0, wy=1.0)

    port_box = make_box("Ports")
    port_area = mk_readonly_text(6, 28, mono=True, size=14)
    add_g(port_box, JScrollPane(port_area), 0, 0, wx=1.0, wy=1.0)

    left_col = JPanel(GridBagLayout())
    add_g(left_col, sub_box, 0, 0, wx=1.0, wy=1.0)
    add_g(left_col, port_box, 0, 1, wx=1.0, wy=0.6)

    # Right column
    status_box = make_box("Status")
    status_area = mk_readonly_text(8, 36, mono=False, size=14)
    add_g(status_box, JScrollPane(status_area), 0, 0, wx=1.0, wy=0.5)

    endp_box = make_box("Endpoints")
    endp_area = mk_readonly_text(10, 36, mono=True, size=14)
    add_g(endp_box, JScrollPane(endp_area), 0, 0, wx=1.0, wy=1.0)

    right_col = JPanel(GridBagLayout())
    add_g(right_col, status_box, 0, 0, wx=1.0, wy=0.4)
    add_g(right_col, endp_box, 0, 1, wx=1.0, wy=1.0)

    add_g(summary_wrapper, left_col, 0, 1, wx=0.5, wy=1.0)
    add_g(summary_wrapper, right_col, 1, 1, wx=0.5, wy=1.0)

    for box in (sub_box, port_box, status_box, endp_box):
        bd = box.getBorder()
        if isinstance(bd, TitledBorder):
            bd.setTitleFont(BOLD_FONT)

    add_g(summary_panel, summary_wrapper, 0, 0, wx=1.0, wy=1.0)
    tabs.addTab("Summary", summary_panel)

    # ===== Scan Results tab =====
    table_model = DefaultTableModel(TABLE_COLUMNS, 0)
    table = JTable(table_model)
    table.setFont(BASE_FONT)
    table.setRowHeight(22)
    table.getTableHeader().setFont(BOLD_FONT)
    table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN)
    table.getColumnModel().getColumn(0).setPreferredWidth(60)
    table.getColumnModel().getColumn(1).setPreferredWidth(220)
    table.getColumnModel().getColumn(2).setPreferredWidth(340)
    table.getColumnModel().getColumn(3).setPreferredWidth(60)
    table.getColumnModel().getColumn(4).setPreferredWidth(120)
    table.getColumnModel().getColumn(5).setPreferredWidth(160)
    table_scroll = JScrollPane(table)
    tabs.addTab("Scan Results", table_scroll)

    sorter = TableRowSorter(table_model)
    sorter.setComparator(0, RiskComparator())     # Risk: High > Medium > Low > Info
    sorter.setComparator(3, IntLikeComparator())  # CWE: ตัวเลขมาก/น้อย
    table.setRowSorter(sorter)

    c.gridx = 0; c.gridy = 2
    c.gridwidth = 3
    c.weightx = 1.0; c.weighty = 1.0
    c.fill = c.BOTH
    c.insets = Insets(8, 10, 10, 10)
    panel.add(tabs, c)

    # ---------- Worker helpers ----------
    def set_busy(b):
        progress.setIndeterminate(b)
        scan_button.setEnabled(not b)

    def show_status(text):
        status_label.setText(text)

    def set_summary_header(text):
        header.setText("target URL : %s" % (text or "-"))

    def set_status_lines(lines):
        if isinstance(lines, (list, tuple)):
            status_area.setText("\n".join(lines))
        else:
            status_area.setText("%s" % (lines or ""))

    def render_summary_from_recon(recon_obj, input_text, targets):
        set_summary_header(input_text or (targets[0] if targets else "-"))

        subs = []
        try:
            for s in (recon_obj.get("subdomains") or []):
                subs.append("%s" % s)
        except Exception:
            pass
        sub_area.setText(join_lines(subs, bullet=True))

        ports_lines = []
        try:
            ports = recon_obj.get("ports") or []
            for p in ports:
                if isinstance(p, dict):
                    host = p.get("host") or p.get("ip") or "-"
                    port = p.get("port") or p.get("value") or "-"
                    ports_lines.append("%s : %s" % (host, port))
                else:
                    ports_lines.append("%s" % p)
        except Exception:
            pass
        port_area.setText(join_lines(ports_lines, bullet=True))

        eps = []
        try:
            for e in (recon_obj.get("endpoints") or []):
                u = (e.get("url") or "").strip()
                sc = e.get("status_code")
                if u:
                    eps.append(u if sc is None else "%s  (%s)" % (u, sc))
        except Exception:
            pass
        if not eps and targets:
            eps = targets
        endp_area.setText(join_lines(eps, bullet=False))

    def append_status(msg):
        prev = status_area.getText().strip()
        status_area.setText((prev + "\n" if prev else "") + ("%s" % msg))

    # ---------- Main worker ----------
    def run_scan(target_input):
        """
        1) run recon.py
        2) extract URLs -> targets
        3) (optional) scan with ZAP
        4) save JSON
        5) update Summary + Table
        """
        if zap_client is None:
            JOptionPane.showMessageDialog(panel, "[!] Cannot import zap_client.py:\n%s" % str(_ZAP_IMPORT_ERROR))
            return

        if not target_input:
            JOptionPane.showMessageDialog(panel, "Please enter target.")
            return

        set_busy(True)
        show_status("Running recon...")
        set_summary_header(target_input)
        set_status_lines(["recon ongoing"])

        env = os.environ.copy()
        env["PATH"] = os.path.expanduser("~/go/bin") + os.pathsep + env.get("PATH", "")

        try:
            # 1) recon
            cmd = "python3 recon.py " + safe_quote(target_input)
            process = subprocess.Popen(
                cmd, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env # <--- แยก stderr
            )
            stdout, stderr = process.communicate() # <--- รับผลลัพธ์ 2 ทาง

            # text คือผลลัพธ์ JSON ที่สะอาด
            text = stdout.decode("utf-8", "ignore")

            try:
                recon_obj = json.loads(text)
                append_status("Got JSON from recon")  # <--- เพิ่มบรรทัดนี้
            except Exception as e:
                # (แนะนำ) เพิ่มสถานะเมื่อ JSON ล้มเหลวด้วย
                append_status("JSON parse failed") 
                recon_obj = {"raw_text": text}

            preferred = "https"
            if is_url(target_input):
                preferred = (target_input.split(":", 1)[0] or "https").lower()

            # 2) collect URLs
            targets = extract_urls_from_recon_json(text, target_input, preferred_scheme=preferred)
            if not targets:
                raw = re.findall(r'https?://[^\s"<>]+', text)
                seen = set(); targets = []
                for u in raw:
                    nu = normalize_origin(u)
                    if nu and nu not in seen:
                        seen.add(nu)
                        targets.append(nu)

            render_summary_from_recon(recon_obj, target_input, targets)
            append_status("recon done, %d target(s) prepared" % len(targets))

            if not targets:
                show_status("No URLs to scan.")
                set_busy(False)
                return

            to_scan = targets[:SCAN_LIMIT]

            # 3) ZAP scan (Auto-Start Logic)
            alerts = []
            if ENABLE_ZAP:
                show_status("Checking ZAP status...")
                
                # --- ส่วนที่เพิ่ม: เช็คว่า ZAP เปิดอยู่ไหม ถ้าไม่เปิดให้สั่งเปิด ---
                z_conn = zap_client.ZapClient(base=ZAP_BASE, apikey=ZAP_APIKEY, timeout=5)
                zap_is_up = False
                
                try:
                    # ลอง Ping ดูว่า ZAP อยู่ไหม
                    v = z_conn.version()
                    append_status("ZAP is already running (v%s)" % v)
                    zap_is_up = True
                except Exception:
                    # ถ้า Error แปลว่ายังไม่เปิด -> สั่งเปิดเลย!
                    append_status("ZAP is offline. Auto-starting daemon...")
                    try:
                        zap_client.start_zap_daemon()
                        
                        # รอให้ ZAP บูตเสร็จ (วนลูปเช็คทุก 2 วิ นานสุด 60 วิ)
                        show_status("Booting ZAP (please wait ~20s)...")
                        for i in range(30): 
                            time.sleep(2)
                            try:
                                z_conn.version()
                                zap_is_up = True
                                append_status("ZAP started successfully!")
                                break
                            except Exception:
                                pass # ยังบูตไม่เสร็จ รอต่อ
                    except Exception as e:
                        append_status("Failed to auto-start ZAP: %s" % str(e))

                # --- จบส่วน Auto-Start ---

                if zap_is_up:
                    show_status("Scanning %d URL(s) with ZAP..." % len(to_scan))
                    append_status("scan started with ZAP...")
                    try:
                        # สร้าง Client ใหม่ (เผื่อ timeout)
                        z = zap_client.ZapClient(
                            base=ZAP_BASE,
                            apikey=ZAP_APIKEY,
                            timeout=ZAP_TIMEOUT
                        )
                        alerts = z.active_scan_urls(
                            to_scan,
                            spider_first=True,
                            recurse=True,
                            limit=SCAN_LIMIT,
                            sleep=1.0
                        )

                        show_status("Done. Alerts: %d" % len(alerts))
                        append_status("scan completed. alerts: %d" % len(alerts))

                    except Exception as e:
                        show_status("ZAP error")
                        append_status("ZAP error: %s" % str(e))
                else:
                    show_status("Skipping ZAP (Connection failed)")
                    append_status("Could not connect to ZAP after waiting.")
            else:
                append_status("ZAP disabled (ENABLE_ZAP=False). Skipping active scan.")
                show_status("Recon done. ZAP skipped.")

            # 4) save bundle JSON
            ok, err = ensure_dir(SAVE_DIR)
            bundle = {
                "meta": {
                    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "target_input": target_input,
                    "preferred_scheme": preferred,
                    "num_scan_targets": len(to_scan),
                    "save_dir": SAVE_DIR,
                    "zap_enabled": ENABLE_ZAP
                },
                "recon": recon_obj,
                "scan_targets": to_scan,
                "zap_alerts": alerts
            }
            if not ok:
                append_status("cannot create dir: %s" % str(err))
            else:
                out_path = generate_timestamp_filename(SAVE_DIR, prefix=RESULT_PREFIX, ext=".json")
                try:
                    with codecs.open(out_path, "w", "utf-8") as f:
                        json.dump(bundle, f, ensure_ascii=False, indent=2)
                    append_status("saved: %s" % out_path)
                except Exception as e:
                    append_status("cannot write JSON: %s" % str(e))

            # 5) fill table (ถ้า ZAP ถูกปิด ตารางก็จะว่าง—which is expected)
            while table_model.getRowCount() > 0:
                table_model.removeRow(0)
            for row in alerts_to_rows(alerts):
                table_model.addRow(row)

        except Exception as e:
            show_status("Error")
            append_status("error: %s" % str(e))
        finally:
            set_busy(False)

    # Button action
    def on_scan_click(event):
        target_input = url_field.getText().strip()
        Thread(target=lambda: run_scan(target_input)).start()

    scan_button.actionPerformed = on_scan_click

    return panel
