# -*- coding: utf-8 -*-
# zap_client.py
from __future__ import print_function
import json, time, subprocess, sys, os

try:
    from urllib.parse import urlencode
    from urllib.request import urlopen, Request, build_opener, ProxyHandler
except ImportError:
    from urllib import urlencode
    from urllib2 import urlopen, Request, build_opener, ProxyHandler

# ==========================================
# ส่วนตั้งค่า (Configuration)
# ==========================================
# ตรวจสอบ OS: ถ้าเป็น Windows ใช้ path นึง, Linux ใช้อีก path
if os.name == 'nt':
    # ตัวอย่าง path ของ Windows (แก้ได้ถ้าติดตั้งที่อื่น)
    ZAP_PATH = r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat"
else:
    # Linux / Kali
    ZAP_PATH = "/usr/bin/zaproxy"

ZAP_PORT = "8088"
ZAP_HOST = "0.0.0.0"
API_KEY = "4b4cqkmda9nqgjjcrdoflv79fn"

# Helper สำหรับ DEVNULL ใน Python 2
try:
    from subprocess import DEVNULL
except ImportError:
    DEVNULL = open(os.devnull, 'wb')

class ZapError(Exception):
    pass

class ZapClient(object):
    def __init__(self, base="http://127.0.0.1:8088", apikey=None, timeout=60, use_system_proxy=False):
        self.base = base.rstrip("/")
        self.apikey = apikey
        self.timeout = timeout
        self._opener = build_opener(ProxyHandler({})) if not use_system_proxy else None

    # ---------- low-level ----------
    def _open(self, req):
        if self._opener:
            return self._opener.open(req, None, self.timeout)
        return urlopen(req, None, self.timeout)

    def _get_json(self, path, params):
        if self.apikey:
            params = dict(params or {})
            params["apikey"] = self.apikey
        qs = urlencode(params or {})
        url = "%s%s?%s" % (self.base, path, qs)
        req = Request(url)
        resp = self._open(req)
        data = resp.read()
        try:
            return json.loads(data.decode("utf-8"))
        except Exception:
            return {"raw": data.decode("utf-8", "ignore")}

    # ---------- core/info ----------
    def version(self):
        return self._get_json("/JSON/core/view/version/", {}).get("version")

    def access_url(self, url, follow=True):
        return self._get_json("/JSON/core/action/accessUrl/", {
            "url": url,
            "followRedirects": "true" if follow else "false",
        })

    # ---------- spider ----------
    def start_spider(self, url, maxChildren=0, recurse=False):
        res = self._get_json("/JSON/spider/action/scan/", {
            "url": url,
            "maxChildren": str(maxChildren),
            "recurse": "true" if recurse else "false",
        })
        return res.get("scan")

    def wait_spider(self, scan_id, sleep=1.0):
        while True:
            st = self._get_json("/JSON/spider/view/status/", {"scanId": str(scan_id)})
            if st.get("status") == "100":
                break
            time.sleep(sleep)

    # ---------- active scan ----------
    def start_ascan(self, url, recurse=False, method="", postData=""):
        res = self._get_json("/JSON/ascan/action/scan/", {
            "url": url,
            "recurse": "true" if recurse else "false",
            "method": method,
            "postData": postData,
        })
        sid = res.get("scan")
        if sid is None:
            raise ZapError("Cannot start scan: %r" % res)
        return sid

    def wait_ascan(self, scan_id, sleep=1.0):
        while True:
            st = self._get_json("/JSON/ascan/view/status/", {"scanId": str(scan_id)})
            if st.get("status") == "100":
                break
            time.sleep(sleep)

    # ---------- alerts ----------
    def alerts_for_url(self, url, start=0, count=9999):
        res = self._get_json("/JSON/alert/view/alerts/", {
            "url": url, "start": str(start), "count": str(count)
        })
        return res.get("alerts", [])
        
    def alerts_for_base(self, baseurl, start=0, count=9999):
        res = self._get_json("/JSON/core/view/alerts/", {
            "baseurl": baseurl, "start": str(start), "count": str(count)
        })
        return res.get("alerts", [])

    def get_message(self, messageId):
        try:
            res = self._get_json("/JSON/core/view/message/", {"id": str(messageId)})
            return res.get("message", {})
        except Exception:
            return {}

    # ---------- helpers ----------
    def active_scan_urls(self, urls, spider_first=False, recurse=False, limit=None, sleep=1.0):
        out = []
        uniq, seen = [], set()
        for u in urls:
            if u not in seen:
                uniq.append(u)
                seen.add(u)
        if limit:
            uniq = uniq[:limit]

        for i, u in enumerate(uniq, 1):
            print("[ZAP] (%d/%d) %s" % (i, len(uniq), u))
            try:
                self.access_url(u, follow=True)
                if spider_first:
                    sid = self.start_spider(u, recurse=True)
                    self.wait_spider(sid, sleep=sleep)
                sid = self.start_ascan(u, recurse=recurse)
                self.wait_ascan(sid, sleep=sleep)

                if recurse:
                    alerts = self.alerts_for_base(u)
                else:
                    alerts = self.alerts_for_url(u)

                print("   -> alerts found:", len(alerts))
                for a in alerts:
                    a["_scanned_url"] = u
                    try:
                        msg_id = a.get("messageId")
                        if msg_id:
                            msg_data = self.get_message(msg_id)
                            a["responseHeader"] = msg_data.get("responseHeader")
                    except Exception as e:
                        print("   ! could not fetch raw msg: %s" % e)
                    out.append(a)
            except Exception as e:
                print("   ! error:", e)
        return out

# ==========================================
# ฟังก์ชันสำหรับเริ่ม ZAP (subprocess)
# ==========================================
def start_zap_daemon():
    """
    รันคำสั่ง Shell เพื่อเปิด ZAP (รองรับ Python 2.7 / Jython)
    """
    cmd = [
        ZAP_PATH,
        "-daemon",
        "-port", ZAP_PORT,
        "-host", ZAP_HOST,
        "-config", "api.key={}".format(API_KEY),
        "-config", "api.addrs.addr.name=.*",
        "-config", "api.addrs.addr.regex=true"
    ]
    
    print("[*] Starting ZAP Daemon...")
    print("    Command: " + " ".join(cmd))
    
    try:
        # ใช้ DEVNULL ที่ประกาศไว้ข้างบน (รองรับทั้ง py2/py3)
        proc = subprocess.Popen(cmd, stdout=DEVNULL, stderr=DEVNULL)
        return proc
    except OSError as e: # ใช้ OSError แทน FileNotFoundError ใน Python 2
        print("[X] Error starting ZAP: {}".format(e))
        # ถ้าหาไฟล์ไม่เจอ ให้แจ้ง User
        if getattr(e, 'errno', None) == 2: # errno 2 = No such file or directory
             print("    Hint: Check if path '{}' is correct.".format(ZAP_PATH))
        raise

# ==========================================
# Main Execution
# ==========================================
if __name__ == "__main__":
    zap_process = None
    try:
        zap_process = start_zap_daemon()
        print("[*] Waiting 20 seconds for ZAP to boot...")
        time.sleep(20) 

        print("[*] Connecting to ZAP API...")
        client = ZapClient(
            base="http://127.0.0.1:{}".format(ZAP_PORT), 
            apikey=API_KEY
        )

        version = client.version()
        print("[+] Connected! ZAP Version: {}".format(version))

    except KeyboardInterrupt:
        print("\n[!] User aborted.")
    except Exception as e:
        print("\n[X] Error occured: {}".format(e))
    finally:
        if zap_process:
            print("[*] Shutting down ZAP...")
            try:
                zap_process.terminate()
                zap_process.wait()
            except:
                pass
            print("[*] ZAP Stopped.")
