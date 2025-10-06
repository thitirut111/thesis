# -*- coding: utf-8 -*-
# zap_client.py
from __future__ import print_function
import json, time

try:
    from urllib.parse import urlencode
    from urllib.request import urlopen, Request, build_opener, ProxyHandler
except ImportError:
    from urllib import urlencode
    from urllib2 import urlopen, Request, build_opener, ProxyHandler

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
            params = dict(params or {}); params["apikey"] = self.apikey
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
        # ดึง alert ทั้ง tree ของ base URL
        res = self._get_json("/JSON/core/view/alerts/", {
            "baseurl": baseurl, "start": str(start), "count": str(count)
        })
        return res.get("alerts", [])

    # ---------- helpers ----------
    def active_scan_urls(self, urls, spider_first=False, recurse=False, limit=None, sleep=1.0):
        """สแกนทีละ URL; ถ้า recurse=True จะดึงผลด้วย alerts_for_base"""
        out = []
        uniq, seen = [], set()
        for u in urls:
            if u not in seen:
                uniq.append(u); seen.add(u)
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

                # ถ้า recurse → ดึงผลทั้ง base tree; ถ้าไม่ → ดึงเฉพาะ URL
                if recurse:
                    alerts = self.alerts_for_base(u)
                else:
                    alerts = self.alerts_for_url(u)

                for a in alerts:
                    a["_scanned_url"] = u
                print("   -> alerts:", len(alerts))
                out.extend(alerts)
            except Exception as e:
                print("   ! error:", e)
        return out
