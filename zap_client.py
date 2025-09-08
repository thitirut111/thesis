# zap_scan.py
import sys, time, json, re
import requests

ZAP = "http://127.0.0.1:8088"
API_KEY = "u4cn99cd9j4g323m62gi7dkopm"

SLEEP = 1.0  # วินาที ระหว่างเช็คสถานะ

def zap_json(path, **params):
    if API_KEY: params["apikey"] = API_KEY
    r = requests.get(f"{ZAP}{path}", params=params, timeout=60)
    r.raise_for_status()
    return r.json()

def zap_other(path, **params):
    if API_KEY: params["apikey"] = API_KEY
    r = requests.get(f"{ZAP}{path}", params=params, timeout=120)
    r.raise_for_status()
    return r.content

def start_spider(url):
    # ถ้าอยากให้ ZAP เก็บลิงก์ก่อน (optional)
    res = zap_json("/JSON/spider/action/scan/", url=url, maxChildren=0, recurse=False)
    return res.get("scan")

def wait_spider_done(scan_id):
    while True:
        st = zap_json("/JSON/spider/view/status/", scanId=scan_id)
        if st.get("status") == "100":
            break
        time.sleep(SLEEP)

def start_active_scan(url):
    # scan เฉพาะ URL นี้ (ไม่ไล่ลิงก์)
    res = zap_json("/JSON/ascan/action/scan/", url=url, recurse=False, method="", postData="")
    sid = res.get("scan")
    if sid is None:
        raise RuntimeError(f"Cannot start active scan for {url}: {res}")
    return sid

def wait_active_done(scan_id):
    while True:
        st = zap_json("/JSON/ascan/view/status/", scanId=scan_id)
        if st.get("status") == "100":
            break
        time.sleep(SLEEP)

def fetch_alerts_for(url):
    # ดึงเฉพาะ alerts ของ URL นี้
    out = []
    start = 0
    page = 999
    while True:
        chunk = zap_json("/JSON/alert/view/alerts/", url=url, start=start, count=page).get("alerts", [])
        if not chunk:
            break
        out.extend(chunk)
        if len(chunk) < page:
            break
        start += page
    return out

def normalize_urls_from_stdin():
    url_re = re.compile(r'https?://[^\s"<>]+')
    urls = []
    for line in sys.stdin:
        urls.extend(url_re.findall(line))
    # unique โดยรักษาลำดับ
    seen = set(); uniq = []
    for u in urls:
        if u not in seen:
            seen.add(u); uniq.append(u)
    return uniq

def main():
    # โหมดรับ URL
    urls = sys.argv[1:] if len(sys.argv) > 1 else normalize_urls_from_stdin()
    if not urls:
        print("Usage:\n  python zap_scan.py <url1> <url2> ...\n  OR:\n  type urls.txt | python zap_scan.py\n")
        sys.exit(1)

    all_alerts = []
    for u in urls:
        try:
            print(f"[+] TARGET: {u}")

            # (ถ้าต้อง spider ก่อน ให้ uncomment 2 บรรทัดนี้)
            # spid = start_spider(u); wait_spider_done(spid)

            asid = start_active_scan(u)
            wait_active_done(asid)
            alerts = fetch_alerts_for(u)
            print(f"    -> done, alerts={len(alerts)}")

            for a in alerts:
                a["_scanned_url"] = u
            all_alerts.extend(alerts)
        except Exception as e:
            print(f"[!] error on {u}: {e}")

    with open("alerts.json", "w", encoding="utf-8") as f:
        json.dump(all_alerts, f, ensure_ascii=False, indent=2)
    print("[+] saved: alerts.json")

    # (ถ้าต้องการ HTML report รวมโปรเจกต์ทั้งหมด)
    # html = zap_other("/OTHER/core/other/htmlreport/")
    # open("zap_report.html","wb").write(html)
    # print("[+] saved: zap_report.html")

if __name__ == "__main__":
    main()
