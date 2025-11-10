#!/usr/bin/env python3
# convert_dataset.py
# แปลง ZAP export JSON (เช่นมี key "zap_alerts") -> dataset.jsonl (หนึ่งบรรทัด = 1 record)

import json
import argparse
import os
from typing import Any, Dict, List

def first_nonempty(*values) -> str:
    for v in values:
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""

def normalize_line(text: str, fallback: str = "(none)") -> str:
    if text is None:
        return fallback
    s = str(text).strip()
    return s if s else fallback

def coerce_alerts(obj: Any) -> List[Dict[str, Any]]:
    """
    รองรับรูปแบบ:
    - {"zap_alerts": [ {...}, {...} ]}
    - {"alerts": [ ... ]}
    - [ {...}, {...} ]
    - {"something": [ ... ]}  (จะหยิบ value อันแรกที่เป็น list)
    """
    if isinstance(obj, list):
        return obj

    if isinstance(obj, dict):
        for key in ("zap_alerts", "alerts", "site", "items"):
            if key in obj and isinstance(obj[key], list):
                return obj[key]
        # เผื่อกรณีลิสต์อยู่ใน value อันแรก
        for v in obj.values():
            if isinstance(v, list):
                return v

    raise ValueError("ไม่พบลิสต์ของ alerts ในไฟล์ JSON (ควรมี key: zap_alerts / alerts / site / items)")

def to_dataset_record(a: Dict[str, Any]) -> Dict[str, str]:
    alert_name = first_nonempty(a.get("alert"), a.get("name"), a.get("pluginId"))
    url        = first_nonempty(a.get("url"), a.get("_scanned_url"))
    evidence   = first_nonempty(a.get("evidence"), a.get("attack"), a.get("param"))

    # Observed เอา other > description > solution
    observed   = first_nonempty(a.get("other"), a.get("description"), a.get("solution"))
    header = normalize_line(a.get("responseHeader"), fallback="(no header data)")

    input_block = (
        f"Alert: {normalize_line(alert_name, '(unspecified)')} on {normalize_line(url, '(unknown URL)')}\n"
        f"Evidence: {normalize_line(evidence)}\n"
        f"Observed: {normalize_line(observed)}"
        f"Response Header: {header}\n"
    )

    return {
        "instruction": "Classify and explain if the alert is false positive.",
        "input": input_block,
        "output": ""  # ยังไม่ใส่ gold label
    }

def main():
    parser = argparse.ArgumentParser(description="Convert ZAP JSON to dataset.jsonl")
    parser.add_argument("--input", "-i", dest="in_path", required=True,
                        help="พาธไฟล์ ZAP JSON เช่น alert_20251006_031721.json")
    parser.add_argument("--output", "-o", dest="out_path", default="dataset.jsonl",
                        help="พาธไฟล์ JSONL ที่จะเขียน (ค่าเริ่มต้น: dataset.jsonl)")
    args = parser.parse_args()

    in_path = os.path.expanduser(args.in_path)
    out_path = os.path.expanduser(args.out_path)

    if not os.path.isfile(in_path):
        raise FileNotFoundError(f"ไม่พบไฟล์อินพุต: {in_path}")

    with open(in_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    alerts = coerce_alerts(data)
    if not alerts:
        raise ValueError("ไม่พบ alert รายการใดในไฟล์")

    if not isinstance(alerts[0], dict):
        raise ValueError("รายการ alert ไม่ใช่ object (dict); กรุณาตรวจสอบโครงสร้าง JSON")

    count = 0
    with open(out_path, "w", encoding="utf-8") as out:
        for a in alerts:
            try:
                rec = to_dataset_record(a)
                out.write(json.dumps(rec, ensure_ascii=False) + "\n")
                count += 1
            except Exception:
                # ข้ามเรคคอร์ดที่เสีย แล้วยิงต่อ
                continue

    print(f"✅ เขียน {count} บรรทัดไปที่ {out_path}")

if __name__ == "__main__":
    main()
