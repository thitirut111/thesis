import json

INSTRUCTION_TEXT = "Classify and explain if the alert is false positive."

def build_raw_input(alert: dict) -> str:
    parts = [
        f"Alert: {alert.get('alert', '')}",
        f"Severity: {alert.get('risk', '')}, Status: {alert.get('confidence', '')}",
        f"Evidence: {alert.get('evidence', '')}",
        f"Attack vector: {alert.get('attack', '')}",
        f"Details: {alert.get('other', '')}",
        f"Impact: {alert.get('description', '')}",
        f"Response Header: {alert.get('responseHeader', '')}",
    ]
    return "\n".join(parts)

def convert_input_to_jsonl(input_json_path: str, output_jsonl_path: str):
    with open(input_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # รองรับทั้งแบบ dict ที่มี zap_alerts และ list ตรง ๆ
    if isinstance(data, dict) and "zap_alerts" in data:
        alerts = data["zap_alerts"]
    elif isinstance(data, list):
        alerts = data
    else:
        raise ValueError("Unsupported input.json format")

    with open(output_jsonl_path, "w", encoding="utf-8") as out:
        for alert in alerts:
            record = {
                "instruction": INSTRUCTION_TEXT,
                "raw_input": build_raw_input(alert),
                "reason": "",
                "label": ""
            }
            out.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(f"✅ Converted {len(alerts)} alerts → {output_jsonl_path}")

# -----------------------------
# Example usage
# -----------------------------
if __name__ == "__main__":
    convert_input_to_jsonl(
        input_json_path=r"E:\thesis\automate-script\input.json",
        output_jsonl_path=r"E:\thesis\automate-script\befAI.jsonl"
    )
