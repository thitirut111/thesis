import json

with open("/mnt/shared/input.json", "r", encoding="utf-8") as f:
    data = json.load(f)

# รองรับทั้ง dict และ list
if isinstance(data, dict) and "zap_alerts" in data:
    alerts = data["zap_alerts"]
elif isinstance(data, list):
    alerts = data
else:
    raise ValueError("Unsupported input.json format")

with open("/mnt/shared/ai_result.json", "r", encoding="utf-8") as f:
    results = json.load(f)

for alert, result in zip(alerts, results):
    alert["predicted_label"] = result["predicted"]
    alert["reasoning"] = result["reasoning"]

with open("/mnt/shared/final.json", "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

print("✅ Merge complete")
