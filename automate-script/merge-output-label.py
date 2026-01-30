import json

INPUT_JSON = r"E:\thesis\automate-script\input.json"
LLAMA_RESULTS_JSON = r"E:\thesis\automate-script\ai_result.json"
OUTPUT_JSON = r"E:\thesis\automate-script\final.json"

# โหลด input.json
with open(INPUT_JSON, "r", encoding="utf-8") as f:
    data = json.load(f)

alerts = data["zap_alerts"]

# โหลดผล llama (JSON array)
with open(LLAMA_RESULTS_JSON, "r", encoding="utf-8") as f:
    results = json.load(f)

if len(alerts) != len(results):
    raise ValueError(
        f"❌ จำนวน alerts ({len(alerts)}) ไม่เท่ากับผล llama ({len(results)})"
    )

# merge ตาม index
for alert, res in zip(alerts, results):
    alert["aiLabel"] = res.get("predicted", "unknown")
    alert["aiReason"] = res.get("reasoning", "")

# เขียนออกเป็น JSON (format เดิม)
with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, indent=4)

print(f"✅ Merge completed → {OUTPUT_JSON}")
