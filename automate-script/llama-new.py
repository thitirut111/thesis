import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel
from datasets import load_dataset
from tqdm import tqdm
import json

# =========================
# CONFIG
# =========================
BASE_MODEL = "meta-llama/Llama-3.2-1B-Instruct"
ADAPTER_PATH = "./final_model_llama_1b_v2"
INPUT_JSONL = "output-new.jsonl"          # ไฟล์ที่ reason/label ยังว่าง
OUTPUT_JSONL = "output_labeled.jsonl" # ไฟล์ผลลัพธ์

INSTRUCTION = (
    "Classify the following security alert as true positive (tp) "
    "or false positive (fp).\n"
    "Answer strictly in the following format:\n\n"
    "reason: <short explanation>\n"
    "label: <tp|fp>"
)

# =========================
# LOAD MODEL
# =========================
tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
tokenizer.pad_token = tokenizer.eos_token

bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.float16,
)

print("Loading base model...")
base_model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    quantization_config=bnb_config,
    device_map="auto"
)

print("Loading LoRA adapter...")
model = PeftModel.from_pretrained(base_model, ADAPTER_PATH)
model.eval()

# =========================
# LOAD DATA
# =========================
dataset = load_dataset("json", data_files=INPUT_JSONL, split="train")

# =========================
# HELPER: parse model output
# =========================
def parse_response(text: str):
    text_l = text.lower()
    label = "unknown"

    if "label: fp" in text_l:
        label = "fp"
    elif "label: tp" in text_l:
        label = "tp"
    elif "false positive" in text_l:
        label = "fp"
    elif "true positive" in text_l:
        label = "tp"

    return label, text.strip()

# =========================
# MAIN INFERENCE LOOP
# =========================
results = []

print("Running inference...")

for item in tqdm(dataset):
    raw_input = item["raw_input"]

    prompt = f"user {INSTRUCTION}\n\n{raw_input} assistant reason: "
    inputs = tokenizer(prompt, return_tensors="pt").to("cuda")

    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=128,
            temperature=0.1,
            do_sample=True,
            eos_token_id=tokenizer.eos_token_id,
            pad_token_id=tokenizer.eos_token_id
        )

    decoded = tokenizer.decode(outputs[0], skip_special_tokens=True)

    if "assistant reason:" in decoded:
        assistant_part = decoded.split("assistant reason:")[1].strip()
    else:
        assistant_part = decoded.replace(prompt, "").strip()

    label, reason = parse_response(assistant_part)

    # update record
    item["label"] = label
    item["reason"] = reason

    results.append(item)

# =========================
# WRITE OUTPUT
# =========================
with open(OUTPUT_JSONL, "w", encoding="utf-8") as f:
    for r in results:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

print(f"✅ Done! Saved to {OUTPUT_JSONL}")
