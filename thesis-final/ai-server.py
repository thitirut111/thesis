import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel
from datasets import load_dataset
from tqdm import tqdm
import json
from fastapi import FastAPI
import os

BATCH_SIZE = 8

# 1. ตั้งค่าพื้นฐาน
base_model_name = "meta-llama/Llama-3.2-1B-Instruct"
adapter_model_path = "./final_model_llama_1b_v2" 
test_file = "befAI.jsonl"

SHARED_FOLDER = r"D:\myProject\eatraid\shared-thesis"
INPUT_FILE = os.path.join(SHARED_FOLDER, "befAI.jsonl")
OUTPUT_FILE = os.path.join(SHARED_FOLDER, "ai_result.json")

# fixed instruction
INSTRUCTION = (
    "Classify the following security alert as true positive (tp) "
    "or false positive (fp).\n"
    "Answer strictly in the following format:\n\n"
    "reason: <short explanation>\n"
    "label: <tp|fp>"
)

# โหลด Tokenizer
tokenizer = AutoTokenizer.from_pretrained(base_model_name, token=hf_token)
tokenizer.pad_token = tokenizer.eos_token

# ตั้งค่า Quantization (4-bit)
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.float16,
)

# โหลด Base Model
print("Loading Base Model...")
base_model = AutoModelForCausalLM.from_pretrained(
    base_model_name,
    quantization_config=bnb_config,
    token=hf_token,
    device_map="auto"
)

# โหลด Adapter (LoRA)
print("Loading Adapter...")
model = PeftModel.from_pretrained(base_model, adapter_model_path)
model.eval()
app = FastAPI()

@app.post("/run-job")
def run_job():
# โหลดข้อมูล Test
    test_dataset = load_dataset("json", data_files=INPUT_FILE, split="train")

   
    correct = 0
    total = 0
    results = []

    print(f"Starting evaluation...")

    for item in tqdm(test_dataset):
        raw_log = item["raw_input"]
        # ป้องกัน error กรณี label เป็น None

        # จัด Prompt
        prompt = f"user {INSTRUCTION}\n\n{raw_log} assistant reason: "
        
        inputs = tokenizer(prompt, return_tensors="pt").to("cuda")

        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=128,      
                repetition_penalty=1.2,  
                temperature=0.1,         
                do_sample=True,
                eos_token_id=tokenizer.eos_token_id,
                pad_token_id=tokenizer.eos_token_id
            )
        
        response = tokenizer.decode(outputs[0], skip_special_tokens=True)
        
        # --- ตัดเอาเฉพาะส่วนที่โมเดลตอบมาใหม่ (ตัด prompt ทิ้ง) ---
        # เราจะใช้ assistant_part เป็นหลักในการค้นหาคำตอบ
        if "assistant reason:" in response:
            # เอาส่วนที่อยู่หลัง 'assistant reason:' ทั้งหมด
            assistant_part = response.split("assistant reason:")[1].strip()
        else:
            # ถ้าไม่เจอ keyword ให้เอา text ทั้งหมด (เผื่อไว้) แต่เสี่ยง prompt leak
            assistant_part = response.replace(prompt, "").strip()

        # แปลงเป็นตัวเล็กเพื่อค้นหา
        search_text = assistant_part.lower()

        # --- ระบบดึงคำตอบ (Parsing Logic) V.Final ---
        pred_label = "unknown"
        
        # ค้นหาคำว่า label: fp หรือ label: tp ในส่วนที่โมเดลตอบเท่านั้น
        if "label: fp" in search_text:
            pred_label = "fp"
        elif "label: tp" in search_text:
            pred_label = "tp"
        
        # Fallback: ถ้ายังไม่เจอ ให้หาคำว่า false positive / true positive ตรงๆ
        if pred_label == "unknown":
            if "false positive" in search_text:
                pred_label = "fp"
            elif "true positive" in search_text:
                pred_label = "tp"

        # เก็บเหตุผล (Reasoning) - เอาประโยคแรกๆ ที่มันตอบ
        reasoning = assistant_part


        results.append({
            "predicted": pred_label,
            "reasoning": reasoning,
            "full_response": response # เก็บไว้ดู Debug
        })
    
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=4)
    
    print(f"Saved results to {OUTPUT_FILE}")

