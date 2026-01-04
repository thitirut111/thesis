import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig

# เปลี่ยนชื่อโมเดลจาก Mistral-7B เป็น Mistral-7B-Instruct-v0.3
model_name = "mistralai/Mistral-7B-Instruct-v0.3"

# ตั้งค่า BitsAndBytesConfig สำหรับ 4-bit
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_use_double_quant=True,
    bnb_4bit_compute_dtype=torch.float16,
)

# โหลด Tokenizer
tokenizer = AutoTokenizer.from_pretrained(
    model_name,
    trust_remote_code=True,
    use_fast=False
)

# โหลดโมเดล Mistral 7B Instruct v0.3 ด้วยการตั้งค่า 4-bit
model = AutoModelForCausalLM.from_pretrained(
    model_name,
    quantization_config=bnb_config,
    device_map="auto",  # ใช้ device map เพื่อให้สามารถใช้ GPU หรือ CPU ที่เหมาะสม
    trust_remote_code=True
)

print("Mistral-7B Instruct v0.3 Model loaded in 4-bit successfully (stable Windows setup)")
