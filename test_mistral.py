import torch
import json
import pandas as pd
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
from peft import PeftModel

# 1. ตั้งค่า Path (เช็คให้ตรงกับเครื่องคุณนะ)
base_model_path = "mistralai/Mistral-7B-Instruct-v0.3"
adapter_path = r"C:\Users\Dhinotea\mistal_train\mistral-finetuned-thesis" 
test_file = r"C:\Users\Dhinotea\Downloads\thesis\test.jsonl"

# 2. โหลด Tokenizer และ Model (ใช้ 4-bit เพื่อความเร็ว)
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.float16,
)

tokenizer = AutoTokenizer.from_pretrained(base_model_path)
tokenizer.pad_token = tokenizer.eos_token

base_model = AutoModelForCausalLM.from_pretrained(
    base_model_path,
    quantization_config=bnb_config,
    device_map="auto"
)

# โหลด "สมอง" ส่วนที่คุณเทรนมาสวมทับ
model = PeftModel.from_pretrained(base_model, adapter_path)
model.eval() 

print("✅ Loaded Fine-tuned Model Successfully!")

# 3. อ่านไฟล์ Test และให้ AI ตอบ
results = []
with open(test_file, 'r', encoding='utf-8') as f:
    for line in f:
        data = json.loads(line)
        prompt = data['raw_input']
        ground_truth = data.get('label', 'N/A')
        reason_truth = data.get('reason', 'N/A')

        # จัดการส่งเข้า AI
        inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=512).to("cuda")
        
        with torch.no_grad():
            outputs = model.generate(
                **inputs, 
                max_new_tokens=100, # ให้ AI ตอบไม่เกิน 100 คำ
                temperature=0.1     # ตั้งค่าน้อยๆ เพื่อให้คำตอบเสถียร ไม่มั่ว
            )
        
        # ตัดเอาเฉพาะส่วนที่ AI ตอบออกมา
        answer = tokenizer.decode(outputs[0], skip_special_tokens=True)
        # (Optional) ตัดส่วนที่เป็นโจทย์ออก เหลือแค่คำตอบ
        ai_response_only = answer.replace(prompt, "").strip()

        results.append({
            "Input": prompt,
            "Ground_Truth_Label": ground_truth,
            "Ground_Truth_Reason": reason_truth,
            "AI_Prediction": ai_response_only
        })
        print(f"Processed: {len(results)}")

# 4. บันทึกผลลง CSV เอาไปเปิดใน Excel
df = pd.DataFrame(results)
df.to_csv("my_thesis_test_results.csv", index=False, encoding='utf-8-sig')
print("🏁 Done! ผลลัพธ์อยู่ในไฟล์ my_thesis_test_results.csv แล้วครับ")