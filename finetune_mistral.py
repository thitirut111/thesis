import torch
import json
from datasets import load_dataset
from transformers import (
    AutoTokenizer, 
    AutoModelForCausalLM, 
    Trainer, 
    TrainingArguments, 
    BitsAndBytesConfig
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training

# 1. ตั้งค่าพื้นฐาน
model_name = "mistralai/Mistral-7B-Instruct-v0.3"

# 2. ตั้งค่าการโหลดโมเดลแบบ 4-bit (Quantization)
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_use_double_quant=True,
    bnb_4bit_compute_dtype=torch.float16,
)

# 3. โหลด Tokenizer
tokenizer = AutoTokenizer.from_pretrained(
    model_name,
    trust_remote_code=True,
    use_fast=False
)
# ตั้งค่า Pad Token (สำคัญมากสำหรับ Mistral)
tokenizer.pad_token = tokenizer.eos_token
tokenizer.padding_side = "right" 

# 4. โหลดโมเดล
model = AutoModelForCausalLM.from_pretrained(
    model_name,
    quantization_config=bnb_config,
    device_map="auto",
    trust_remote_code=True
)

# 5. เตรียมโมเดลสำหรับ Low-Bit Training (QLoRA)
model.config.use_cache = False # ปิด cache ระหว่าง train เพื่อลดหน่วยความจำ
model.config.pad_token_id = tokenizer.eos_token_id
model = prepare_model_for_kbit_training(model)

# ตั้งค่า LoRA Config
peft_config = LoraConfig(
    r=16,
    lora_alpha=32,
    target_modules=["q_proj", "v_proj", "k_proj", "o_proj"], # โมดูลหลักของ Mistral
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM"
)
model = get_peft_model(model, peft_config)

print("✅ Model & Tokenizer loaded with QLoRA successfully")

# 6. โหลดข้อมูลจากไฟล์ JSONL
# ตรวจสอบว่ามีไฟล์ตาม Path นี้จริงๆ
train_file = r"C:\Users\Dhinotea\Downloads\thesis\train.jsonl"
test_file = r"C:\Users\Dhinotea\Downloads\thesis\test.jsonl"
valid_file = r"C:\Users\Dhinotea\Downloads\thesis\val.jsonl"

dataset = load_dataset('json', data_files={
    'train': train_file,
    'test': test_file,
    'validation': valid_file
})

# 7. ฟังก์ชันสำหรับ Tokenize ข้อมูล
# หมายเหตุ: ในไฟล์ JSONL ของคุณต้องมี Column ชื่อ 'raw_input'
def tokenize_function(examples):
    outputs = tokenizer(
        examples['raw_input'], 
        padding="max_length", 
        truncation=True, 
        max_length=512 # ปรับตามความเหมาะสมของข้อมูลคุณ
    )
    outputs["labels"] = outputs["input_ids"].copy() # สำหรับ Causal LM labels คือ input_ids
    return outputs

tokenized_datasets = dataset.map(tokenize_function, batched=True, remove_columns=dataset["train"].column_names)

# 8. ตั้งค่าการฝึก (Training Arguments)
training_args = TrainingArguments(
    output_dir='./results',
    eval_strategy="epoch",
    logging_dir='./logs',
    logging_steps=10,
    save_strategy="epoch",
    save_total_limit=2,
    per_device_train_batch_size=2, # ถ้า VRAM เหลือให้ปรับเป็น 4
    per_device_eval_batch_size=2,
    num_train_epochs=3,
    weight_decay=0.01,
    fp16=True, # ใช้ความแม่นยำต่ำเพื่อประหยัด VRAM
    learning_rate=1e-4,
    optim="paged_adamw_32bit", # Optimizer ที่แนะนำสำหรับ QLoRA
    report_to="none" # ปิดการส่งข้อมูลไป wandb/tensorboard ถ้าไม่ได้ตั้งค่าไว้
)

# 9. สร้าง Trainer และเริ่ม Train
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=tokenized_datasets['train'],
    eval_dataset=tokenized_datasets['validation'],
    tokenizer=tokenizer,
)

print("🚀 Starting training...")
trainer.train()

# 10. บันทึกโมเดลที่ Train เสร็จแล้ว
model.save_pretrained("./mistral-finetuned-thesis")
tokenizer.save_pretrained("./mistral-finetuned-thesis")

# 11. ประเมินผลด้วยข้อมูล Test
print("📊 Evaluating on test set...")
trainer.evaluate(tokenized_datasets['test'])
