import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
from huggingface_hub import login
from dotenv import load_dotenv

load_dotenv()

hf_token = os.getenv("hf_token")

login(token=hf_token)

model_name = "meta-llama/Llama-3.2-1B-Instruct"

bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_use_double_quant=True,
    bnb_4bit_compute_dtype=torch.float16,
)

tokenizer = AutoTokenizer.from_pretrained(
    model_name,
    token=hf_token,
    trust_remote_code=True
)
tokenizer.pad_token = tokenizer.eos_token

model = AutoModelForCausalLM.from_pretrained(
    model_name,
    quantization_config=bnb_config,
    device_map="auto",
    token=hf_token, 
    trust_remote_code=True
)

print(f"Llama-1B-Instruct loaded with Auth Token successfully!")
print(f"VRAM Used: {model.get_memory_footprint() / 1e6:.2f} MB")