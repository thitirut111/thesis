import json
import subprocess
import sys

# Step 1: convert input.json → output-new.jsonl
print("🚀 Step 1: Converting input.json → output-new.jsonl")
subprocess.run([sys.executable, r"E:\thesis\automate-script\auto-script-new.py"], check=True)

# Step 2: run llama inference
print("🚀 Step 2: Running llama2.py")
subprocess.run([sys.executable, r"E:\thesis\automate-script\llama2.py"], check=True)

# Step 3: merge label/reason back to input.json
print("🚀 Step 3: Merging results back to JSON")
subprocess.run([sys.executable, r"E:\thesis\automate-script\merge-output-label.py"], check=True)

print("✅ Pipeline completed successfully!")
