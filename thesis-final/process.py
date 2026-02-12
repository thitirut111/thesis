import subprocess
import sys
import requests
import os
import time

windows_ip = "192.168.37.59"   # ใส่ IP Windows
API_URL = f"http://{windows_ip}:5000/run-job"

SHARED_FOLDER = "/mnt/shared"
AI_RESULT = os.path.join(SHARED_FOLDER, "ai_result.json")

# Clean old files
if os.path.exists(AI_RESULT):
    os.remove(AI_RESULT)

bef_file = os.path.join(SHARED_FOLDER, "befAI.jsonl")
if os.path.exists(bef_file):
    os.remove(bef_file)

print("🚀 Step 1: Convert")
subprocess.run([sys.executable, "auto-script-new.py"], check=True)

print("🚀 Step 2: Trigger Windows AI")

response = requests.post(API_URL)

if response.status_code != 200:
    raise Exception("Failed to trigger AI")

print("⏳ Waiting for ai_result.json...")

while not os.path.exists(AI_RESULT):
    time.sleep(2)

print("🚀 Step 3: Merge")
subprocess.run([sys.executable, "merge-output-label.py"], check=True)

print("🎉 Pipeline completed successfully!")
