import subprocess
import json

target = "example.com"
subdomains_file_json = "/home/kali/Desktop/project/subfinder_output.json"

print(f"[+] Running subfinder on {target}")

# รัน subfinder และเก็บ stdout
result = subprocess.run([
    "subfinder",
    "-d", target,
    "-json"  # output เป็น JSON line-delimited บน stdout
], capture_output=True, text=True)

# เขียน stdout ลงไฟล์
with open(subdomains_file_json, "w") as f:
    f.write(result.stdout)
