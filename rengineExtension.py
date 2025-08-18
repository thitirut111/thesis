# -*- coding: utf-8 -*-
import sys
import requests
from bs4 import BeautifulSoup
import json

def main():
    session, csrf_token, target_url = login()
    if session:
        add_target(session, csrf_token, target_url)

def login():
    if len(sys.argv) != 2:
        print("Usage: python rengine_api_runner.py <target_url>")
        return None, None, None

    target_url = sys.argv[1]
    s = requests.Session()

    login_page = s.get("http://localhost:8000/login/")
    if login_page.status_code != 200:
        print(f"❌ Failed to load login page. Status: {login_page.status_code}")
        return None, None, None

    csrf_token = s.cookies.get("csrftoken")
    if not csrf_token:
        soup = BeautifulSoup(login_page.text, "html.parser")
        csrf_input = soup.find("input", {"name": "csrfmiddlewaretoken"})
        csrf_token = csrf_input["value"] if csrf_input else None

    if not csrf_token:
        print("❌ Failed to retrieve CSRF token.")
        return None, None, None

    login_data = {
        "username": "kalii",
        "password": "kali",
        "csrfmiddlewaretoken": csrf_token,
    }

    headers = {
        "Referer": "http://localhost:8000/login/",
        "X-CSRFToken": csrf_token,
    }

    login_res = s.post("http://localhost:8000/login/", data=login_data, headers=headers)

    if login_res.status_code not in [200, 302]:
        print(f"❌ Login failed. Status: {login_res.status_code}")
        return None, None, None

    # ✅ ดึง CSRF ใหม่หลัง login สำเร็จ
    csrf_token = s.cookies.get("csrftoken")
    if not csrf_token:
        print("❌ Failed to retrieve CSRF token after login.")
        return None, None, None

    print("✅ Login successful!")
    print("🔎 Final CSRF Token:", csrf_token)
    print("🍪 Session Cookies:", s.cookies.get_dict())
    return s, csrf_token, target_url


def add_target(session, csrf_token, target_url):
    api_url = "http://localhost:8000/api/add/target/"
    headers = {
        "X-CSRFToken": csrf_token,
        "Content-Type": "application/json",
        "Referer": "http://localhost:8000/targets/"
    }

    payload = {
        "name": target_url,
        "description": "Added via API runner",
        "engine": 1  # ปกติ engine id = 1 หมายถึง default engine (เช็คได้จาก UI)
    }

    response = session.post(api_url, headers=headers, data=json.dumps(payload), cookies=session.cookies)

    if response.status_code == 200:
        print(f"✅ Target '{target_url}' added successfully.")
        print("Response:", response.text)
    else:
        print(f"❌ Failed to add target. Status: {response.status_code}")
        print("Response:", response.text)

if __name__ == "__main__":
    main()
