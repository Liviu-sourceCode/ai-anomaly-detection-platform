"""
This script automates a network scan using Nmap. It scans the target IP for open ports, service versions, and OS detection, and prints the results. For security testing and simulation purposes only.
"""
import subprocess

def run_nmap_scan(target_ip):
    nmap_command = ["nmap", "-sV", "-A", target_ip]
    try:
        result = subprocess.run(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            print(f"Nmap Scan Results for IP: {target_ip}")
            print(result.stdout)
        else:
            print(f"Error occurred while running Nmap scan: {result.stderr}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    target_ip = "192.168.56.101"
    run_nmap_scan(target_ip)
