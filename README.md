# 🔓 WifiMeNow - Automated WPA2 Handshake Capture & Cracking Tool

> 🚨 **Unlock the power of automation in wireless penetration testing.** WifiMeNow hunts, captures, and cracks WPA2 handshakes with minimal input and maximum efficiency. Just plug in your wireless adapter, run the script, and let it do the dirty work.

---

## ✨ Features

- 🔍 **Auto Network Discovery** – Continuously scans for nearby WiFi networks.
- ⚡ **Auto Handshake Capture** – Targets networks, performs deauth attacks, and listens for WPA2 handshakes.
- 🧠 **Smart Filtering** – Skips previously processed BSSIDs and weak signals.
- 🔐 **Auto Crack WPA2** – Uses `aircrack-ng` with `rockyou.txt` to brute-force handshakes.
- 📂 **Save Results** – Captures and passwords are stored with timestamps.
- 🧪 **Multithreaded Attacks** – Attack multiple networks concurrently.
- 💻 **Minimal Setup** – All handled via CLI. No GUI nonsense.

---

## 📁 Included Scripts

### `WifiMeNow.py`
Main interactive version that runs on demand and targets nearby WPA2 WiFi networks based on signal strength.

### `WifiMeNowAuto.py`
An automated variant for fully hands-off operation – suitable for persistent wardriving sessions or testing.

---

## 🛠️ Requirements

Make sure you have the following tools installed:

- `aircrack-ng` suite (`airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng`)
- `iwconfig`
- Python 3
- External WiFi adapter that supports monitor mode and packet injection
- `rockyou.txt` wordlist (default path: `/usr/share/wordlists/rockyou.txt`)

---

## 🚀 Usage

Run as root with a supported wireless interface:

```bash
sudo python3 WifiMeNow.py 
# or
sudo python3 WifiMeNowAuto.py <interface>
