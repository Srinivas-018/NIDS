Since you are looking for a clean, professional version to copy directly into a document or a GitHub README "Canvas," I’ve framed this to be more "human-centric"—focusing on the story of the project, the logic behind the code, and clear user guidance.

***

# 🛡️ Project: Sentinel NIDS
### *A Lightweight Python-Based Network Security Monitor*

Welcome to **Sentinel**, a custom-built Network Intrusion Detection System. This project was developed to bridge the gap between complex enterprise security tools and accessible, script-based network monitoring. Using the power of **Python** and **Scapy**, Sentinel watches your traffic in real-time to catch threats before they escalate.

---

## 🌟 Why This Project?
Most modern IDS tools are "black boxes" that are hard to configure. Sentinel is built for transparency. It provides a readable, rule-based approach to security, allowing you to see exactly *why* a packet was flagged. Whether you're a student learning network security or a developer securing a lab, Sentinel provides the visibility you need.

## 🛠️ Core Capabilities
Sentinel doesn't just sniff packets; it analyzes behavior:
*   **Port Scan Guard:** Detects reconnaissance attempts when an IP hits 10+ unique ports in under a second.
*   **SYN Flood Defense:** Identifies DoS patterns by measuring the ratio of connection requests (SYN) to acknowledgments (ACK).
*   **ARP Integrity:** Protects against Man-in-the-Middle attacks by tracking IP-to-MAC address consistency.
*   **Hybrid Storage:** Logs alerts to `alerts.csv` for quick viewing and `alerts.db` for long-term data analysis.

---

## 🚀 Getting Started

### 1. Prerequisites
Before running the engine, ensure your environment is ready:
*   **Python 3.10+**
*   **Npcap (Windows):** Essential for packet capture. [Download here](https://npcap.com/).
*   **Admin Rights:** Packet sniffing requires elevated permissions on most OSs.

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/Srinivas-018/NIDS_.git
cd NIDS_

# Install the dependencies
pip install -r requirements.txt
```

### 3. Running the System
You can choose between a CLI-heavy approach or a clean Desktop UI.

**Option A: The Dashboard (User Friendly)**
```bash
python ui.py
```
*Use the "Run Test Traffic" button inside the UI to see the system in action instantly.*

**Option B: The Engine (Power User)**
```bash
# Live monitoring on a specific interface
python nids.py --iface "Wi-Fi" --profile balanced

# Analyzing a saved capture file
python nids.py --pcap sample.pcap --replay-timing
```

---

## 📈 Sensitivity Profiles
We've pre-configured "Rules of Engagement" to minimize noise:
--------------------------------------------------------------------------------
|    Profile    |                         Best For...                          |
|---------------|--------------------------------------------------------------|
| **Balanced**  | Standard monitoring with low false-positives.                |
| **Sensitive** | Lab environments where you want to catch every tiny anomaly. |
| **Strict**    | Busy networks where you only care about major attacks.       |
--------------------------------------------------------------------------------
---

## 🧪 The Simulation Lab
To prove the system works, use our built-in `traffic_generator.py`. This allows you to simulate "attacks" against your own machine safely.

```bash
# Simulate a Port Scan
python traffic_generator.py --mode portscan --target-ip 127.0.0.1

# Simulate a SYN Flood
python traffic_generator.py --mode synflood --target-ip 127.0.0.1

# Run the full gauntlet
python traffic_generator.py --mode all --target-ip 127.0.0.1
```

---

## 🔒 Safety & Disclaimer
This tool is for **educational and lab use only**. While Sentinel is powerful, it should not replace professional-grade firewalls in a production environment. Always ensure you have permission to monitor the network you are connected to.

**Developed with ❤️ by [Srinivas](https://github.com/Srinivas-018)**
