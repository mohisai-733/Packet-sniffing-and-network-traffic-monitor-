<div align="center">

# 🛡️ Sentinel Analytica
### Advanced Real-Time Packet Sniffing, Threat Intelligence & Network Forensics Platform

🌐 **Live Hosted Platform:** [https://sentinel-analytica.onrender.com/](https://sentinel-analytica.onrender.com/)

[![Live Deployment](https://img.shields.io/badge/Live_Website-sentinel--analytica.onrender.com-00f2ff?style=for-the-badge&logo=render&logoColor=white)](https://sentinel-analytica.onrender.com/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Scapy](https://img.shields.io/badge/Capture-Scapy%20%2F%20TShark-FF6B6B?style=for-the-badge&logo=wireshark&logoColor=white)](https://scapy.net)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://reactjs.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

<p align="center">
  <b>Sentinel Analytica</b> is an enterprise-grade cybersecurity network monitoring platform that bridges live physical hardware packet captures (Wi-Fi, Ethernet, Loopback, VPN) to a reactive, high-performance web dashboard over encrypted WebSocket streams.
</p>

### 🚀 **[👉 Access Live Platform: https://sentinel-analytica.onrender.com/ 👈](https://sentinel-analytica.onrender.com/)**

[Live Dashboard](https://sentinel-analytica.onrender.com/) • [Hardware Agent](#-sentinel-local-hardware-agent) • [Architecture](#-target-architecture) • [API Reference](#-api-endpoints) • [Security & Privacy](#-security--privacy-framework)

---

</div>

## 📑 Table of Contents
- [Target Architecture](#-target-architecture)
- [Core Capabilities](#-core-capabilities)
- [Platform Modules](#-platform-modules)
- [Sentinel Local Hardware Agent](#-sentinel-local-hardware-agent)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Local Installation](#local-installation)
  - [Connecting Your Local Network Hardware](#connecting-your-local-network-hardware)
- [Conservative Threat Detection Engine](#-conservative-threat-detection-engine)
- [PCAP Deep Forensics Analyzer](#-pcap-deep-forensics-analyzer)
- [AI Copilot Telemetry Audit](#-ai-copilot-telemetry-audit)
- [API & WebSocket Reference](#-api--websocket-reference)
- [Security & Privacy Framework](#-security--privacy-framework)
- [License & Disclaimer](#-license--disclaimer)

---

## 🏗️ Target Architecture

```
                  USER AUTHORIZED COMPUTER
                             │
                             ▼
                    Wi-Fi / Ethernet NIC
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Sentinel Local Agent│
                  │   Python / Scapy    │
                  │   TShark / Npcap    │
                  │  Packet Normalizer  │
                  └──────────┬──────────┘
                             │
                      Real-time packet stream
                      (TLS/WSS JSON Events)
                             │
                             ▼
                  ┌─────────────────────┐
                  │  Sentinel Backend   │
                  │  Session Tracking   │
                  │  Protocol Analysis  │
                  │  Threat Detection   │
                  │  DNS & TLS Cache    │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │  Sentinel Analytica │
                  │  Web UI Dashboard   │
                  └─────────────────────┘
```

> **Zero Cloud Raw Sniffing:** Browsers cannot directly capture hardware NIC packets due to sandboxing. The Sentinel Local Agent captures frames locally on the user's authorized machine, normalizes security metadata, and securely relays events to the central backend.

---

## ⚡ Core Capabilities

- **🔴 Real-Time Hardware Capture:** Directly bridges Wi-Fi, Ethernet, VPN, and Virtual NICs via Python Scapy and TShark packet engines.
- **🌐 4-Tuple Flow & Session Tracking:** Dynamic 4-tuple session tracking (`Src IP:Port` $\rightarrow$ `Dst IP:Port`) with live byte volume, packet rates, and direction indicators.
- **🔍 Deep Packet Inspection (DPI):** Frame-level dissecting across Layer 2 (Ethernet), Layer 3 (IPv4/IPv6/ARP), Layer 4 (TCP/UDP/ICMP), and Application Layers (DNS, TLS SNI, HTTP).
- **🛡️ Conservative Threat & Anomaly Detection:** Rule-based heuristic engine identifying Potential Port Scans, Abnormal Traffic Bursts, SYN Floods, and Conflicting TCP Flags with verifiable evidence.
- **🧪 Dual-Mode Operation (Live vs. Demo):** Seamless toggling between authentic hardware monitoring and high-fidelity demo simulation for training and offline evaluations.
- **📁 Forensic PCAP Analyzer:** Deep analysis of `.pcap` and `.pcapng` files with conversational graphs, protocol distributions, and threat indicator extraction.
- **🤖 Context-Aware AI Security Copilot:** Powered by LLMs with real-time injection of observed network telemetry, active connections, and security alerts.

---

## 🖥️ Platform Modules

| Module | Purpose | Key Metrics / Features |
| :--- | :--- | :--- |
| **Monitor Dashboard** | Real-time command center | Packets/sec, Throughput Graph, Protocol Distribution, Top Talkers |
| **Live Traffic Intel** | Connection & DNS cache | 4-Tuple Active Connections, Resolved Domain Queries, Visited HTTPS Sites |
| **Packet Inspector** | Deep protocol dissection | Hex/ASCII Payloads, Layer Headers, TCP Flags, TTL, Checksums |
| **Threat Analyzer** | Network anomaly detection | Non-alarmist alert logs, Severity ratings, Actionable mitigation steps |
| **PCAP Deep Analyzer** | Forensic capture analysis | PCAP/PCAPNG file upload, Session reconstruction, Risk scoring |
| **AI Copilot Intel** | Automated security assistant | Plain-English explanations, Root cause analysis, Action checklists |
| **Sniffing Tools** | Educational & audit guides | Native Wireshark, TShark, Npcap, Scapy command references |

---

## 🐍 Sentinel Local Hardware Agent

The platform provides a standalone, zero-setup Python agent (`agent/sentinel_agent.py`) capable of capturing and streaming normalized packet metadata from any authorized computer.

### Features:
1. **Interface Detection:** Autodetects all physical and virtual network adapters.
2. **Privacy-Preserving:** Strips sensitive credentials, cookies, and cleartext user payloads; only inspects packet headers and security metadata.
3. **Resilient Reconnection:** WebSocket channel with exponential backoff on network dropouts.
4. **Multi-Driver Support:** Compatible with Scapy, Npcap (Windows), libpcap (Linux/macOS), or raw socket fallbacks.

### Quick Start with Python Agent:
```bash
# 1. Install prerequisites
pip install scapy psutil websocket-client

# 2. Run capture agent pointing to your dashboard
python agent/sentinel_agent.py --server https://sentinel-analytica.onrender.com
```

### 1-Click Launchers (Available in Dashboard):
- **Windows:** Download and double-click `Sentinel-Capture-Agent.cmd`
- **macOS:** Run `Sentinel-Capture-Agent-macOS.command`
- **Linux:** Run `Sentinel-Capture-Agent-Linux.sh`

---

## 🚀 Getting Started

### Prerequisites
- **Node.js** (v18.0.0 or higher)
- **Python** (v3.10 or higher with `pip`)
- **Npcap / Wireshark** (optional, for raw local packet capture)

### Local Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Eswar-2006/Advanced-Packet-Sniffer-Network-Analyzer.git
   cd Advanced-Packet-Sniffer-Network-Analyzer
   ```

2. **Install frontend and backend dependencies:**
   ```bash
   npm install
   ```

3. **Configure Environment Variables (Optional):**
   Create a `.env` file in the root directory:
   ```env
   PORT=3000
   GROQ_API_KEY=your_groq_api_key_here
   GEMINI_API_KEY=your_gemini_api_key_here
   ```

4. **Start the platform in development mode:**
   ```bash
   npm run dev
   ```
   *Dashboard opens at `http://localhost:3000` (or `http://localhost:5173`).*

5. **Build for production:**
   ```bash
   npm run build
   npm start
   ```

---

## 🛡️ Conservative Threat Detection Engine

Unlike simplistic alarms that flag every unusual packet as malicious, Sentinel Analytica employs **evidence-based conservative security rules**:

- **Potential Port Scan:** Triggered when a single source IP contacts $\ge 8$ distinct destination ports in a short sliding window.
- **Abnormal Traffic Burst:** Detects sustained high-rate spikes ($\ge 60$ frames in rapid succession) from a non-loopback source.
- **Conflicting TCP Flags:** Alerts on anomalous combinations (e.g. `SYN + FIN` or `NULL` flags) typical of active scanner fingerprinting.
- **Anomalous DNS Query Length:** Flags oversized DNS resolution payloads ($> 512$ bytes) indicating potential covert C2 channels.

---

## 🔬 Packet Data Normalization Model

All captured packets are normalized into a unified security structure:

```typescript
interface Packet {
  id: number;
  timestamp: string;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'HTTPS' | 'DNS' | 'HTTP' | 'ARP' | 'TLS';
  srcIp: string;
  dstIp: string;
  srcPort?: number;
  dstPort?: number;
  macSrc: string;
  macDst: string;
  size: number;
  ttl?: number;
  tcpFlags?: string;
  direction: 'INCOMING' | 'OUTGOING' | 'LOOPBACK';
  hostname?: string;
  service?: string;
  appProtocol?: string;
  interface: string;
  summary: string;
  payloadHex?: string;
  payloadAscii?: string;
}
```

---

## 📡 API & WebSocket Reference

### REST Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/status` | Current capture engine status, flow rate, and capture mode (`REAL` vs `SIMULATED`) |
| `GET` | `/api/packets` | Recent ring buffer packets with throughput statistics |
| `GET` | `/api/connections` | Active 4-tuple tracked sessions |
| `GET` | `/api/dns-cache` | Extracted DNS queries and mapped IP resolutions |
| `GET` | `/api/top-sites` | Extracted HTTPS TLS SNI server names and HTTP hosts |
| `POST` | `/api/demo-mode/toggle` | Switch between live capture and simulation demo mode |
| `POST` | `/api/agents/quick-register` | Zero-configuration agent pairing endpoint |
| `GET` | `/api/download/agent-python` | Download standalone `sentinel_agent.py` script |

### WebSocket Streams

- **Agent Ingestion Channel:** `/ws/agent?agentId=<ID>&agentSecret=<TOKEN>`
- **Dashboard Live Channel:** `/ws/dashboard` (Broadcasts agent status, interface changes, and capture alerts)

---

## 🔒 Security & Privacy Framework

1. **Explicit Capture Action:** The platform and local agent never sniff network traffic without explicit user initiation.
2. **Payload Sanitization:** Cleartext passwords, session cookies, and private messages are omitted by default; inspection is restricted to protocol headers.
3. **Hashed Token Authentication:** Every remote agent connects via unique `AGENT_ID` and cryptographically validated `AGENT_TOKEN`.
4. **Authorized Monitoring Only:** Built strictly for authorized personal network auditing, cybersecurity education, and defensive analysis.

---

## 📄 License & Disclaimer

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

> **Disclaimer:** *Sentinel Analytica is intended for authorized network monitoring, defense optimization, and cybersecurity educational research. Always ensure you have explicit permission before monitoring any network or system.*

<div align="center">
  <sub>Developed by <a href="https://github.com/Eswar-2006">Eswar-2006</a> • Built for Cybersecurity Analysts & Network Engineers</sub>
</div>
