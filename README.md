# 🔥 NetPhantom

**NetPhantom** (Network Phantom Poisoning & Authentication Capture Tool) is a modern, modular, and asynchronous offensive security tool designed for network poisoning and credential capture. It mimics legitimate network services to intercept authentication attempts and extract valuable information like NTLM hashes.

## 🚀 Features

- **Modular Poisoning Engine**: Supports LLMNR, NBT-NS, and mDNS protocols.
- **Asynchronous Sniffing**: Uses Scapy and threading for high-performance packet processing.
- **Rich CLI**: Beautiful and informative command-line interface.
- **NTLM Hash Extraction**: Automatically extracts NTLMv1/v2 blobs from HTTP and SMB traffic.
- **Extensible Architecture**: Easily add new protocols or capture mechanisms.

## 🛠️ Installation

NetPhantom requires Python 3.11+ and uses Poetry for dependency management.

```bash
# Clone the repository
git clone https://github.com/ismailtasdelen/netphantom.git
cd netphantom

# Install dependencies
poetry install
```

## 📖 Usage

Run NetPhantom by specifying the network interface and the IP address you want to spoof.

```bash
# Start NetPhantom with default protocols (LLMNR, NBT-NS, mDNS)
poetry run python -m netph.ui.cli --interface eth0 --spoof-ip 192.168.1.50

# Specify specific protocols
poetry run python -m netph.ui.cli -i eth0 -s 192.168.1.50 -p llmnr mdns
```

## 🛡️ Security & Disclaimer

> [!WARNING]
> This tool is for educational and authorized penetration testing purposes ONLY. Unauthorized use of NetPhantom against systems you do not have explicit permission to test is illegal and unethical.

## 📜 License

This project is licensed under the MIT License.
