# Custos - Vigilantia per Scientiam

A modular Python-based network traffic analyzer built for cybersecurity research and training. Features a flexible architecture allowing both high-level (Scapy) and low-level (raw sockets) packet capture implementations.

---

## 🎯 Project Goals

- Learn packet-level network operations
- Practice modular software architecture
- Demonstrate both practical and low-level networking knowledge
- Build a foundation for advanced traffic analysis features

---

## 🏗️ Architecture

The project uses an interface-based design pattern allowing multiple capture implementations:

```
NetworkAnalyzer
├── Capture Layer (Abstract Interface)
│   ├── ScapyCapture (Current - High-level)
│   └── RawSocketCapture (Future - Low-level)
├── Parser Layer (Protocol dissection)
├── Analysis Layer (Statistics, anomaly detection)
├── Filter Layer (BPF filters)
└── Display Layer (CLI output, exports)
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- macOS/Linux (Windows support via Npcap)
- Root/administrator privileges for packet capture

### Installation

Clone or download the project and run the setup script:

```bash
chmod +x setup.sh
./setup.sh
```

Activate virtual environment:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

### Basic Usage

Capture all traffic:

```bash
sudo python3 main.py
```

Capture on specific interface:

```bash
sudo python3 main.py -i en0
```

Apply BPF filter:

```bash
sudo python3 main.py -f "tcp port 443"
```

Use preset filter:

```bash
sudo python3 main.py -p https
```

Capture limited packets:

```bash
sudo python3 main.py -c 100
```

Verbose output:

```bash
sudo python3 main.py -v
```

---

## 📋 Available Filter Presets

| Preset | Description                     |
| ------ | ------------------------------- |
| http   | HTTP traffic (port 80)          |
| https  | HTTPS traffic (port 443)        |
| dns    | DNS queries (port 53)           |
| ssh    | SSH connections (port 22)       |
| web    | All web traffic (ports 80, 443) |
| icmp   | ICMP packets (ping, etc.)       |

---

## 🛠️ Development Roadmap

### Phase 1: Core Implementation ✅

- [x] Project structure
- [x] Abstract capture interface
- [x] Scapy-based capture module
- [x] Basic packet display
- [x] BPF filtering support
- [ ] Unit tests

### Phase 2: Analysis Features _(In Progress)_

- [ ] Protocol-specific parsers (HTTP, DNS, TLS)
- [ ] Traffic statistics
- [ ] Session tracking
- [ ] Export to PCAP
- [ ] JSON/CSV export

### Phase 3: Raw Socket Implementation _(Planned)_

- [ ] Raw socket capture module
- [ ] Manual Ethernet/IP/TCP/UDP parsing
- [ ] Platform-specific optimizations
- [ ] Performance benchmarking

### Phase 4: Advanced Features _(Future)_

- [ ] Anomaly detection
- [ ] Port scan detection
- [ ] DPI (Deep Packet Inspection)
- [ ] Real-time visualization
- [ ] Web UI

---

## 📁 Project Structure

```
network_analyzer/
├── capture/              # Packet capture modules
│   ├── base.py           # Abstract interface
│   ├── scapy_capture.py  # Scapy implementation
│   └── raw_capture.py    # Raw socket implementation (future)
├── parsers/              # Protocol parsers
├── analysis/             # Traffic analysis modules
├── filters/              # Packet filtering
├── display/              # Output formatting
├── tests/                # Unit tests
├── main.py               # Main application
├── config.py             # Configuration
└── requirements.txt      # Dependencies
```

---

## 🔧 Technical Details

### Capture Module Design

The abstract `PacketCapture` class defines the interface:

- `start()` - Initialize capture
- `next_packet()` - Retrieve captured packet
- `stop()` - Cleanup and shutdown
- `get_stats()` - Capture statistics

All implementations return standardized `CapturedPacket` objects with:

- Timestamp
- Raw packet data
- Pre-parsed common fields (IPs, ports, protocols)

---

### Why This Architecture?

- **Separation of Concerns:** Capture, parsing, analysis, and display are independent modules.
- **Extensibility:** Easy to add new capture methods, protocols, or analysis features.
- **Testability:** Each module can be tested independently.
- **Learning Path:** Start with high-level tools, progress to low-level implementations.

---

## 🧪 Testing

```bash
# Run all tests
pytest

# With coverage
pytest --cov=. --cov-report=html

# Specific test file
pytest tests/test_capture.py
```

---

## ⚠️ Security Considerations

- **Privileges:** Packet capture requires root/administrator access
- **Data Privacy:** Captured traffic may contain sensitive information
- **Legal:** Only capture traffic you have permission to monitor
- **Storage:** Be mindful of disk space when saving captures

---

## 🤝 Contributing

This is a personal learning project, but suggestions and improvements are welcome!

---

## 📚 Resources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [BPF Filter Syntax](https://biot.com/capstats/bpf.html)
- [TCP/IP Protocol Suite](https://www.rfc-editor.org/)
- [Wireshark](https://www.wireshark.org/) – Reference implementation

---

## 📝 License

**MIT License** — Use for learning and research purposes.

---

## 🎓 Learning Notes

### Key Concepts Demonstrated

- Network Programming: Socket programming, packet capture
- Protocol Analysis: Understanding OSI layers, packet structure
- Software Design: Abstract interfaces, modular architecture
- Python Skills: Threading, queues, context managers, dataclasses
- Security Tools: BPF filters, traffic analysis techniques

### Next Steps for Learning

- Implement protocol-specific parsers
- Add statistical analysis features
- Build the raw socket module
- Create performance benchmarks
- Explore machine learning for anomaly detection

---

> **Note:** This project requires root privileges. Always run packet capture tools responsibly and only on networks you own or have permission to monitor.
