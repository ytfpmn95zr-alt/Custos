# Configuration settings for the network Traffic Analyzer application

from enum import Enum

class CaptureMode(Enum):
    # Available packet capture methods
    SCAPY = "scapy"
    # Future implementations:
    # RAW_SOCKET = "raw_socket"
    
class Config:
    # Main Configuration Class
    DEFAULT_CAPTURE_MODE = CaptureMode.SCAPY
    DEFAULT_INTERFACE = None  # Capture on all interfaces
    DEFAULT_BPF_FILTER = ""  # No filter
    DEFAULT_PACKET_COUNT = 0  # 0 = unlimited
    VERBOSE = True  # Enable verbose output
    DISPLAY_RAW_DATA = False  # Do not display raw packet data by default
    MAX_PACKET_DISPLAY = 100  # Max packets to display in UI
    ENABLE_STATISTICS = True  # Enable capture statistics
    ENABLE_ANOMALY_DETECTION = False  # Future feature: anomaly detection
    DEFAULT_SNAPLEN = 65535  # Max packet size
    DEFAULT_PROMISCUOUS = True  # Enable promiscuous mode

    # Filter Presets
    COMMON_FILTERS = {
        "HTTP Traffic": "tcp port 80",
        "HTTPS Traffic": "tcp port 443",
        "DNS Traffic": "udp port 53",
        "SSH Traffic": "tcp port 22",
        "WEB Traffic": "tcp port 80 or tcp port 443",
        "TCP Traffic": "tcp",
        "UDP Traffic": "udp",
        "ICMP Traffic": "icmp",
    }

    # Output Settings
    SAVE_TO_PCAP = False  # Do not save to pcap by default
    PCAP_OUTPUT_DIR = "./captures"  # Default directory for pcap files
    LOG_FILE = "./logs/traffic_analyzer.log"  # Default log file path

    # Performance Settings
    CAPTURE_BUFFER_SIZE = 2**20  # 1 MB buffer size
    PACKET_TIMEOUT = 1.0  # Seconds to wait for next packet

    @classmethod
    def get_common_filter(cls, filter_name: str) -> str:
        # Gets a common filter by name
        # Args: filter_name(str): Name of the filter preset
        # Returns: BPF filter string or empty string if not found
        return cls.COMMON_FILTERS.get(filter_name.lower(), "")