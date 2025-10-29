# Abstract base class
# Allows for swapping between scapy and raw socket implementations

from abc import ABC, abstractmethod
from dataclasses import dataclass   
from typing import Optional, Iterator
from datetime import datetime

@dataclass
class CapturedPacket:
    # Standardized packet representation
    timestamp: datetime
    raw_data: bytes
    length: int
    interface: str

    # Pre-paresed layers(Provided by scapy)
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None

class PacketCapture(ABC):
    # Abstract base class for packet capturing implementations.
    # Must provide: -Scapycapture -Rawsocketcapture
    def __init__(self, interface: str, bpf_filter: Optional[str] = None):
        # Initialize the packet capture interface
        # Args: interface(str): Network interface name (e.g. "eth0") if None, uses all interfaces)
        self.interface = interface
        self.is_running = False
        self.packet_count = 0

    @abstractmethod
    def start_capture(self, bpf_filter: Optional[str] = None, packet_count: int = 0) -> None:       
        # Start capturing packets
        # Args: bptf_filter(str): Berkeley Packet Filter string
        # packet_count(int): Number of packets to capture (0 for infinite)
        pass
    @abstractmethod
    def next_packet(self) -> Optional[CapturedPacket]:
        # Retrieve the next captured packet
        # Returns: CapturedPacket or None if no more packets
        pass
    @abstractmethod
    def stop(self) -> None:
        # Stop the packet capturing process and cleanup resources
        pass

    def __iter__(self) -> Iterator[CapturedPacket]:
        # Iteration over captured packets
        while self.is_running:
            packet = self.next_packet()
            if packet is None:
                break
            yield packet

    def __enter__(self):
        # Context manager entry
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Context manager exit
        self.stop()
        pass 
    
    @abstractmethod
    def get_stats(self) -> dict:
        # Retrieve capture statistics
        # Returns: Dictionary with statistics (e.g. packets captured, dropped, etc.)
        pass