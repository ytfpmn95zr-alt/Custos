# Implements Scapy-based packet capture functionality


from typing import Optional
from datetime import datetime
from queue import Queue, Empty
import threading

try:
    from scapy.all import sniff, conf 
    from scapy.layers.l2 import Ether 
    from scapy.layers.inet import IP, TCP, UDP 
except ImportError:
    raise ImportError("Scapy is required for ScapyCapture. Please install it via 'pip install scapy'.")

from base import PacketCapture, CapturedPacket

class ScapyCapture(PacketCapture):
    # Scapy-based packet capture implementation
    def __init__(self, interface: Optional[str] = None):
        super().__init__(interface)
        self.packet_queue = Queue()
        self.capture_thread = None
        self.filter = None
        self.max_packers = 0

    def start(self, bpf_filter: Optional[str] = None, packet_count: int = 0) -> None:
        # Start capturing packets using Scapy
        # Args: bpf_filter(str): Berkeley Packet Filter string
        # packet_count(int): Number of packets to capture (0 for infinite)

       if self.is_running:
            raise RuntimeError("Capture is already running.")
       else:
           self.filter = bpf_filter
           self.max_packets = packet_count
           self.is_running = True
           self.packet_count = 0

           # Start capture in a separate thread to avoid blocking
           self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
           self.capture_thread.start()

           print(f"Started Scapy capture on interface: {self.interface or 'all interfaces'}")
           if bpf_filter:
                print(f"Applied filter: {bpf_filter}")

    def _capture_loop(self):
        # Internal method to run the Scapy in background thread
        try:
            sniff(
                iface=self.interface,
                filter=self.filter,
                prn=self._process_packet,
                store=False, # Do not store packets in memory
                count=self.max_packets if self.max_packets > 0 else 0,
                stop_filter=lambda x: not self.is_running
            )
        except Exception as e:
            print(f"Error durring Capture: {e}")
        finally:
            self.is_running = False

    def _process_packet(self, scapy_packet):
        # Process scapy packet and convert to CapturedPacket
        # Args: scapy_packet: Packet captured by Scapy

        self.packet_count += 1

        # Extract Common data feilds
        timestamp = datetime.now()
        raw_data = bytes(scapy_packet)
        length = len(raw_data)

        # Extract layer information(if available)
        src_mac = scapy_packet[Ether].src if Ether in scapy_packet else None
        dst_mac = scapy_packet[Ether].dst if Ether in scapy_packet else None
        src_ip = scapy_packet[IP].src if IP in scapy_packet else None
        dst_ip = scapy_packet[IP].dst if IP in scapy_packet else None

        # Determine Protocol and port
        protocol = None
        src_port = None
        dst_port = None

        if TCP in scapy_packet:
            protocol = "TCP"
            src_port = scapy_packet[TCP].sport
            dst_port = scapy_packet[TCP].dport
        elif UDP in scapy_packet:
            protocol = "UDP"
            src_port = scapy_packet[UDP].sport
            dst_port = scapy_packet[UDP].dport
        elif IP in scapy_packet:
            protocol = scapy_packet[IP].proto

        # Create standardized packet
        packet = CapturedPacket(
            timestamp=timestamp,
            raw_data=raw_data,
            length=length,
            interface=self.interface or "all",
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol
        )
    
        # Add to queue for consumption
        self.packet_queue.put(packet)
    def next_packet(self, timeout: float = 1.0) -> Optional[CapturedPacket]:
        # Retrieve the next captured packet from the queue
        # Args: timeout(float): Max time to wait for a packet (in seconds)
        # Returns: CapturedPacket or None if timeout or capture stopped
        try:
            packet = self.packet_queue.get(timeout=timeout)
            return packet
        except Empty:
            return None if self.is_running else None
    
    def stop(self) -> None:
        # Stop the packet capturing process and cleanup resources
        if not self.is_running:
            return

        print("\nStopping Scapy capture...")
        self.is_running = False

        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)
        
        print("Scapy capture stopped. Total packets: {self.packet_count}")
    
    def get_stats(self) -> dict:
        # Retrieve capture statistics
        # Returns: Dictionary with capture statistics
        return {
            "packets_captured": self.packet_count,
            "queue_size": self.packet_queue.qsize(),
            "interface": self.interface or "all",
            "is_running": self.is_running,
            "filter": self.filter,
        }