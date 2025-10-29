#! /usr/bin/env python3

# Network Traffic Analyzer 
# A Modular Packet Capture and Analysis Tool for Cybersecurity Researchers
# Usage :     sudo python3 main.py [options]
# Note: Root/Sudo privileges are required for packet capturing.

import sys
import signal
from typing import Optional
from capture.scapy_capture import ScapyCapture
from config import Config


class NetworkAnalyzer:
    # Main class for coordination of all components
    def __init__(self, interface: Optional[str] = None):
        self.interface = interface or Config.DEFAULT_INTERFACE
        self.capture = None
        self.running = False

        # Register signal handlers for clean shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        # Handle Ctrl+C and other forms of termination
        print("\n\nReceived interrupt signal. Shutting down gracefully..." )
        self.stop_capture()
        sys.exit(0)
    
    def start(self, bpf_filter: Optional[str] = None, packet_count: int = 0):
        # Start the network analyzer
        # Args: bpf_filter(str): BPF filter string
        # packet_count(int): Number of packets to capture (0 for infinite)
        print("="*70)
        print("Starting Custos - Vigilantia per Scientiam")
        print("="*70)

        # Initialize Scapy Capture Module 
        # Extensible for future RAW Socket Module
        self.capture = ScapyCapture(interface=self.interface)
        
        try: # Start Packet Capture
            self.capture.start(bpf_filter=bpf_filter, packet_count=packet_count)
            self.running = True
            print("\nCapturing packets... Press Ctrl+C to stop.\n ")
            print(f"{'Time':<12} {'Source':<25} {'Destination':<25} {'Protocol':<8} {'Length':<8}")
            print("-" * 88)

            # Process Packets
            packet_num = 0
            for packet in self.capture:
                packet_num += 1
                self._display_packet(packet, packet_num)
                
                # Stop if we've reached the specified packet count
                if packet_count > 0 and packet_num >= packet_count:
                    break
        except PermissionError:
            print("❌ Permission denied: Please run the program with elevated privileges (e.g., using sudo). ")
            print("Exiting.......")
            sys.exit(1)
        except Exception as e:
            print(f"❌ An error occurred durring capture: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.stop()
            print("Exiting...")
    def _display_packet(self, packet, packet_num: int):
        # Display packet information in a formatted manner
        # Args: packet(CapturedPacket): The captured packet
        # packet_num(int): Sequence number of the packet

        # Format Timestamp
        time_str = packet.timestamp.strftime("%H:%M:%S.%f")[:-3]

        # Format source and destination addresses
        if packet.src_ip and packet.dst_ip:
            if packet.src_port and packet.dst_port:
                source = f"{packet.src_ip}:{packet.src_port}"
                destination = f"{packet.dst_ip}:{packet.dst_port}"
            else:
                source = f"{packet.src_ip}"
                destination = f"{packet.dst_ip}"
        else:
            source = packet.src_mac or "Unknown"
            destination = packet.dst_mac or "Unknown"
        protocol = packet.protocol or "Unknown"

        # Display packet information
        if Config.DISPLAY_RAW_DATA:
            hex_data = packet.raw_data[:32].hex()
            print(f"Raw Data (Hex): {hex_data}")
    
    def stop(self):
        # Stop the network analyzer and clean up resources
        if self.running and self.capture:
            print("\nStopping packet capture...")
            self.capture.stop()
            self.running = False
            print("Packet capture stopped.")

            # Display Statistics
            print("\n" + "=" * 70)
            print("Custos Report")
            print("=" * 70)
            for key, value in self.get_stats().items():
                 print(f"{key.replace('_', '').title()}: {value}")
            print("=" * 70)

def main():
    # Entry point for the Network Traffic Analyzer
    import argparse

    parser = argparse.ArgumentParser(description="Custos - Capture and analyze network packets.", default=None)
    parser.add_argument("-i", "--interface", type=str, help="Network interface to capture packets from (default: all interfaces).", default=None)
    parser.add_argument("-f", "--filter", type=str, help="BPF filter string to apply during capture (e.g. 'tcp port 80').", default=None)
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture (0 for unlimited).", default=0)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.",)
    args = parser.parse_args()

    # Get filter (custom or preset)
    bpf_filter = args.filter
    if args.preset:
        bpf_filter = Config.get_filter(args.preset)
        if not bpf_filter:
            print(f"❌ Preset filter '{args.preset}' not found.\nAvailable presets: {', '.join(Config.COMMON_FILTERS.keys())}")
            sys.exit(1)
    
    # Set verbose mode
    if args.verbose:
        Config.VERBOSE = True
        Config.DISPLAY_RAW_DATA = True
    
    # Create and start analyzer
    analyzer = NetworkAnalyzer(interface=args.interface)
    analyzer.start(bpf_filter=bpf_filter, packet_count=args.count)

if __name__ == "__main__":
    main()
            