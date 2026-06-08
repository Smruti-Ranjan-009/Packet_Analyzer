"""
pcap_reader.py
==============
Reads .pcap files and yields raw packets one by one.

Replaces: src/pcap_reader.cpp from the original C++ project.

Key Concept:
    A .pcap file is a binary file with:
        - 1 Global Header (24 bytes) — identifies it as a PCAP file
        - N Packet Records, each with:
            - Packet Header (16 bytes) — timestamp + length
            - Packet Data   (variable) — actual network bytes

We use Scapy which handles all of this automatically.
"""

import os
from dataclasses import dataclass, field
from typing import Iterator, Optional

try:
    from scapy.all import rdpcap, PcapReader as ScapyPcapReader, Packet
except ImportError:
    raise ImportError(
        "Scapy is required. Install it with: pip install scapy"
    )


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class RawPacket:
    """
    Holds one raw packet as returned from the PCAP file.

    Attributes:
        index       : Packet number (1-based) in the file
        timestamp   : Capture time in seconds (float)
        data        : The raw Scapy packet object (contains all layers)
        length      : Original length of the packet on the wire (bytes)
        caplen      : Captured length saved in the file (may be truncated)
    """
    index     : int
    timestamp : float
    data      : Packet          # Scapy packet — all layers accessible
    length    : int
    caplen    : int


# ---------------------------------------------------------------------------
# PcapReader Class
# ---------------------------------------------------------------------------

class PcapReader:
    """
    Reads a .pcap file and provides packets one by one.

    Two modes:
        1. Lazy  (default) — reads one packet at a time, memory-efficient
                             good for large files
        2. Eager           — loads all packets at once into memory
                             good for small test files

    Usage:
        reader = PcapReader("test_dpi.pcap")

        # Lazy iteration (recommended)
        for raw_pkt in reader.read_packets():
            print(raw_pkt.timestamp, raw_pkt.length)

        # Or load all at once
        packets = reader.read_all()
        print(f"Total packets: {len(packets)}")
    """

    def __init__(self, filepath: str):
        """
        Args:
            filepath: Path to the .pcap file.

        Raises:
            FileNotFoundError : If the file doesn't exist.
            ValueError        : If the file is not a valid PCAP.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"PCAP file not found: {filepath}")

        if not filepath.endswith((".pcap", ".pcapng", ".cap")):
            print(f"[Warning] Unexpected file extension: {filepath}")

        self.filepath = filepath
        self._packet_count = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def read_packets(self) -> Iterator[RawPacket]:
        """
        Lazily yields RawPacket objects one at a time.
        Memory-efficient — suitable for large capture files.

        Yields:
            RawPacket for each packet in the file.
        """
        print(f"[PcapReader] Opening: {self.filepath}")

        try:
            # ScapyPcapReader is a lazy file reader — does NOT load all at once
            with ScapyPcapReader(self.filepath) as pcap:
                for index, pkt in enumerate(pcap, start=1):
                    self._packet_count = index

                    raw = RawPacket(
                        index     = index,
                        timestamp = float(pkt.time),
                        data      = pkt,
                        length    = len(pkt),           # captured length
                        caplen    = len(pkt),           # same in most cases
                    )
                    yield raw

        except Exception as e:
            raise ValueError(
                f"[PcapReader] Failed to read PCAP file '{self.filepath}': {e}"
            )

        print(f"[PcapReader] Done. Total packets read: {self._packet_count}")

    def read_all(self) -> list[RawPacket]:
        """
        Eagerly loads ALL packets into a list.
        Easy to work with for small files and testing.

        Returns:
            List of RawPacket objects.
        """
        return list(self.read_packets())

    def packet_count(self) -> int:
        """Returns number of packets read so far."""
        return self._packet_count

    def get_file_info(self) -> dict:
        """
        Returns basic metadata about the PCAP file.

        Returns:
            Dict with filepath, size_bytes, size_kb.
        """
        size = os.path.getsize(self.filepath)
        return {
            "filepath"   : self.filepath,
            "size_bytes" : size,
            "size_kb"    : round(size / 1024, 2),
        }


# ---------------------------------------------------------------------------
# Quick Test — run this file directly to verify it works
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    # Allow passing a pcap file as argument, else use a default path
    pcap_path = sys.argv[1] if len(sys.argv) > 1 else "../data/test_dpi.pcap"

    print("=" * 55)
    print("  PcapReader — Quick Test")
    print("=" * 55)

    reader = PcapReader(pcap_path)

    # Print file info
    info = reader.get_file_info()
    print(f"File     : {info['filepath']}")
    print(f"Size     : {info['size_kb']} KB")
    print()

    # Read first 5 packets and display them
    print(f"{'#':<5} {'Timestamp':<18} {'Length':>8}")
    print("-" * 35)

    for raw_pkt in reader.read_packets():
        if raw_pkt.index <= 5:
            print(
                f"{raw_pkt.index:<5} "
                f"{raw_pkt.timestamp:<18.6f} "
                f"{raw_pkt.length:>6} bytes"
            )
        else:
            print(f"  ... (showing first 5 only)")
            break

    print()
    print(f"Total packets in file: {reader.packet_count()}")
