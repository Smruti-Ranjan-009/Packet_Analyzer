"""
packet_parser.py
================
Parses raw Scapy packets into clean, structured Python objects.

Replaces: src/packet_parser.cpp from the original C++ project.

Key Concept:
    A network packet is a Russian nesting doll of headers:

        [ Ethernet Header ]
            [ IP Header ]
                [ TCP / UDP Header ]
                    [ Payload (application data) ]

    Scapy automatically parses these layers. We just extract the fields
    we need and wrap them in clean dataclasses.

    The Five-Tuple uniquely identifies a network flow (connection):
        (src_ip, dst_ip, src_port, dst_port, protocol)
    All packets with the same five-tuple belong to the same conversation.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from enum import IntEnum

try:
    from scapy.all import Packet, Ether, IP, TCP, UDP, Raw
    from scapy.layers.dns import DNS
except ImportError:
    raise ImportError("Scapy is required. Install it with: pip install scapy")

from pcap_reader import RawPacket


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Protocol(IntEnum):
    """
    IP protocol numbers (from IANA).
    These appear in the 'proto' field of the IP header.
    """
    TCP  = 6
    UDP  = 17
    ICMP = 1
    OTHER = 0


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FiveTuple:
    """
    Uniquely identifies a network flow (connection).

    frozen=True makes it hashable → can be used as dict key.

    Example:
        FiveTuple(
            src_ip   = "192.168.1.100",
            dst_ip   = "172.217.14.206",
            src_port = 54321,
            dst_port = 443,
            protocol = Protocol.TCP
        )
    """
    src_ip   : str
    dst_ip   : str
    src_port : int
    dst_port : int
    protocol : int   # Protocol enum or raw int

    def __str__(self) -> str:
        proto_name = Protocol(self.protocol).name if self.protocol in Protocol._value2member_map_ else str(self.protocol)
        return (
            f"{self.src_ip}:{self.src_port} → "
            f"{self.dst_ip}:{self.dst_port} "
            f"[{proto_name}]"
        )

    def reverse(self) -> "FiveTuple":
        """
        Returns the reverse direction of this flow.
        Useful for matching server → client replies to the same flow.

        Example:
            client → server  maps to same flow as  server → client
        """
        return FiveTuple(
            src_ip   = self.dst_ip,
            dst_ip   = self.src_ip,
            src_port = self.dst_port,
            dst_port = self.src_port,
            protocol = self.protocol,
        )


@dataclass
class ParsedPacket:
    """
    A fully parsed network packet with all important fields extracted.

    This is the main output of PacketParser.parse().
    All downstream components (flow tracker, SNI extractor, ML feature
    extractor) work with ParsedPacket objects.

    Attributes:
        index         : Packet number in the PCAP file
        timestamp     : Capture time (seconds since epoch)
        tuple         : FiveTuple identifying the flow

        -- Ethernet Layer --
        src_mac       : Source MAC address (e.g., "00:11:22:33:44:55")
        dst_mac       : Destination MAC address
        eth_type      : EtherType (0x0800 = IPv4, 0x0806 = ARP, etc.)

        -- IP Layer --
        src_ip        : Source IP address (dotted notation)
        dst_ip        : Destination IP address
        ip_version    : 4 (IPv4) or 6 (IPv6)
        ttl           : Time To Live (decrements at each router hop)
        ip_length     : Total length of IP packet (bytes)
        protocol      : Transport protocol (TCP=6, UDP=17, ICMP=1)

        -- TCP Layer (if has_tcp) --
        src_port      : Source port number
        dst_port      : Destination port number
        tcp_seq       : Sequence number
        tcp_ack       : Acknowledgment number
        tcp_flags     : TCP flags string (e.g., "S", "SA", "PA", "F")
        tcp_window    : Window size (flow control)

        -- UDP Layer (if has_udp) --
        src_port      : Source port number
        dst_port      : Destination port number
        udp_length    : UDP payload length

        -- Payload --
        payload       : Raw bytes of application data (after transport header)
        payload_length: Number of payload bytes

        -- Flags --
        has_ethernet  : Does this packet have an Ethernet header?
        has_ip        : Does this packet have an IP header?
        has_tcp       : Is this a TCP packet?
        has_udp       : Is this a UDP packet?
        is_https      : Is destination/source port 443?
        is_http       : Is destination/source port 80?
        is_dns        : Is destination/source port 53?
    """

    # Metadata
    index         : int   = 0
    timestamp     : float = 0.0

    # Five-Tuple (set after parsing)
    tuple         : Optional[FiveTuple] = None

    # Ethernet
    src_mac       : str   = ""
    dst_mac       : str   = ""
    eth_type      : int   = 0

    # IP
    src_ip        : str   = ""
    dst_ip        : str   = ""
    ip_version    : int   = 0
    ttl           : int   = 0
    ip_length     : int   = 0
    protocol      : int   = 0

    # TCP
    src_port      : int   = 0
    dst_port      : int   = 0
    tcp_seq       : int   = 0
    tcp_ack       : int   = 0
    tcp_flags     : str   = ""
    tcp_window    : int   = 0

    # UDP
    udp_length    : int   = 0

    # Payload
    payload       : bytes = b""
    payload_length: int   = 0

    # Boolean flags
    has_ethernet  : bool  = False
    has_ip        : bool  = False
    has_tcp       : bool  = False
    has_udp       : bool  = False
    is_https      : bool  = False
    is_http       : bool  = False
    is_dns        : bool  = False


# ---------------------------------------------------------------------------
# PacketParser Class
# ---------------------------------------------------------------------------

class PacketParser:
    """
    Parses RawPacket objects (from PcapReader) into ParsedPacket objects.

    Usage:
        parser = PacketParser()
        parsed = parser.parse(raw_packet)

        if parsed and parsed.has_tcp:
            print(parsed.tuple)
            print(parsed.payload_length)
    """

    # TCP flags mapping — Scapy uses letters for TCP flags
    _FLAG_MAP = {
        "F": "FIN",
        "S": "SYN",
        "R": "RST",
        "P": "PSH",
        "A": "ACK",
        "U": "URG",
        "E": "ECE",
        "C": "CWR",
    }

    def parse(self, raw: RawPacket) -> Optional[ParsedPacket]:
        """
        Parse a single RawPacket into a ParsedPacket.

        Args:
            raw: A RawPacket from PcapReader.

        Returns:
            ParsedPacket if parsing succeeds, None if packet is malformed
            or doesn't have an IP layer (e.g., ARP packets).
        """
        pkt = raw.data  # Scapy packet object

        parsed = ParsedPacket(
            index     = raw.index,
            timestamp = raw.timestamp,
        )

        # ── Layer 2: Ethernet ──────────────────────────────────────────
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            parsed.has_ethernet = True
            parsed.src_mac      = eth.src
            parsed.dst_mac      = eth.dst
            parsed.eth_type     = eth.type  # 0x0800 = IPv4

        # ── Layer 3: IP ────────────────────────────────────────────────
        if not pkt.haslayer(IP):
            # Skip non-IP packets (ARP, IPv6-only, etc.)
            return None

        ip = pkt[IP]
        parsed.has_ip     = True
        parsed.src_ip     = ip.src
        parsed.dst_ip     = ip.dst
        parsed.ip_version = ip.version
        parsed.ttl        = ip.ttl
        parsed.ip_length  = ip.len
        parsed.protocol   = ip.proto

        # ── Layer 4: TCP ───────────────────────────────────────────────
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            parsed.has_tcp    = True
            parsed.src_port   = tcp.sport
            parsed.dst_port   = tcp.dport
            parsed.tcp_seq    = tcp.seq
            parsed.tcp_ack    = tcp.ack
            parsed.tcp_flags  = self._parse_tcp_flags(tcp.flags)
            parsed.tcp_window = tcp.window

            # Extract payload (bytes after TCP header)
            if pkt.haslayer(Raw):
                parsed.payload        = bytes(pkt[Raw].load)
                parsed.payload_length = len(parsed.payload)

        # ── Layer 4: UDP ───────────────────────────────────────────────
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            parsed.has_udp    = True
            parsed.src_port   = udp.sport
            parsed.dst_port   = udp.dport
            parsed.udp_length = udp.len

            if pkt.haslayer(Raw):
                parsed.payload        = bytes(pkt[Raw].load)
                parsed.payload_length = len(parsed.payload)

        # ── Protocol Flags (convenience) ───────────────────────────────
        port_pair = {parsed.src_port, parsed.dst_port}
        parsed.is_https = 443 in port_pair
        parsed.is_http  = 80  in port_pair
        parsed.is_dns   = 53  in port_pair

        # ── Build Five-Tuple ───────────────────────────────────────────
        if parsed.has_tcp or parsed.has_udp:
            parsed.tuple = FiveTuple(
                src_ip   = parsed.src_ip,
                dst_ip   = parsed.dst_ip,
                src_port = parsed.src_port,
                dst_port = parsed.dst_port,
                protocol = parsed.protocol,
            )

        return parsed

    def parse_all(self, raw_packets: list[RawPacket]) -> list[ParsedPacket]:
        """
        Parse a list of RawPackets. Skips packets that fail parsing.

        Args:
            raw_packets: List of RawPacket from PcapReader.read_all()

        Returns:
            List of successfully parsed ParsedPacket objects.
        """
        results = []
        skipped = 0

        for raw in raw_packets:
            parsed = self.parse(raw)
            if parsed is not None:
                results.append(parsed)
            else:
                skipped += 1

        print(f"[PacketParser] Parsed: {len(results)}, Skipped: {skipped}")
        return results

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _parse_tcp_flags(self, flags) -> str:
        """
        Convert Scapy TCP flags to a readable string.

        Scapy flags are a FlagValue object. We convert to short form.
        Examples:
            0x002 → "S"    (SYN)
            0x012 → "SA"   (SYN-ACK)
            0x018 → "PA"   (PSH-ACK — data packet)
            0x011 → "FA"   (FIN-ACK)
        """
        return str(flags)


# ---------------------------------------------------------------------------
# Quick Test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import os

    # Allow passing pcap path as argument
    pcap_path = sys.argv[1] if len(sys.argv) > 1 else "../data/test_dpi.pcap"

    # We need to import from same directory
    sys.path.insert(0, os.path.dirname(__file__))
    from pcap_reader import PcapReader

    print("=" * 65)
    print("  PacketParser — Quick Test")
    print("=" * 65)

    reader = PcapReader(pcap_path)
    parser = PacketParser()

    tcp_count   = 0
    udp_count   = 0
    https_count = 0
    http_count  = 0
    dns_count   = 0

    print(f"\n{'#':<5} {'Five-Tuple':<55} {'Payload':>8}")
    print("-" * 72)

    for raw in reader.read_packets():
        parsed = parser.parse(raw)

        if parsed is None:
            continue

        # Count protocols
        if parsed.has_tcp:   tcp_count   += 1
        if parsed.has_udp:   udp_count   += 1
        if parsed.is_https:  https_count += 1
        if parsed.is_http:   http_count  += 1
        if parsed.is_dns:    dns_count   += 1

        # Show first 8 packets
        if raw.index <= 8 and parsed.tuple:
            print(
                f"{raw.index:<5} "
                f"{str(parsed.tuple):<55} "
                f"{parsed.payload_length:>6} B"
            )

    print()
    print("── Summary ──────────────────────")
    print(f"  TCP packets  : {tcp_count}")
    print(f"  UDP packets  : {udp_count}")
    print(f"  HTTPS (443)  : {https_count}")
    print(f"  HTTP  (80)   : {http_count}")
    print(f"  DNS   (53)   : {dns_count}")
