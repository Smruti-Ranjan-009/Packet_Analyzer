"""
sni_extractor.py
================
Extracts the destination domain name from two sources:

    1. TLS Client Hello  → SNI (Server Name Indication) field
       Used for HTTPS traffic (port 443).
       The domain is sent in PLAINTEXT in the very first TLS packet —
       even though all subsequent data is encrypted.

    2. HTTP Host Header  → "Host:" field
       Used for plain HTTP traffic (port 80).
       The domain is always in plaintext here.

Replaces: src/sni_extractor.cpp from the original C++ project.

Key Concept — Why SNI Works:
    When your browser visits https://www.youtube.com, the first packet
    it sends is a TLS "Client Hello". This packet MUST contain the domain
    name in plaintext so the server knows which SSL certificate to use
    (one server can host many domains — this is called SNI).

    TLS Client Hello structure (simplified):
    ┌──────────────────────────────────────────────────┐
    │ Byte 0    : 0x16  → TLS Handshake record         │
    │ Bytes 1-2 : TLS version                          │
    │ Bytes 3-4 : Record length                        │
    │ Byte 5    : 0x01  → Client Hello message         │
    │ ...                                              │
    │ Extensions:                                      │
    │   Type 0x0000 → SNI extension                    │
    │     └── "www.youtube.com"  ← We extract THIS    │
    └──────────────────────────────────────────────────┘
"""

from __future__ import annotations
from typing import Optional
from enum import Enum, auto


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class AppType(Enum):
    """
    Application types identified by SNI or HTTP Host.
    Extend this list to support more apps.
    """
    UNKNOWN   = auto()
    HTTP      = auto()
    HTTPS     = auto()
    DNS       = auto()
    GOOGLE    = auto()
    YOUTUBE   = auto()
    FACEBOOK  = auto()
    INSTAGRAM = auto()
    TWITTER   = auto()
    TIKTOK    = auto()
    NETFLIX   = auto()
    AMAZON    = auto()
    GITHUB    = auto()
    LINKEDIN  = auto()
    REDDIT    = auto()
    WHATSAPP  = auto()
    ZOOM      = auto()
    MICROSOFT = auto()
    APPLE     = auto()


# Domain keyword → AppType mapping
# Order matters: more specific patterns first
_SNI_TO_APP: list[tuple[str, AppType]] = [
    ("youtube",     AppType.YOUTUBE),
    ("ytimg",       AppType.YOUTUBE),       # YouTube image CDN
    ("googlevideo", AppType.YOUTUBE),       # YouTube video delivery
    ("facebook",    AppType.FACEBOOK),
    ("fbcdn",       AppType.FACEBOOK),      # Facebook CDN
    ("instagram",   AppType.INSTAGRAM),
    ("twitter",     AppType.TWITTER),
    ("x.com",       AppType.TWITTER),
    ("tiktok",      AppType.TIKTOK),
    ("netflix",     AppType.NETFLIX),
    ("nflxvideo",   AppType.NETFLIX),       # Netflix video CDN
    ("amazon",      AppType.AMAZON),
    ("amazonaws",   AppType.AMAZON),        # AWS/Amazon CDN
    ("github",      AppType.GITHUB),
    ("linkedin",    AppType.LINKEDIN),
    ("reddit",      AppType.REDDIT),
    ("whatsapp",    AppType.WHATSAPP),
    ("zoom",        AppType.ZOOM),
    ("microsoft",   AppType.MICROSOFT),
    ("bing",        AppType.MICROSOFT),
    ("apple",       AppType.APPLE),
    ("icloud",      AppType.APPLE),
    ("google",      AppType.GOOGLE),        # Must come after youtube/googlevideo
]


def sni_to_app_type(sni: str) -> AppType:
    """
    Map a domain name (SNI or HTTP Host) to an AppType.

    Uses substring matching — the SNI "www.youtube.com" matches
    the keyword "youtube".

    Args:
        sni: Domain name string (e.g., "www.youtube.com")

    Returns:
        AppType enum value (UNKNOWN if no match found)

    Examples:
        sni_to_app_type("www.youtube.com")   → AppType.YOUTUBE
        sni_to_app_type("graph.facebook.com") → AppType.FACEBOOK
        sni_to_app_type("example.com")        → AppType.UNKNOWN
    """
    sni_lower = sni.lower()
    for keyword, app_type in _SNI_TO_APP:
        if keyword in sni_lower:
            return app_type
    return AppType.UNKNOWN


# ---------------------------------------------------------------------------
# SNIExtractor Class (TLS)
# ---------------------------------------------------------------------------

class SNIExtractor:
    """
    Extracts the SNI (Server Name Indication) from a TLS Client Hello.

    This works by manually parsing the TLS handshake bytes because:
      - The SNI is in the FIRST packet (before encryption)
      - We need to navigate through variable-length fields to find it

    Usage:
        extractor = SNIExtractor()
        sni = extractor.extract(payload_bytes)

        if sni:
            print(f"Domain: {sni}")              # "www.youtube.com"
            print(f"App: {sni_to_app_type(sni)}") # AppType.YOUTUBE
    """

    # TLS record/handshake type constants
    _TLS_RECORD_HANDSHAKE  = 0x16  # Content Type: Handshake
    _TLS_HANDSHAKE_HELLO   = 0x01  # Handshake Type: Client Hello
    _TLS_EXT_SNI           = 0x0000  # Extension Type: SNI
    _TLS_SNI_TYPE_HOSTNAME = 0x00  # SNI name type: hostname

    def extract(self, payload: bytes) -> Optional[str]:
        """
        Extract the SNI hostname from a TLS Client Hello payload.

        Args:
            payload: Raw bytes of the TCP payload (application data).

        Returns:
            Domain name string if found (e.g., "www.youtube.com"),
            None if this is not a TLS Client Hello or SNI is missing.
        """
        if len(payload) < 43:
            return None  # Too short to be a valid Client Hello

        # ── Check TLS Record Header (bytes 0–4) ────────────────────────
        #
        # Byte 0: Content Type
        #   0x16 = Handshake  (what we want)
        #   0x14 = ChangeCipherSpec
        #   0x15 = Alert
        #   0x17 = Application Data (encrypted — no SNI here)
        #
        if payload[0] != self._TLS_RECORD_HANDSHAKE:
            return None

        # Bytes 1-2: TLS version (e.g., 0x0301 = TLS 1.0, 0x0303 = TLS 1.2)
        # Bytes 3-4: Record length
        # We don't strictly need these, but they help with validation.

        # ── Check Handshake Header (bytes 5–8) ────────────────────────
        #
        # Byte 5: Handshake Type
        #   0x01 = Client Hello  (what we want — client initiating TLS)
        #   0x02 = Server Hello
        #   0x0b = Certificate
        #
        if len(payload) < 6 or payload[5] != self._TLS_HANDSHAKE_HELLO:
            return None

        # ── Navigate to Extensions ─────────────────────────────────────
        #
        # Client Hello structure after byte 5:
        #   3 bytes  : Handshake length
        #   2 bytes  : Client version
        #   32 bytes : Random (fixed size)
        #   1 byte   : Session ID length (N)
        #   N bytes  : Session ID
        #   2 bytes  : Cipher Suites length (C)
        #   C bytes  : Cipher Suites
        #   1 byte   : Compression Methods length (M)
        #   M bytes  : Compression Methods
        #   2 bytes  : Extensions length
        #   ... extensions ...
        #
        offset = 43  # Skip to Session ID length field

        # Skip Session ID
        if offset >= len(payload):
            return None
        session_id_len = payload[offset]
        offset += 1 + session_id_len

        # Skip Cipher Suites
        if offset + 2 > len(payload):
            return None
        cipher_suites_len = self._read_uint16(payload, offset)
        offset += 2 + cipher_suites_len

        # Skip Compression Methods
        if offset + 1 > len(payload):
            return None
        compression_len = payload[offset]
        offset += 1 + compression_len

        # ── Read Extensions ────────────────────────────────────────────
        if offset + 2 > len(payload):
            return None

        extensions_len = self._read_uint16(payload, offset)
        offset += 2

        extensions_end = offset + extensions_len

        # ── Search for SNI Extension (type 0x0000) ─────────────────────
        while offset + 4 <= extensions_end and offset + 4 <= len(payload):

            ext_type = self._read_uint16(payload, offset)
            ext_data_len = self._read_uint16(payload, offset + 2)
            offset += 4

            if ext_type == self._TLS_EXT_SNI:
                # Found SNI extension!
                # SNI extension data structure:
                #   2 bytes : SNI list length
                #   1 byte  : SNI type (0x00 = hostname)
                #   2 bytes : SNI name length (K)
                #   K bytes : SNI name (the domain string)

                if offset + 5 > len(payload):
                    return None

                # Skip SNI list length (2) + SNI type (1) = 3 bytes
                sni_name_len = self._read_uint16(payload, offset + 3)

                sni_start = offset + 5
                sni_end   = sni_start + sni_name_len

                if sni_end > len(payload):
                    return None

                # Decode the hostname bytes to a string
                try:
                    sni = payload[sni_start:sni_end].decode("utf-8", errors="ignore")
                    return sni if sni else None
                except Exception:
                    return None

            # Not the SNI extension — skip past this extension's data
            offset += ext_data_len

        return None  # SNI extension not found

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _read_uint16(data: bytes, offset: int) -> int:
        """
        Read a 2-byte big-endian unsigned integer from bytes.

        Network protocols use big-endian (most significant byte first),
        which is the opposite of most modern CPUs (little-endian).

        Args:
            data  : byte array
            offset: starting position

        Returns:
            Integer value (0 to 65535)
        """
        return (data[offset] << 8) | data[offset + 1]


# ---------------------------------------------------------------------------
# HTTPHostExtractor Class
# ---------------------------------------------------------------------------

class HTTPHostExtractor:
    """
    Extracts the Host header value from plain HTTP requests.

    HTTP is unencrypted, so the Host header is always visible:

        GET /search?q=python HTTP/1.1\r\n
        Host: www.google.com\r\n          ← We extract THIS
        User-Agent: Mozilla/5.0\r\n
        ...

    Usage:
        extractor = HTTPHostExtractor()
        host = extractor.extract(payload_bytes)

        if host:
            print(f"Host: {host}")  # "www.google.com"
    """

    # Common HTTP methods — used to verify this is an HTTP request
    _HTTP_METHODS = (
        b"GET ", b"POST ", b"PUT ", b"DELETE ",
        b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ",
    )

    def extract(self, payload: bytes) -> Optional[str]:
        """
        Extract the Host header from an HTTP request payload.

        Args:
            payload: Raw bytes of the TCP payload.

        Returns:
            Host string if found (e.g., "www.google.com"),
            None if this is not an HTTP request or Host header is missing.
        """
        if len(payload) < 10:
            return None

        # Verify this is an HTTP request (starts with a known method)
        is_http = any(payload.startswith(method) for method in self._HTTP_METHODS)
        if not is_http:
            return None

        # Search for "Host:" header (case-insensitive)
        # HTTP headers are ASCII text, lines separated by \r\n
        try:
            text = payload.decode("utf-8", errors="ignore")
        except Exception:
            return None

        for line in text.split("\r\n"):
            if line.lower().startswith("host:"):
                host = line[5:].strip()  # Remove "Host:" prefix and whitespace
                # Remove port if present (e.g., "example.com:8080" → "example.com")
                host = host.split(":")[0].strip()
                return host if host else None

        return None


# ---------------------------------------------------------------------------
# Combined Extraction Function
# ---------------------------------------------------------------------------

def extract_domain(payload: bytes, dst_port: int) -> Optional[str]:
    """
    Try to extract a domain name from the packet payload.

    Tries TLS SNI first (port 443), then HTTP Host (port 80).
    This is the main function called by the DPI engine.

    Args:
        payload  : Raw bytes of the TCP application payload.
        dst_port : Destination port number.

    Returns:
        Domain name string if found, None otherwise.

    Examples:
        extract_domain(tls_hello_bytes, 443)  → "www.youtube.com"
        extract_domain(http_bytes, 80)        → "www.google.com"
        extract_domain(encrypted_bytes, 443)  → None
    """
    if not payload:
        return None

    # Try TLS SNI (HTTPS traffic)
    if dst_port == 443:
        sni = SNIExtractor().extract(payload)
        if sni:
            return sni

    # Try HTTP Host header (plain HTTP traffic)
    if dst_port == 80:
        host = HTTPHostExtractor().extract(payload)
        if host:
            return host

    # Try SNI on non-standard HTTPS ports too (e.g., 8443)
    if dst_port not in (80, 443) and payload and payload[0] == 0x16:
        sni = SNIExtractor().extract(payload)
        if sni:
            return sni

    return None


# ---------------------------------------------------------------------------
# Quick Test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import os

    sys.path.insert(0, os.path.dirname(__file__))
    from pcap_reader import PcapReader
    from packet_parser import PacketParser

    pcap_path = sys.argv[1] if len(sys.argv) > 1 else "../data/test_dpi.pcap"

    print("=" * 65)
    print("  SNIExtractor — Quick Test")
    print("=" * 65)

    reader = PcapReader(pcap_path)
    parser = PacketParser()

    found_domains: dict[str, AppType] = {}

    for raw in reader.read_packets():
        parsed = parser.parse(raw)
        if parsed is None or not parsed.has_tcp:
            continue

        domain = extract_domain(parsed.payload, parsed.dst_port)
        if domain and domain not in found_domains:
            app = sni_to_app_type(domain)
            found_domains[domain] = app

    print(f"\nUnique domains detected: {len(found_domains)}\n")
    print(f"{'Domain':<40} {'App Type':<20}")
    print("-" * 62)

    for domain, app in sorted(found_domains.items()):
        print(f"{domain:<40} {app.name:<20}")

    # ── Built-in unit tests ──────────────────────────────────────────
    print()
    print("── Unit Tests ──────────────────────────────")

    # Test sni_to_app_type
    tests = [
        ("www.youtube.com",    AppType.YOUTUBE),
        ("graph.facebook.com", AppType.FACEBOOK),
        ("www.google.com",     AppType.GOOGLE),
        ("github.com",         AppType.GITHUB),
        ("randomsite.xyz",     AppType.UNKNOWN),
    ]

    for sni, expected in tests:
        result = sni_to_app_type(sni)
        status = "✅" if result == expected else "❌"
        print(f"  {status} sni_to_app_type('{sni}') → {result.name}")
