# A test pcap (DLT 256, Bluetooth LE link layer with the pseudo-header) of an advertiser, a
# scanner and an initiator.
# Usage: pdu_pcaps.py <out.pcap>
# The advertiser sends connectable advertisements (ADV_IND) and answers scans (SCAN_RSP); the
# scanner only sends SCAN_REQ and the initiator only CONNECT_IND, both from random addresses,
# as phones do.  Each sends on channel 37 every 100 ms.
import struct, sys

T0 = 1_790_000_000      # capture epoch
ADV_AA = 0x8E89BED6     # advertising access address
ADV_IND, SCAN_REQ, SCAN_RSP, CONNECT_IND = 0x0, 0x3, 0x4, 0x5
TX_RANDOM = 0x40        # TxAdd: the transmitter address is random
FLAGS = bytes([2, 0x01, 0x06])

ADVERTISER = "00:1b:dc:12:34:56"
SCANNER = "4a:11:22:33:44:55"
INITIATOR = "5b:66:77:88:99:aa"


def crc24(data, init=0xAAAAAA):
    # The link layer CRC as Kismet checks it: init 0x555555, bit-reversed for the LFSR
    lfsr = init
    for byte in data:
        for _ in range(8):
            bit = (byte ^ lfsr) & 1
            lfsr >>= 1
            byte >>= 1
            if bit:
                lfsr ^= 0xDA6000
    return lfsr


def addr(a):
    # Addresses go least significant octet first
    return bytes.fromhex(a.replace(":", ""))[::-1]


def pdu(pdu_type, random, payload):
    header = bytes([pdu_type | (TX_RANDOM if random else 0), len(payload)])
    ll = struct.pack("<I", ADV_AA) + header + payload + struct.pack("<I", crc24(header + payload))[:3]
    # Pseudo-header: RF channel 0 (advertising channel 37), signal and noise valid; the
    # CRC is left for Kismet to check
    flags = (1 << 1) | (1 << 2)
    return struct.pack("<BbbBIH", 0, -50, -100, 0, ADV_AA, flags) + ll


# CONNECT_IND's LLData: access address, CRC init, window size and offset, interval, latency,
# timeout, channel map, hop and sleep clock accuracy
LL_DATA = struct.pack("<I3sBHHHH5sB", 0x50654C1A, b"\x12\x34\x56", 2, 0, 24, 0, 72,
                      b"\xff\xff\xff\xff\x1f", 0x25)

PACKETS = [
    pdu(ADV_IND, False, addr(ADVERTISER) + FLAGS),
    pdu(SCAN_RSP, False, addr(ADVERTISER) + bytes([5, 0x09]) + b"Test"),
    pdu(SCAN_REQ, True, addr(SCANNER) + addr(ADVERTISER)),
    pdu(CONNECT_IND, True, addr(INITIATOR) + addr(ADVERTISER) + LL_DATA),
]

frames = sorted((i * 100_000 + n * 1000, p) for n, p in enumerate(PACKETS) for i in range(10))
with open(sys.argv[1], "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 256))
    for t, p in frames:
        f.write(struct.pack("<IIII", T0 + t // 1_000_000, t % 1_000_000, len(p), len(p)) + p)
