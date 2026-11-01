# A test pcap (DLT 256, Bluetooth LE link layer with the pseudo-header) of two devices
# advertising, one from a public address and one from a random one.
# Usage: address_pcaps.py <out.pcap>
# Each device sends a connectable advertisement (ADV_IND) on channel 37 every 100 ms.
import struct, sys

T0 = 1_790_000_000      # capture epoch
ADV_AA = 0x8E89BED6     # advertising access address
ADV_IND = 0x0
TX_RANDOM = 0x40        # TxAdd: the advertiser address is random
FLAGS = bytes([2, 0x01, 0x06])

# Address -> whether it's random
DEVICES = {"00:1b:dc:12:34:56": False, "c6:11:22:33:44:55": True}


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


def adv(addr, random):
    payload = bytes.fromhex(addr.replace(":", ""))[::-1] + FLAGS
    header = bytes([ADV_IND | (TX_RANDOM if random else 0), len(payload)])
    ll = struct.pack("<I", ADV_AA) + header + payload + struct.pack("<I", crc24(header + payload))[:3]
    # Pseudo-header: RF channel 0 (advertising channel 37), signal and noise valid; the
    # CRC is left for Kismet to check
    flags = (1 << 1) | (1 << 2)
    return struct.pack("<BbbBIH", 0, -50, -100, 0, ADV_AA, flags) + ll


frames = sorted((i * 100_000 + n * 1000, adv(a, r))
                for n, (a, r) in enumerate(DEVICES.items()) for i in range(10))
with open(sys.argv[1], "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 256))
    for t, p in frames:
        f.write(struct.pack("<IIII", T0 + t // 1_000_000, t % 1_000_000, len(p), len(p)) + p)
