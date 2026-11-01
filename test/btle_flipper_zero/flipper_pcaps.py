# Test pcaps (DLT 256, Bluetooth LE link layer with the pseudo-header) of devices that do and
# don't match a Flipper Zero signature.
# Usage: flipper_pcaps.py <scenario> <outdir>
# Each device sends a connectable advertisement (ADV_IND) on channel 37 every 100 ms.
import struct, sys

T0 = 1_790_000_000      # capture epoch
ADV_AA = 0x8E89BED6     # advertising access address
ADV_IND = 0x0
TX_RANDOM = 0x40        # TxAdd: the advertiser address is random

# Advertising data types
AD_FLAGS = 0x01
AD_UUID16_COMPLETE = 0x03
AD_NAME = 0x09
AD_MANUF = 0xFF


def mac(s):
    return bytes.fromhex(s.replace(":", ""))


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


def ad(kind, data):
    return bytes([len(data) + 1, kind]) + data


def adv(addr, random, ads, signal=-50):
    payload = mac(addr)[::-1] + b"".join(ads)
    header = bytes([ADV_IND | (TX_RANDOM if random else 0), len(payload)])
    crc = crc24(header + payload)
    ll = struct.pack("<I", ADV_AA) + header + payload + struct.pack("<I", crc)[:3]
    # Pseudo-header: RF channel 0 (advertising channel 37), signal and noise valid, the
    # reference access address valid; the CRC is left for Kismet to check
    flags = (1 << 1) | (1 << 2) | (1 << 5)
    phdr = struct.pack("<BbbBIH", 0, signal, -100, 0, ADV_AA, flags)
    return phdr + ll


FLAGS = ad(AD_FLAGS, b"\x06")


def device(addr, random, first, later=None, secs=3, start=0, counter=False):
    """Advertisements every 100 ms; `later` replaces `first` after the first second.  With
    `counter`, each carries a changing byte, under the SIG's test company ID 0xFFFF, so it
    isn't a duplicate of the last: Kismet skips a frame identical to a recent one."""
    out = []
    for i in range(secs * 10):
        ads = list(first if later is None or i < 10 else later)
        if counter:
            ads.append(ad(AD_MANUF, struct.pack("<HB", 0xFFFF, i & 0xFF)))
        out.append((start + i * 100_000, adv(addr, random, ads)))
    return out


def build(name):
    if name == "stm32_public":
        # The address the official firmware derives from the STM32WB chip ID
        return device("80:e1:26:12:34:56", False, [FLAGS, ad(AD_NAME, b"Ruhe")])
    if name == "stm32_random":
        # 80:E1:2x can't be a random address, so it counts whatever TxAdd says
        return device("80:e1:27:12:34:56", True, [FLAGS])
    if name == "oui_public":
        return device("0c:fa:22:12:34:56", False, [FLAGS])
    if name == "oui_random":
        # A non-resolvable private address that happens to begin with the Flipper OUI
        return device("0c:fa:22:12:34:56", True, [FLAGS])
    if name == "uuid_later":
        # The serial service UUID only in advertisements after the first second
        return device("4a:11:22:33:44:55", True, [FLAGS],
                      [FLAGS, ad(AD_UUID16_COMPLETE, struct.pack("<H", 0x3082))])
    if name == "name_later":
        return device("4a:11:22:33:44:56", True, [FLAGS],
                      [FLAGS, ad(AD_NAME, b"Flipper Ruhe")])
    if name == "company":
        return device("4a:11:22:33:44:57", True,
                      [FLAGS, ad(AD_MANUF, struct.pack("<H", 0x0E29) + b"\x01\x02")])
    if name == "other":
        # Nothing Flipper about it: another UUID, company and name
        return device("4a:11:22:33:44:58", True,
                      [FLAGS, ad(AD_UUID16_COMPLETE, struct.pack("<H", 0x180F)),
                       ad(AD_MANUF, struct.pack("<H", 0x004C) + b"\x10\x05"),
                       ad(AD_NAME, b"Flipperish")])
    if name == "burst":
        # Four Flipper devices at once, more than the alert rate allows; each still gets
        # its alert with a later packet
        out = []
        for n in range(4):
            out += device("80:e1:26:00:00:%02x" % (n + 1), False, [FLAGS], secs=20,
                          start=n * 1000, counter=True)
        return out
    raise SystemExit("unknown scenario " + name)


name, outdir = sys.argv[1], sys.argv[2]
frames = sorted(build(name), key=lambda x: x[0])
with open("%s/%s.pcap" % (outdir, name), "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 256))
    for t, p in frames:
        f.write(struct.pack("<IIII", T0 + t // 1_000_000, t % 1_000_000, len(p), len(p)) + p)
print("%s: %d packets" % (name, len(frames)))
