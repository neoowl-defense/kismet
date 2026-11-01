# Test pcaps (DLT 127, radiotap with channel and dBm signal) for disconnects on networks with
# and without management frame protection: a protected disconnect's reason code is encrypted, so
# it mustn't be judged.
# Usage: disconnect_pcaps.py <scenario> <outdir>
# The AP beacons every 102.4 ms at -50 dBm and answers probes in between.
import random, struct, sys

def mac(s): return bytes.fromhex(s.replace(":", ""))
BC = mac("ff:ff:ff:ff:ff:ff")
AP = mac("02:00:00:00:33:a1")
CL = mac("42:00:00:00:33:99")
PR = mac("42:00:00:00:33:77")   # a station probing
SSID = b"disconnect-test"
RATES = b"\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24"
TU = 1024
BI = 100 * TU          # beacon interval in us
T0 = 1_790_000_000     # capture epoch
FREQ = 2437            # channel 6

def radiotap(signal):
    # present: channel (bit 3, u16 freq + u16 flags, 2-aligned at offset 8), dBm signal (bit 5)
    return struct.pack("<BBHIHHb", 0, 0, 13, (1 << 3) | (1 << 5), FREQ, 0x00a0, signal)

def hdr(fc, flags, a1, a2, a3, seq):
    return struct.pack("<BBH", fc, flags, 0) + a1 + a2 + a3 + struct.pack("<H", (seq & 0xfff) << 4)

def rsn(mfp_required):
    # CCMP group and pairwise, PSK; capabilities MFPC, plus MFPR when required
    caps = 0x00c0 if mfp_required else 0x0080
    body = struct.pack("<H", 1) + b"\x00\x0f\xac\x04" + struct.pack("<H", 1) + b"\x00\x0f\xac\x04" \
        + struct.pack("<H", 1) + b"\x00\x0f\xac\x02" + struct.pack("<H", caps)
    return b"\x30" + bytes([len(body)]) + body

def ies(pmf):
    return b"\x00" + bytes([len(SSID)]) + SSID + RATES + b"\x03\x01\x06" + rsn(pmf)

def beacon(tsf, seq, pmf):
    return hdr(0x80, 0, BC, AP, AP, seq) + struct.pack("<QHH", tsf, 100, 0x0411) + ies(pmf)

def probe_resp(tsf, seq, pmf):
    return hdr(0x50, 0, PR, AP, AP, seq) + struct.pack("<QHH", tsf, 100, 0x0411) + ies(pmf)

def data_from_client(seq, rng):
    # to-DS, protected: the client's link is up and encrypted
    return hdr(0x08, 0x41, AP, CL, BC, seq) + randbytes(rng, 8 + 120 + 8)

def randbytes(rng, n):
    # random.randbytes needs Python 3.9
    return bytes(rng.getrandbits(8) for _ in range(n))

def disconnect(fc, dest, seq, reason=7, protected=False, rng=None):
    if protected:
        # CCMP header, the encrypted reason code and the MIC
        return hdr(fc, 0x40, dest, AP, AP, seq) + randbytes(rng, 8 + 2 + 8)
    return hdr(fc, 0, dest, AP, AP, seq) + struct.pack("<H", reason)

def deauth(dest, seq, reason=7, protected=False, rng=None):
    return disconnect(0xc0, dest, seq, reason, protected, rng)

def disassoc(dest, seq, reason=8, protected=False, rng=None):
    return disconnect(0xa0, dest, seq, reason, protected, rng)

class AP_:
    """The AP; time and TSF in us"""
    def __init__(self, pmf):
        self.t = 0; self.tsf = 50_000_000; self.seq = 0; self.pmf = pmf
    def run(self, secs, rng):
        out = []
        end = self.t + secs * 1_000_000
        cseq = 100
        while self.t < end:
            out.append((self.t, -50, beacon(self.tsf, self.seq, self.pmf)))
            self.seq += 1
            # a probe response and some client traffic between beacons
            out.append((self.t + 40_000, -50, probe_resp(self.tsf + 40_000, self.seq, self.pmf)))
            self.seq += 1
            out.append((self.t + 60_000, -62, data_from_client(cseq, rng)))
            cseq += 1
            self.t += BI; self.tsf += BI
        return out

def build(name):
    rng = random.Random(name)
    pmf = name.startswith("pmf")
    ap = AP_(pmf)
    frames = ap.run(3, rng)
    at = ap.t
    n = 15

    if name == "router":
        # the AP disconnects its client itself, with a valid reason
        frames += [(at + i * 2000, -50, deauth(CL, ap.seq + i)) for i in range(n)]
    elif name == "pmf_protected":
        # the AP's own protected deauth: the reason code is encrypted, so it can't be judged
        frames += [(at + i * 2000, -50, deauth(CL, ap.seq + i, protected=True, rng=rng))
                   for i in range(n)]
    elif name == "pmf_protected_disassoc":
        # the same with disassociations
        frames += [(at + i * 2000, -50, disassoc(CL, ap.seq + i, protected=True, rng=rng))
                   for i in range(n)]
    elif name == "badreason":
        # an unprotected reason code Kismet considers invalid still raises the invalid-code alert
        frames += [(at + i * 2000, -50, deauth(CL, ap.seq + i, reason=99)) for i in range(n)]
    else:
        raise SystemExit("unknown scenario " + name)
    return frames

name, outdir = sys.argv[1], sys.argv[2]
frames = sorted(build(name), key=lambda x: x[0])
with open("%s/%s.pcap" % (outdir, name), "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 127))
    for t, sig, p in frames:
        p = radiotap(sig) + p
        f.write(struct.pack("<IIII", T0 + t // 1_000_000, t % 1_000_000, len(p), len(p)) + p)
print("%s: %d frames" % (name, len(frames)))
