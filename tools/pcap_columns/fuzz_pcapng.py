"""pcapng cases for the dpkt-vs-stackforge differential test (frames from fuzz_pcap.frame()).
python -I fuzz_pcapng.py <seed.pcap> <outdir> [n_packets] [seed]
Writes ng_le.pcapng (LE, usec, mixed block types, SPB/ISB/NRB/custom/PB, 2nd IDB with other linktype, 2nd SHB,
EPBs before the first IDB, option comments), ng_be.pcapng (BE, if_tsresol 2^-10, negative if_tsoffset),
ng_ns.pcapng (LE, if_tsresol 9 -> ns ticks > 2^53, if_tsoffset), ng_raw.pcapng (first IDB linktype 101),
ng_trunc_block.pcapng (cut inside the last EPB: dpkt raises), ng_trunc_tail.pcapng (5 trailing bytes: ignored),
ng_bad_mid.pcapng (an EPB with a wrong trailing length mid-file: dpkt raises there)."""
import os
import random
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fuzz_pcap as fz  # noqa: E402

seed_path, outdir = sys.argv[1], sys.argv[2]
N = int(sys.argv[3]) if len(sys.argv) > 3 else 200_000
fz.init(seed_path, int(sys.argv[4]) if len(sys.argv) > 4 else 7)
rng = random.Random(int(sys.argv[4]) + 1 if len(sys.argv) > 4 else 8)


def pad4(b): return b + b"\x00" * (-len(b) % 4)


def opt(e, code, data): return struct.pack(e + "HH", code, len(data)) + pad4(data)


def block(e, btype, body):
    n = 12 + len(body)
    return struct.pack(e + "II", btype, n) + body + struct.pack(e + "I", n)


def shb(e, opts=b""):
    return block(e, 0x0A0D0D0A, struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1) + opts)


def idb(e, link, tsresol=None, tsoff=None, extra=b""):
    o = extra
    if tsresol is not None: o += opt(e, 9, bytes([tsresol]))
    if tsoff is not None: o += opt(e, 14, struct.pack(e + "q", tsoff))
    if o: o += opt(e, 0, b"")
    return block(e, 1, struct.pack(e + "HHI", link, 0, 65535) + o)


def epb(e, ticks, data, opts=b"", btype=6, iface=0):
    hi, lo = ticks >> 32 & 0xFFFFFFFF, ticks & 0xFFFFFFFF
    if btype == 2:
        head = struct.pack(e + "HHIIII", iface, 0, hi, lo, len(data), len(data))
    else:
        head = struct.pack(e + "IIIII", iface, hi, lo, len(data), len(data))
    return block(e, btype, head + pad4(data) + opts)


def ticks_for(divisor, tsoff):
    r = rng.random()
    if r < 0.85:
        secs = 1519233000 + rng.random() * 86400 - tsoff
        return max(0, int(secs * divisor) + rng.randint(-3, 3))
    if r < 0.95: return rng.getrandbits(rng.choice([32, 40, 48]))   # keeps ts_us inside int64 for every divisor used
    return rng.choice([0, 1, 2**32 - 1, 2**32, 2**53 + 1, 2**53 + 3])


def packets(e, n, divisor, tsoff, extras=True, link_strip=False):
    out = []
    for _ in range(n):
        fr = fz.frame()
        if link_strip and rng.random() < 0.85: fr = fr[14:]
        r = rng.random()
        if extras and r < 0.03: out.append(block(e, 3, struct.pack(e + "I", len(fr)) + pad4(fr)))      # SPB: ignored
        elif extras and r < 0.04: out.append(block(e, 5, struct.pack(e + "III", 0, 1, 2)))             # ISB
        elif extras and r < 0.045: out.append(block(e, 4, b"\x00\x00\x00\x00"))                       # NRB
        elif extras and r < 0.05: out.append(block(e, 0x00000BAD, rb_(16)))                          # custom
        opts = b""
        q = rng.random()
        if q < 0.05: opts = opt(e, 1, "comment é".encode()) + opt(e, 0, b"")
        elif q < 0.07: opts = opt(e, 1, b"ascii\x00\xff") + opt(e, 0, b"")        # not utf-8, NUL then 0xff: ascii ok
        elif q < 0.08: opts = opt(e, 2, b"\x00" * 4) + opt(e, 0, b"")
        out.append(epb(e, ticks_for(divisor, tsoff), fr, opts, btype=2 if rng.random() < 0.05 else 6, iface=rng.choice([0, 0, 1])))
    return out


def rb_(n): return bytes(rng.getrandbits(8) for _ in range(n))


def write(name, parts):
    with open(os.path.join(outdir, name), "wb") as f:
        for p in parts: f.write(p)


os.makedirs(outdir, exist_ok=True)
e = "<"
pre = [epb(e, 123, fz.frame()) for _ in range(5)]   # packet blocks before the first IDB: skipped by dpkt
le = [shb(e, opt(e, 4, b"fuzz") + opt(e, 1, b"section comment") + opt(e, 0, b"")), *pre, idb(e, 1),
      *packets(e, N // 2, 1e6, 0), idb(e, 101, 9), shb(e), idb(e, 113), *packets(e, N // 2, 1e6, 0)]
write("ng_le.pcapng", le)
e = ">"
write("ng_be.pcapng", [shb(e), idb(e, 1, 0x8A, -3600), *packets(e, N // 2, 1024.0, -3600)])
e = "<"
write("ng_ns.pcapng", [shb(e), idb(e, 1, 9, 7200, extra=opt(e, 2, b"eth0")), *packets(e, N // 2, 1e9, 7200)])
write("ng_raw.pcapng", [shb(e), idb(e, 101), *packets(e, N // 4, 1e6, 0, link_strip=True)])
full = b"".join([shb(e), idb(e, 1), *packets(e, N // 4, 1e6, 0)])
open(os.path.join(outdir, "ng_trunc_block.pcapng"), "wb").write(full[:-7])
open(os.path.join(outdir, "ng_trunc_tail.pcapng"), "wb").write(full + b"\x01\x02\x03\x04\x05")
mid = packets(e, N // 4, 1e6, 0, extras=False)
bad = bytearray(mid[len(mid) // 2]); bad[-4:] = struct.pack("<I", len(bad) + 4)
mid[len(mid) // 2] = bytes(bad)
write("ng_bad_mid.pcapng", [shb(e), idb(e, 1), *mid])
print("wrote pcapng fuzz files")
