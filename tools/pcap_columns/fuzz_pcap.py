"""Build adversarial pcaps from real packets for a dpkt-vs-stackforge differential test.
python -I fuzz_pcap.py <seed.pcap> <outdir> [n_packets] [seed]
Writes: fz_be_us.pcap (big-endian usec, Ethernet), fz_le_ns.pcap (little-endian nsec), fz_raw.pcap (linktype 101, raw IPv4/garbage),
fz_mod.pcap (modified-pcap magic, 24-byte records), and truncated copies fz_trunc_hdr.pcap / fz_trunc_data.pcap."""
import os
import random
import struct
import sys

seed_path, outdir = sys.argv[1], sys.argv[2]
N = int(sys.argv[3]) if len(sys.argv) > 3 else 200_000
rng = random.Random(int(sys.argv[4]) if len(sys.argv) > 4 else 7)


def read_seed(path, limit=30000):
    with open(path, "rb") as f:
        gh = f.read(24)
        e = "<" if gh[:4] == b"\xd4\xc3\xb2\xa1" else ">"
        out = []
        while len(out) < limit:
            h = f.read(16)
            if len(h) < 16: break
            _, _, cap, _ = struct.unpack(e + "IIII", h)
            out.append(f.read(cap))
    return out


base = read_seed(seed_path)
ipv4_frames = [p for p in base if len(p) > 34 and p[12:14] == b"\x08\x00"]
ipv6_frames = [p for p in base if len(p) > 54 and p[12:14] == b"\x86\xdd"]
other_frames = [p for p in base if p[12:14] not in (b"\x08\x00", b"\x86\xdd")]
print(f"seed: {len(base)} frames, ipv4 {len(ipv4_frames)}, ipv6 {len(ipv6_frames)}, other {len(other_frames)}")


def rb(n): return bytes(rng.getrandbits(8) for _ in range(n))


def flip(b, lo=0, hi=None, k=None):
    b = bytearray(b); hi = len(b) if hi is None else min(hi, len(b))
    for _ in range(k or rng.randint(1, 4)):
        if hi > lo: b[rng.randrange(lo, hi)] = rng.getrandbits(8)
    return bytes(b)


def trunc(b): return b[:rng.randint(0, len(b))]


def mac(): return rng.choice([b"\x02" + rb(5), b"\x01\x00\x0c\x00\x00" + rb(1), b"\x03\x00\x0c\x00\x00\x01", b"\xff" * 6])


def ip_payload(): return rng.choice(ipv4_frames)[14:]


def mutate_ip(ip):
    ip = bytearray(ip)
    if len(ip) < 20: return bytes(ip)
    r = rng.random()
    if r < 0.15: ip[0] = (ip[0] & 0xF0) | rng.randint(0, 15)                    # IHL
    elif r < 0.25: ip[0] = (rng.randint(0, 15) << 4) | (ip[0] & 0x0F)           # version
    elif r < 0.40: ip[2:4] = struct.pack("!H", rng.choice([0, 1, 19, 20, 21, 28, 40, rng.randint(0, 65535), len(ip) - 1, len(ip) + 7]))
    elif r < 0.55: ip[6:8] = struct.pack("!H", rng.choice([0x2000, 0x4000, 0x0001, 0x1fff, rng.getrandbits(16)]))  # MF/DF/offset
    elif r < 0.75: ip[9] = rng.choice([0, 1, 2, 4, 6, 17, 41, 47, 50, 51, 58, 89, 103, 112, 118, 132, 255, rng.getrandbits(8)])
    elif r < 0.85 and len(ip) > 33: ip[32] = rng.getrandbits(8)                  # TCP data offset / flags region
    else: ip = bytearray(flip(bytes(ip), 0, 60))
    return bytes(ip)


def icmp_err():
    inner = ip_payload()[: rng.choice([0, 8, 19, 20, 24, 28, 40, 60])]
    icmp = bytes([rng.choice([3, 4, 5, 11, 0, 8, 12, 13]), rng.getrandbits(8)]) + rb(2) + rb(4) + inner
    hdr = bytearray(ip_payload()[:20]); hdr[0] = 0x45; hdr[9] = 1; hdr[6:8] = b"\x00\x00"
    hdr[2:4] = struct.pack("!H", 20 + len(icmp) if rng.random() < 0.8 else rng.getrandbits(16))
    return bytes(hdr) + icmp


def ip6_ext():
    p = bytearray(rng.choice(ipv6_frames)[14:]) if ipv6_frames else bytearray(b"\x60" + rb(39))
    chain = b""; nxt0 = None
    for _ in range(rng.randint(1, 3)):
        t = rng.choice([0, 43, 44, 50, 51, 60, 6, 17, 58])
        nxt0 = t if nxt0 is None else nxt0
        L = rng.choice([0, 1, 2])
        if t in (0, 60):
            body = bytearray(rb(6 + 8 * L));
            if rng.random() < 0.5: body = bytearray(b"\x01" + bytes([4 + 8 * L]) + bytes(4 + 8 * L))
            chain += bytes([rng.choice([6, 17, 58, 59, 0, 60, 44])]) + bytes([L]) + bytes(body)
        elif t == 43: chain += bytes([6, L, 0, 0]) + rb(4 + 8 * L)
        elif t == 44: chain += bytes([rng.choice([6, 17]), 0]) + struct.pack("!H", rng.choice([0, 8, 1])) + rb(4)
        elif t == 51: chain += bytes([6, L]) + rb(10 + 4 * L)
        elif t == 50: chain += rb(rng.choice([4, 8, 16]))
        else: break
    p[6] = nxt0
    body = chain + rb(rng.choice([0, 8, 20]))
    p = bytes(p[:40]) + body
    if rng.random() < 0.3: p = trunc(p)
    p = bytearray(p)
    if len(p) >= 6: p[4:6] = struct.pack("!H", len(p) - 40 if len(p) >= 40 and rng.random() < 0.7 else rng.getrandbits(16))
    return bytes(p)


def frame():
    r = rng.random()
    d, s = mac(), mac()
    if r < 0.20: f = rng.choice(base)
    elif r < 0.30: f = flip(rng.choice(base), 0, 64)
    elif r < 0.38: f = trunc(rng.choice(base))
    elif r < 0.50: f = b"\x02" + rb(5) + rb(6) + b"\x08\x00" + mutate_ip(ip_payload())
    elif r < 0.55: f = b"\x02" + rb(5) + rb(6) + b"\x08\x00" + icmp_err()
    elif r < 0.62:                                     # VLAN / QinQ stacks
        tags = b""; outer = rng.choice([0x8100, 0x88A8, 0x9100, 0x9200])
        types = [rng.choice([0x8100, 0x88A8, 0x0800, 0x86DD, 0x0806, 0x0000, 0x8847]) for _ in range(rng.randint(0, 4))] + [rng.choice([0x0800, 0x86DD, 0x0806])]
        for t in types: tags += rb(2) + struct.pack("!H", t)
        pl = ip_payload() if types[-1] == 0x0800 else (rng.choice(ipv6_frames)[14:] if types[-1] == 0x86DD and ipv6_frames else rb(30))
        f = b"\x02" + rb(5) + rb(6) + struct.pack("!H", outer) + tags + pl
        if rng.random() < 0.3: f = trunc(f)
    elif r < 0.67:                                     # MPLS
        labels = b"".join(struct.pack("!I", (rng.getrandbits(20) << 12) | (rng.random() < 0.4) << 8 | 64) for _ in range(rng.randint(1, 3)))
        tailb = rng.choice([ip_payload(), rng.choice(ipv6_frames)[14:] if ipv6_frames else b"", b"\x00\x00\x00\x00" + rng.choice(base), rng.choice(base), rb(5), b""])
        f = b"\x02" + rb(5) + rb(6) + rng.choice([b"\x88\x47", b"\x88\x48"]) + labels + tailb
        if rng.random() < 0.3: f = trunc(f)
    elif r < 0.71:                                     # ISL
        inner = rng.choice(base)
        f = b"\x01\x00\x0c\x00\x00" + rb(1) + rb(6) + struct.pack("!H", rng.randint(0, 1500)) + rb(12) + inner
        if rng.random() < 0.3: f = trunc(f)
    elif r < 0.79:                                     # 802.3 / LLC / SNAP / raw IPX
        kind = rng.random()
        if kind < 0.3: llc = b"\xaa\xaa\x03" + rb(3) + rng.choice([b"\x08\x00", b"\x86\xdd", b"\x08\x06", b"\x65\x58", rb(2)]) + rng.choice([ip_payload(), rng.choice(base), rb(10)])
        elif kind < 0.5: llc = b"\x06\x06\x03" + rng.choice([ip_payload(), mutate_ip(ip_payload()), rb(10)])
        elif kind < 0.65: llc = b"\x42\x42\x03" + rb(rng.choice([10, 34, 35, 40]))
        elif kind < 0.8: llc = bytes([rng.choice([0x10, 0xe0])]) + b"\x10\x03" + rb(rng.choice([10, 29, 30, 40]))
        elif kind < 0.9: llc = b"\xff\xff" + rb(rng.choice([10, 29, 30, 40]))
        else: llc = rb(rng.choice([0, 1, 2, 3, 6]))
        ln = rng.choice([len(llc), 0, 1, 2, 3, 5, rng.randint(0, 1500), len(llc) + 3])
        f = d + s + struct.pack("!H", ln) + llc + (bytes(rng.choice([0, 4, 20])) if rng.random() < 0.5 else b"")
    elif r < 0.84:                                     # TEB (nested Ethernet)
        f = b"\x02" + rb(5) + rb(6) + b"\x65\x58" + rng.choice([rng.choice(base), trunc(rng.choice(base)), b"\x02" + rb(11) + b"\x88\x47" + rb(2)])
    elif r < 0.90 and ipv6_frames: f = b"\x02" + rb(5) + rb(6) + b"\x86\xdd" + ip6_ext()
    elif r < 0.95: f = b"\x02" + rb(5) + rb(6) + struct.pack("!H", rng.choice([0x0000, 0x0806, 0x88CC, 0x8864, 0x880B, 0x00BB, 0x2000, 0x8137, rng.getrandbits(16)])) + rb(rng.randint(0, 60))
    else: f = rb(rng.randint(0, 20))
    return f


def ts():
    r = rng.random()
    sec = rng.choice([1519233000 + rng.randint(0, 86400), 0, 1, 2**32 - 1, rng.getrandbits(32)])
    if r < 0.6: frac = rng.randint(0, 999_999)
    elif r < 0.8: frac = rng.randint(0, 999_999_999)
    elif r < 0.9: frac = rng.choice([500, 1500, 2500, 999_999_500, 999_999, 1_000_000, 0])
    else: frac = rng.getrandbits(32)
    return sec, frac


def write(path, frames, endian, magic, rec24=False, link=1):
    with open(path, "wb") as f:
        f.write(struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, link))
        for (sec, frac), fr in frames:
            if rec24: f.write(struct.pack(endian + "IIIIIHBB", sec, frac, len(fr), len(fr), 0, 0, 0, 0))
            else: f.write(struct.pack(endian + "IIII", sec, frac, len(fr), len(fr)))
            f.write(fr)


os.makedirs(outdir, exist_ok=True)
frames = [(ts(), frame()) for _ in range(N)]
write(f"{outdir}/fz_be_us.pcap", frames, ">", 0xA1B2C3D4)
write(f"{outdir}/fz_le_ns.pcap", frames, "<", 0xA1B23C4D)
write(f"{outdir}/fz_mod.pcap", frames[: N // 4], "<", 0xA1B2CD34, rec24=True)
raw = [(t, fr[14:] if rng.random() < 0.85 else fr) for t, fr in frames[: N // 2]]
write(f"{outdir}/fz_raw.pcap", raw, "<", 0xA1B2C3D4, link=101)
data = open(f"{outdir}/fz_be_us.pcap", "rb").read()
open(f"{outdir}/fz_trunc_data.pcap", "wb").write(data[: len(data) - 3])        # last record's data cut short
last = len(data) - (16 + len(frames[-1][1]))
open(f"{outdir}/fz_trunc_hdr.pcap", "wb").write(data[: last + 9])                 # cut inside the last record header
print("wrote", N, "frames")
