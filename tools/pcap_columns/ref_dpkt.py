"""dpkt reference packet table -> .npz (or "-" to skip saving).  Needs dpkt 1.9.8 + numpy:  python -I ref_dpkt.py {offwire|loop} <pcap> <out.npz>
offwire: offwire.pcap.read_pcap itself, imported from the directory in $OFFWIRE_ROOT.
loop:    the same loop body copied verbatim, rows stored in array('q') columns instead of a list of tuples
         (constant ~104 B/packet, needed for the multi-GB capture). Exceptions escaping the reader (truncated header) are reported."""
import os
import struct
import sys
import time
from array import array

import numpy as np

COLS = ["ts_us", "src", "dst", "sport", "dport", "proto", "ip_len", "hdr_len", "payload", "flags", "win", "icmp_type", "icmp_code"]
DT = {"ts_us": "int64", "src": "uint32", "dst": "uint32", "sport": "uint16", "dport": "uint16", "proto": "uint8", "ip_len": "int32",
      "hdr_len": "int16", "payload": "int32", "flags": "uint8", "win": "uint16", "icmp_type": "uint8", "icmp_code": "uint8"}


def read_loop(path):
    import dpkt
    cols = [array("q") for _ in COLS]
    drop = {"non_ip": 0, "ipv6": 0, "other_l4": 0, "fragment": 0, "parse_error": 0}
    total = 0; err = None
    with open(path, "rb") as fh:
        magic = fh.read(4); fh.seek(0)
        rd = dpkt.pcapng.Reader(fh) if magic == b"\x0a\x0d\x0d\x0a" else dpkt.pcap.Reader(fh)
        link = rd.datalink()
        it = iter(rd)
        while True:
            try:
                ts, buf = next(it)
            except StopIteration:
                break
            except Exception as e:   # offwire.read_pcap would raise here
                err = repr(e); break
            total += 1
            try:
                if link == dpkt.pcap.DLT_EN10MB:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                else:
                    ip = dpkt.ip.IP(buf)
                if isinstance(ip, dpkt.ip6.IP6):
                    drop["ipv6"] += 1; continue
                if not isinstance(ip, dpkt.ip.IP):
                    drop["non_ip"] += 1; continue
                if ip.offset:
                    drop["fragment"] += 1; continue
                l4 = ip.data
                ihl = ip.hl * 4
                if isinstance(l4, dpkt.tcp.TCP):
                    thl = l4.off * 4
                    row = (int(round(ts * 1_000_000)), struct.unpack("!I", ip.src)[0], struct.unpack("!I", ip.dst)[0],
                           l4.sport, l4.dport, 6, ip.len, thl, max(0, ip.len - ihl - thl), l4.flags & 0xFF, l4.win, 0, 0)
                elif isinstance(l4, dpkt.udp.UDP):
                    row = (int(round(ts * 1_000_000)), struct.unpack("!I", ip.src)[0], struct.unpack("!I", ip.dst)[0],
                           l4.sport, l4.dport, 17, ip.len, 8, max(0, ip.len - ihl - 8), 0, 0, 0, 0)
                elif isinstance(l4, dpkt.icmp.ICMP):
                    row = (int(round(ts * 1_000_000)), struct.unpack("!I", ip.src)[0], struct.unpack("!I", ip.dst)[0],
                           0, 0, 1, ip.len, 8, 0, 0, 0, l4.type, l4.code)
                else:
                    drop["other_l4"] += 1; continue
                for c, v in zip(cols, row): c.append(v)
            except Exception:
                drop["parse_error"] += 1
    d = {c: np.frombuffer(cols[i], dtype=np.int64).astype(DT[c]) for i, c in enumerate(COLS)}
    return d, drop, total, err


if __name__ == "__main__":
    mode, path, out = sys.argv[1:4]
    t0 = time.time(); err = None
    if mode == "offwire":
        sys.path.insert(0, os.environ["OFFWIRE_ROOT"])
        from offwire.pcap import read_pcap
        df = read_pcap(path); d = {c: df[c].to_numpy() for c in COLS}; drop, total = df.attrs["dropped"], df.attrs["total_seen"]
    else:
        d, drop, total, err = read_loop(path)
    dt = time.time() - t0
    if out != "-":
        np.savez(out, **d, _drop=np.array([drop[k] for k in sorted(drop)]), _total=np.array([total]))
    print(f"{mode} rows={len(d['ts_us'])} total_seen={total} dropped={drop} reader_exception={err} seconds={dt:.2f}")
