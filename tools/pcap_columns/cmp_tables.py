"""Byte-level comparison of two packet-table .npz files.  python -I cmp_tables.py a.npz b.npz"""
import sys

import numpy as np

COLS = ["ts_us", "src", "dst", "sport", "dport", "proto", "ip_len", "hdr_len", "payload", "flags", "win", "icmp_type", "icmp_code"]
a, b = np.load(sys.argv[1]), np.load(sys.argv[2])
ok = True
assert set(a.files) == set(b.files), (a.files, b.files)
for k in COLS + ["_drop", "_total"]:
    x, y = a[k], b[k]
    same = x.dtype == y.dtype and x.shape == y.shape and x.tobytes() == y.tobytes()
    ok &= same
    if not same:
        msg = f"DIFF {k}: dtype {x.dtype}/{y.dtype} shape {x.shape}/{y.shape}"
        if x.shape == y.shape:
            idx = np.flatnonzero(x != y); msg += f" n_diff={idx.size} first_rows={idx[:10].tolist()}"
        print(msg)
print(f"rows={a['ts_us'].shape[0]} drop(sorted keys fragment,ipv6,non_ip,other_l4,parse_error)={a['_drop'].tolist()} total={int(a['_total'][0])}")
print("BYTE-IDENTICAL packet table:", ok)
sys.exit(0 if ok else 1)
