"""New reader -> .npz (same layout as ref_dpkt.py).  python -I dump_sf.py <pcap> <out.npz|-> [n_threads]"""
import sys
import time

import numpy as np
import stackforge as s

path, out = sys.argv[1], sys.argv[2]
nt = int(sys.argv[3]) if len(sys.argv) > 3 else None
t0 = time.time()
cols, meta = s.read_pcap_columns(path, n_threads=nt)
dt = time.time() - t0
drop = meta["dropped"]
if out != "-":
    np.savez(out, **cols, _drop=np.array([drop[k] for k in sorted(drop)]), _total=np.array([meta["total_seen"]]))
print(f"sf rows={len(cols['ts_us'])} total_seen={meta['total_seen']} dropped={drop} truncated={meta['truncated']} "
      f"chunks={meta['n_chunks']} threads={meta['n_threads']} seconds={dt:.3f}")
if meta["truncation"]:
    print("truncation:", meta["truncation"])
