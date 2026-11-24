"""PcapReader iteration cost.  python -I iter_only.py <pcap> {iter|packet|full}"""
import sys, time, socket, struct
import stackforge as s
path, mode = sys.argv[1], sys.argv[2]
K = s.LayerKind
t0 = time.perf_counter(); n = 0
if mode == "iter":
    for p in s.PcapReader(path): n += 1
elif mode == "packet":
    for p in s.PcapReader(path): pk = p.packet; t = p.time; n += 1
elif mode == "getfield":   # 12 getfieldval calls on one TCP packet, repeated
    for p in s.PcapReader(path):
        pk = p.packet
        if pk.has_layer(K.Tcp): break
    g = pk.getfieldval
    for _ in range(500_000):
        g(K.Ipv4, "frag"); g(K.Ipv4, "len"); g(K.Ipv4, "ihl"); g(K.Ipv4, "proto"); g(K.Tcp, "dataofs"); g(K.Tcp, "sport")
        g(K.Tcp, "dport"); g(K.Tcp, "flags"); g(K.Tcp, "window"); n += 9
dt = time.perf_counter() - t0
print(f"{mode}: n={n} {dt:.3f} s {1e9*dt/n:.0f} ns/item")
