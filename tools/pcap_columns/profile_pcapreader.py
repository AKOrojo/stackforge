"""Stage-by-stage timing of the existing stackforge PcapReader path (what analysis/read_pcap_stackforge.py `dump` does).
usage: python -I profile_pcapreader.py <pcap> [max_packets]"""
import socket
import struct
import sys
import time

import stackforge as s

path = sys.argv[1]
N = int(sys.argv[2]) if len(sys.argv) > 2 else 300_000
K = s.LayerKind


def ip2i(a):
    return struct.unpack("!I", socket.inet_aton(a))[0]


def stage(name, fn):
    t0 = time.perf_counter(); n = fn(); dt = time.perf_counter() - t0
    print(f"{name:<44s} {dt:7.3f} s  {1e9 * dt / n:8.0f} ns/pkt  (n={n})")
    return dt


def it_only():
    n = 0
    for p in s.PcapReader(path):
        n += 1
        if n >= N: break
    return n


def it_packet():
    n = 0
    for p in s.PcapReader(path):
        pk = p.packet; t = p.time; n += 1
        if n >= N: break
    return n


def it_haslayer():
    n = 0
    for p in s.PcapReader(path):
        pk = p.packet; pk.has_layer(K.Ipv6); pk.has_layer(K.Ipv4); n += 1
        if n >= N: break
    return n


def it_full():   # the read_sf loop body without the array appends
    n = 0
    for p in s.PcapReader(path):
        n += 1
        pk = p.packet
        if pk.has_layer(K.Ipv6) or not pk.has_layer(K.Ipv4): continue
        if pk.getfieldval(K.Ipv4, "frag"): continue
        iplen = pk.getfieldval(K.Ipv4, "len"); ihl = pk.getfieldval(K.Ipv4, "ihl") * 4
        src = ip2i(pk.getfieldval(K.Ipv4, "src")); dst = ip2i(pk.getfieldval(K.Ipv4, "dst"))
        t = int(round(p.time * 1_000_000)); pr = pk.getfieldval(K.Ipv4, "proto")
        if pr == 6 and pk.has_layer(K.Tcp):
            pk.getfieldval(K.Tcp, "dataofs"); pk.getfieldval(K.Tcp, "sport"); pk.getfieldval(K.Tcp, "dport")
            pk.getfieldval(K.Tcp, "flags"); pk.getfieldval(K.Tcp, "window")
        elif pr == 17 and pk.has_layer(K.Udp):
            pk.getfieldval(K.Udp, "sport"); pk.getfieldval(K.Udp, "dport")
        if n >= N: break
    return n


def getfield_only():   # cost of one getfieldval call on one parsed packet
    for p in s.PcapReader(path):
        pk = p.packet
        if pk.has_layer(K.Tcp): break
    M = 300_000
    for _ in range(M): pk.getfieldval(K.Tcp, "sport")
    return M


def getfield_src():
    for p in s.PcapReader(path):
        pk = p.packet
        if pk.has_layer(K.Tcp): break
    M = 300_000
    for _ in range(M): ip2i(pk.getfieldval(K.Ipv4, "src"))
    return M


def rdpcap_all():
    return len(s.rdpcap(path, N))


for name, fn in [("PcapReader iterate only", it_only), ("+ .packet + .time", it_packet), ("+ 2x has_layer", it_haslayer),
                 ("full read_sf body (no appends)", it_full), ("getfieldval(Tcp,'sport') x1 call", getfield_only),
                 ("ip2i(getfieldval(Ipv4,'src')) x1 call", getfield_src), ("rdpcap(count=N) (mmap)", rdpcap_all)]:
    stage(name, fn)
