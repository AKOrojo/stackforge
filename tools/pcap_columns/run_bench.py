"""Benchmark driver: each run is a fresh process under /usr/bin/time (wall, peak RSS); appends rows to a CSV.
python3 run_bench.py <csv> <label> <pcap> <cache:warm|cold> <cpus> <repeats> -- <cmd...>   ({pcap} in cmd is substituted)"""
import csv
import os
import re
import subprocess
import sys
import time

BENCH = os.path.dirname(os.path.abspath(__file__))
VENV = sys.executable

out_csv, label, pcap, cache, cpus, reps = sys.argv[1:7]
cmd = sys.argv[sys.argv.index("--") + 1:]
size = os.path.getsize(pcap)
for r in range(int(reps)):
    if cache == "cold":
        subprocess.run([VENV, "-I", os.path.join(BENCH, "evict.py"), pcap], check=True)
        res = subprocess.run(["fincore", "-b", "-n", "-o", "RES", pcap], capture_output=True, text=True).stdout.strip()
        resident = int(res or 0)
    else:
        subprocess.run(["cat", pcap], stdout=subprocess.DEVNULL, check=True)   # make sure it is cached
        resident = -1
    full = ["/usr/bin/time", "-f", "TIME wall=%e maxrss=%M", "taskset", "-c", cpus] + [c.replace("{pcap}", pcap) for c in cmd]
    load1 = float(open('/proc/loadavg').read().split()[0])
    t0 = time.time()
    p = subprocess.run(full, capture_output=True, text=True)
    m = re.search(r"TIME wall=([\d.]+) maxrss=(\d+)", p.stderr)
    if p.returncode != 0 or not m:
        print("FAILED", label, p.stdout[-500:], p.stderr[-1500:]); sys.exit(1)
    wall, rss = float(m.group(1)), int(m.group(2))
    inner = re.search(r"seconds=([\d.]+)", p.stdout)
    row = dict(label=label, pcap=os.path.basename(pcap), bytes=size, cache=cache, cpus=cpus, rep=r, wall_s=wall,
               inner_s=float(inner.group(1)) if inner else "", maxrss_mb=round(rss / 1024, 1), mb_s=round(size / 1e6 / wall, 1),
               resident_before=resident, load1=load1, stdout=p.stdout.strip().splitlines()[0][:200] if p.stdout.strip() else "")
    new = not os.path.exists(out_csv)
    with open(out_csv, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(row)); new and w.writeheader(); w.writerow(row)
    print(f"{label:<28s} {row['pcap'][:34]:<34s} {cache:<4s} rep{r} wall={wall:8.2f}s rss={row['maxrss_mb']:9.1f}MB {row['mb_s']:8.1f} MB/s")
