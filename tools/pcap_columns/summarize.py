"""Summarize results.csv: median/min wall, MB/s at the median, peak RSS, per (capture, method, cache); contended rows excluded."""
import csv
import statistics
import sys
from collections import defaultdict

rows = [r for r in csv.DictReader(open(sys.argv[1])) if not r["label"].endswith("_CONTENDED")]
g = defaultdict(list)
for r in rows:
    g[(r["pcap"], r["cache"], r["label"])].append(r)
order = {"dpkt_offwire": 0, "dpkt_loop": 0, "sf073_PcapReader": 1, "sf_new_PcapReader": 2, "cat_devnull": 9}
print(f"{'capture':<34} {'MB':>7} {'cache':<5} {'method':<18} {'n':>2} {'median s':>9} {'min s':>8} {'MB/s':>8} {'peak RSS MB':>11} {'load1':>6} {'in-call s':>9}")
for (pcap, cache, label), rs in sorted(g.items(), key=lambda kv: (int(kv[1][0]["bytes"]), kv[0][1] != "warm",
                                                                    order.get(kv[0][2], 5), int(kv[0][2].split("_t")[-1]) if "_t" in kv[0][2] else 0)):
    walls = [float(r["wall_s"]) for r in rs]
    med = statistics.median(walls); size = int(rs[0]["bytes"])
    loads = [float(r["load1"]) for r in rs if r.get("load1")]
    inn = [float(r["inner_s"]) for r in rs if r.get("inner_s")]
    inner = f"{statistics.median(inn):9.3f}" if inn else f"{'':>9}"
    print(f"{pcap[:34]:<34} {size / 1e6:7.0f} {cache:<5} {label:<18} {len(rs):2d} {med:9.2f} {min(walls):8.2f} {size / 1e6 / med:8.0f} "
          f"{max(float(r['maxrss_mb']) for r in rs):11.0f} {statistics.median(loads) if loads else float('nan'):6.1f} {inner}")
