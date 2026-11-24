"""Helpers around the parallel columnar pcap reader (`read_pcap_columns`)."""

from __future__ import annotations

from .stackforge import read_pcap_columns

PACKET_COLUMNS = (
    "ts_us", "src", "dst", "sport", "dport", "proto", "ip_len",
    "hdr_len", "payload", "flags", "win", "icmp_type", "icmp_code",
)


def read_pcap_dataframe(path, n_threads=None, **kw):
    """`read_pcap_columns` as a pandas DataFrame (columns in table order).

    `df.attrs` carries `dropped` and `total_seen` (as `offwire.pcap.read_pcap` does)
    plus the rest of the reader metadata (`truncated`, `truncation`, ...).
    Requires pandas.
    """
    import pandas as pd

    cols, meta = read_pcap_columns(str(path), n_threads=n_threads, **kw)
    df = pd.DataFrame({c: cols[c] for c in PACKET_COLUMNS}, copy=False)
    df.attrs.update(meta)
    return df
