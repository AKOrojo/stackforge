"""Tests for the parallel columnar reader (stackforge.read_pcap_columns)."""

import struct

import pytest

np = pytest.importorskip("numpy")
import stackforge as sf  # noqa: E402

COLS = ["ts_us", "src", "dst", "sport", "dport", "proto", "ip_len",
        "hdr_len", "payload", "flags", "win", "icmp_type", "icmp_code"]
DTYPES = ["int64", "uint32", "uint32", "uint16", "uint16", "uint8", "int32",
          "int16", "int32", "uint8", "uint16", "uint8", "uint8"]


def eth(ethertype, payload):
    return b"\x02" + b"\x00" * 11 + struct.pack("!H", ethertype) + payload


def ipv4(proto, l4, frag=0):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, frag, 64, proto, 0,
                      bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    return hdr + l4


def tcp(sport, dport, flags, win, n_payload):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, win, 0, 0) + b"x" * n_payload


def write_pcap(path, records, endian="<", magic=0xA1B2C3D4):
    with open(path, "wb") as f:
        f.write(struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, 1))
        for sec, frac, data in records:
            f.write(struct.pack(endian + "IIII", sec, frac, len(data), len(data)) + data)


RECORDS = [
    (1_519_000_000, 123_456, eth(0x0800, ipv4(6, tcp(80, 1234, 0x12, 512, 10)))),
    (1_519_000_001, 999_999, eth(0x0800, ipv4(17, struct.pack("!HHHH", 53, 1024, 8, 0)))),
    (1_519_000_002, 0, eth(0x0806, b"\x00" * 28)),                          # non_ip
    (1_519_000_003, 0, eth(0x86DD, b"\x60\x00\x00\x00\x00\x00\x3b\x40" + b"\x00" * 32)),  # ipv6
    (1_519_000_004, 0, eth(0x0800, ipv4(6, tcp(1, 2, 0, 0, 0), frag=100))),  # fragment
    (1_519_000_005, 0, eth(0x0800, ipv4(47, b"\x00" * 8))),                 # other_l4
    (1_519_000_006, 0, b"\x00" * 10),                                       # parse_error
    (1_519_000_007, 5, eth(0x0800, ipv4(1, bytes([3, 1, 0, 0, 0, 0, 0, 0])))),
]


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("n_threads", [1, 3])
def test_columns_and_drops(tmp_path, endian, n_threads):
    p = tmp_path / "t.pcap"
    write_pcap(p, RECORDS, endian)
    cols, meta = sf.read_pcap_columns(str(p), n_threads=n_threads)
    assert list(cols) == COLS
    assert [str(cols[c].dtype) for c in COLS] == DTYPES
    assert meta["total_seen"] == 8 and not meta["truncated"]
    assert meta["dropped"] == {"non_ip": 1, "ipv6": 1, "other_l4": 1, "fragment": 1, "parse_error": 1}
    assert cols["ts_us"].tolist() == [1_519_000_000_123_456, 1_519_000_001_999_999, 1_519_000_007_000_005]
    assert cols["proto"].tolist() == [6, 17, 1]
    assert cols["payload"].tolist() == [10, 0, 0]
    assert (cols["flags"][0], cols["win"][0]) == (0x12, 512)
    assert (cols["icmp_type"][2], cols["icmp_code"][2]) == (3, 1)
    assert cols["src"][0] == 0x0A000001


def test_truncated(tmp_path):
    p = tmp_path / "t.pcap"
    write_pcap(p, RECORDS)
    data = p.read_bytes()
    p.write_bytes(data[:-3])
    cols, meta = sf.read_pcap_columns(str(p))
    assert meta["truncated"] and meta["total_seen"] == 8


def write_pcapng(path, records):
    def block(btype, body):
        body += b"\x00" * (-len(body) % 4)
        return struct.pack("<II", btype, 12 + len(body)) + body + struct.pack("<I", 12 + len(body))
    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack("<HHI", 1, 0, 65535))
    for sec, frac, data in records:
        t = sec * 1_000_000 + frac
        out += block(6, struct.pack("<IIIII", 0, t >> 32, t & 0xFFFFFFFF, len(data), len(data)) + data)
    path.write_bytes(out)


@pytest.mark.parametrize("n_threads", [1, 3])
def test_pcapng_matches_pcap(tmp_path, n_threads):
    a, b = tmp_path / "t.pcap", tmp_path / "t.pcapng"
    write_pcap(a, RECORDS)
    write_pcapng(b, RECORDS)
    ca, ma = sf.read_pcap_columns(str(a), n_threads=n_threads)
    cb, mb = sf.read_pcap_columns(str(b), n_threads=n_threads)
    assert mb["format"] == "pcapng" and mb["reference_error"] is None
    assert ma["dropped"] == mb["dropped"] and ma["total_seen"] == mb["total_seen"]
    for c in COLS:
        assert ca[c].tobytes() == cb[c].tobytes(), c


def test_pcapng_bad_header_rejected(tmp_path):
    p = tmp_path / "t.pcapng"
    p.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 28)
    with pytest.raises(OSError, match="pcapng"):
        sf.read_pcap_columns(str(p))
