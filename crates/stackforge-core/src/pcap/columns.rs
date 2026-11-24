//! Parallel, columnar PCAP / pcapng reader producing a flow-feature packet table.
//!
//! [`read_pcap_columns`] memory-maps a capture, cuts it into byte ranges and
//! decodes the ranges in parallel on a private Rayon pool (classic PCAP has
//! no index: each worker resynchronises on a record boundary and a serial
//! check proves the chunks tile the true record chain; see the driver). Each packet becomes one row
//! of 13 fixed-width columns (see [`COLUMN_NAMES`]); packets that are not
//! IPv4 TCP/UDP/ICMP are counted by drop reason instead.
//!
//! # Reference semantics
//!
//! The decoder reproduces, packet for packet, what the following `dpkt` 1.9.8
//! loop produces (the reference packet table used by CICFlowMeter-style flow
//! builders):
//!
//! ```text
//! eth = dpkt.ethernet.Ethernet(buf) if linktype == 1 else None
//! ip  = eth.data if linktype == 1 else dpkt.ip.IP(buf)
//! IP6 -> drop "ipv6";  not IP -> drop "non_ip";  ip.offset -> drop "fragment"
//! TCP/UDP/ICMP object as ip.data -> row;  anything else -> drop "other_l4"
//! any exception -> drop "parse_error"
//! ts_us = round(ts * 1e6)   (ts = sec + usec/1e6 as float, or Decimal for ns)
//! ```
//!
//! This includes dpkt's quirks: 802.1Q/QinQ/MPLS/ISL decapsulation, the L4
//! slice bounded by the IP total length, the L4 decision taken from the IPv4
//! protocol field (an ICMP error quoting a TCP header is ICMP), malformed L4
//! headers counted as `other_l4`, malformed IPv4/IPv6 headers behind an
//! Ethernet header counted as `non_ip`, and so on.
//!
//! # Truncated captures
//!
//! A final record whose packet data runs past end-of-file is decoded from the
//! bytes that are present (as dpkt does). A final record header that is cut
//! short stops the walk (dpkt raises in that case). Both set
//! [`PacketTable::truncated`].

use std::fs::File;
use std::path::Path;

use memmap2::Mmap;

use crate::error::{PacketError, Result};

/// Column names, in table order.
pub const COLUMN_NAMES: [&str; 13] = [
    "ts_us",
    "src",
    "dst",
    "sport",
    "dport",
    "proto",
    "ip_len",
    "hdr_len",
    "payload",
    "flags",
    "win",
    "icmp_type",
    "icmp_code",
];

/// Drop-reason names, in the order of the [`DropCounts`] fields.
pub const DROP_NAMES: [&str; 5] = ["non_ip", "ipv6", "other_l4", "fragment", "parse_error"];

/// Packets that produced no row, by reason.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DropCounts {
    /// Not IP (ARP, LLDP, STP, ...), or an IP/IPv6 header too malformed to decode.
    pub non_ip: u64,
    /// IPv6.
    pub ipv6: u64,
    /// IPv4 whose payload is not a decodable TCP/UDP/ICMP header.
    pub other_l4: u64,
    /// Non-first IPv4 fragment (fragment offset != 0).
    pub fragment: u64,
    /// Frame too malformed for the link-layer decoder.
    pub parse_error: u64,
}

impl DropCounts {
    fn add(&mut self, o: &Self) {
        self.non_ip += o.non_ip;
        self.ipv6 += o.ipv6;
        self.other_l4 += o.other_l4;
        self.fragment += o.fragment;
        self.parse_error += o.parse_error;
    }

    /// Counts in [`DROP_NAMES`] order.
    #[must_use]
    pub fn as_array(&self) -> [u64; 5] {
        [
            self.non_ip,
            self.ipv6,
            self.other_l4,
            self.fragment,
            self.parse_error,
        ]
    }
}

/// The 13 packet-table columns (one entry per kept packet, capture order).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PacketColumns {
    pub ts_us: Vec<i64>,
    pub src: Vec<u32>,
    pub dst: Vec<u32>,
    pub sport: Vec<u16>,
    pub dport: Vec<u16>,
    pub proto: Vec<u8>,
    pub ip_len: Vec<i32>,
    pub hdr_len: Vec<i16>,
    pub payload: Vec<i32>,
    pub flags: Vec<u8>,
    pub win: Vec<u16>,
    pub icmp_type: Vec<u8>,
    pub icmp_code: Vec<u8>,
}

impl PacketColumns {
    fn with_capacity(n: usize) -> Self {
        Self {
            ts_us: Vec::with_capacity(n),
            src: Vec::with_capacity(n),
            dst: Vec::with_capacity(n),
            sport: Vec::with_capacity(n),
            dport: Vec::with_capacity(n),
            proto: Vec::with_capacity(n),
            ip_len: Vec::with_capacity(n),
            hdr_len: Vec::with_capacity(n),
            payload: Vec::with_capacity(n),
            flags: Vec::with_capacity(n),
            win: Vec::with_capacity(n),
            icmp_type: Vec::with_capacity(n),
            icmp_code: Vec::with_capacity(n),
        }
    }

    /// Number of rows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ts_us.len()
    }

    /// True if the table has no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ts_us.is_empty()
    }

    #[inline]
    fn push(&mut self, ts: i64, r: &Row) {
        self.ts_us.push(ts);
        self.src.push(r.src);
        self.dst.push(r.dst);
        self.sport.push(r.sport);
        self.dport.push(r.dport);
        self.proto.push(r.proto);
        self.ip_len.push(r.ip_len);
        self.hdr_len.push(r.hdr_len);
        self.payload.push(r.payload);
        self.flags.push(r.flags);
        self.win.push(r.win);
        self.icmp_type.push(r.icmp_type);
        self.icmp_code.push(r.icmp_code);
    }
}

/// Result of [`read_pcap_columns`].
#[derive(Debug, Default, Clone)]
pub struct PacketTable {
    /// Kept packets, in capture order.
    pub columns: PacketColumns,
    /// Packets that produced no row, by reason.
    pub dropped: DropCounts,
    /// Records decoded (rows + drops).
    pub total_seen: u64,
    /// The capture ended inside a record.
    pub truncated: bool,
    /// Human-readable description of the truncation, if any.
    pub truncation: Option<String>,
    /// Set where the reference reader (dpkt) would raise instead of returning
    /// a table: a classic-pcap record header cut by end-of-file, or a
    /// malformed/truncated pcapng packet block. The table holds the packets
    /// before that point.
    pub reference_error: Option<String>,
    /// The input is pcapng (otherwise classic pcap).
    pub pcapng: bool,
    /// Link type (classic: global header; pcapng: first IDB).
    pub linktype: u32,
    /// Classic pcap with nanosecond timestamps.
    pub nanosecond: bool,
    /// Timestamp ticks per second (pcapng: from the first IDB's if_tsresol).
    pub ts_divisor: f64,
    /// Byte offset where decoding stopped (== file size for a complete file).
    pub bytes_consumed: u64,
    /// File size in bytes.
    pub file_size: u64,
    /// Number of byte-range chunks decoded in parallel.
    pub n_chunks: usize,
    /// Chunks whose boundary guess was wrong and were re-decoded serially.
    pub chunks_redecoded: usize,
    /// Worker threads used.
    pub n_threads: usize,
}

/// Tuning knobs for [`read_pcap_columns_with`].
#[derive(Debug, Clone, Copy)]
pub struct ColumnReaderOptions {
    /// Worker threads (None = all logical CPUs available to the process).
    pub n_threads: Option<usize>,
    /// Target chunk size in bytes of capture.
    pub chunk_bytes: usize,
    /// Drop the mapping of each chunk once decoded (`MADV_DONTNEED`) so the
    /// file pages do not accumulate in the process RSS. The page cache is not
    /// affected.
    pub release_pages: bool,
}

impl Default for ColumnReaderOptions {
    fn default() -> Self {
        Self {
            n_threads: None,
            chunk_bytes: 8 << 20,
            release_pages: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Global / record headers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Format {
    little: bool,
    nano: bool,
    rec_hdr_len: usize,
    linktype: u32,
}

#[inline]
fn rd32(b: &[u8], off: usize, little: bool) -> u32 {
    let a = [b[off], b[off + 1], b[off + 2], b[off + 3]];
    if little {
        u32::from_le_bytes(a)
    } else {
        u32::from_be_bytes(a)
    }
}

#[inline]
fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

#[inline]
fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Python-style slice `b[start:end]` (clamped, empty when start >= end).
#[inline]
fn pyslice(b: &[u8], start: usize, end: usize) -> &[u8] {
    let end = end.min(b.len());
    if start >= end { &[] } else { &b[start..end] }
}

#[inline]
fn tail(b: &[u8], start: usize) -> &[u8] {
    if start >= b.len() { &[] } else { &b[start..] }
}

fn parse_global_header(raw: &[u8]) -> Result<Format> {
    if raw.len() < 24 {
        return Err(PacketError::Io(format!(
            "file too small for a pcap global header ({} bytes)",
            raw.len()
        )));
    }
    // dpkt reads the magic big-endian and picks the byte order from it.
    let magic = be32(raw, 0);
    let (little, nano, rec_hdr_len) = match magic {
        0xA1B2_C3D4 => (false, false, 16),
        0xA1B2_3C4D => (false, true, 16),
        0xA1B2_CD34 => (false, false, 24), // Kuznetzov "modified" pcap
        0xD4C3_B2A1 => (true, false, 16),
        0x4D3C_B2A1 => (true, true, 16),
        0x34CD_B2A1 => (true, false, 24),
        _ => {
            return Err(PacketError::Io(format!("invalid pcap magic {magic:#010x}")));
        },
    };
    Ok(Format {
        little,
        nano,
        rec_hdr_len,
        linktype: rd32(raw, 20, little),
    })
}

/// `int(round(ts * 1_000_000))` exactly as Python computes it for dpkt's `ts`.
#[inline]
fn ts_to_us(sec: u32, frac: u32, nano: bool) -> i64 {
    if nano {
        // ts is a Decimal: sec + nsec/Decimal(1E9), exact; round() is half-even.
        let n = u64::from(sec) * 1_000_000_000 + u64::from(frac);
        let (q, r) = (n / 1000, n % 1000);
        let q = if r > 500 || (r == 500 && q % 2 == 1) {
            q + 1
        } else {
            q
        };
        q as i64
    } else {
        // ts is a float: sec + usec/1e6; round() is round-half-even on the double.
        let ts = f64::from(sec) + f64::from(frac) / 1e6;
        (ts * 1_000_000.0).round_ties_even() as i64
    }
}

// ---------------------------------------------------------------------------
// dpkt-compatible decoder
// ---------------------------------------------------------------------------

/// Which exception class a dpkt constructor would raise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exc {
    /// `dpkt.UnpackError` (incl. `NeedData`): caught by the parent's dispatch.
    Unpack,
    /// Anything else (e.g. `IndexError`): propagates to the top level.
    Other,
}

#[derive(Debug, Clone, Copy)]
enum L4 {
    Tcp {
        sport: u16,
        dport: u16,
        off: u8,
        flags: u8,
        win: u16,
    },
    Udp {
        sport: u16,
        dport: u16,
    },
    Icmp {
        typ: u8,
        code: u8,
    },
    Other,
}

#[derive(Debug, Clone, Copy)]
struct Ip4 {
    hl: u8,
    len: u16,
    offset: u16,
    src: u32,
    dst: u32,
    l4: L4,
}

/// What `Ethernet.data` ends up holding.
#[derive(Debug, Clone, Copy)]
enum Data<'a> {
    Bytes(&'a [u8]),
    Ip(Ip4),
    Ip6,
    /// Any other decoded object (ARP, LLC, nested Ethernet, ...).
    Obj,
}

/// `dpkt.ip.IP(buf)`. Only raises `UnpackError` (every child parser dpkt
/// registers raises `UnpackError` on malformed input, and those are caught).
#[inline]
fn ip4(buf: &[u8]) -> Option<Ip4> {
    if buf.len() < 20 {
        return None;
    }
    let hl = buf[0] & 0x0f;
    if hl < 5 {
        return None;
    }
    let len = be16(buf, 2);
    let offset = be16(buf, 6) & 0x1fff;
    let p = buf[9];
    let start = usize::from(hl) * 4;
    let l4buf = if len != 0 {
        pyslice(buf, start, usize::from(len))
    } else {
        tail(buf, start)
    };
    let l4 = if offset != 0 {
        L4::Other
    } else {
        match p {
            6 if l4buf.len() >= 20 && (l4buf[12] >> 4) >= 5 => L4::Tcp {
                sport: be16(l4buf, 0),
                dport: be16(l4buf, 2),
                off: l4buf[12] >> 4,
                flags: l4buf[13],
                win: be16(l4buf, 14),
            },
            17 if l4buf.len() >= 8 => L4::Udp {
                sport: be16(l4buf, 0),
                dport: be16(l4buf, 2),
            },
            // ICMP: the 4-byte header is all that can fail; the quoted
            // payload parse is wrapped in dpkt's try.
            1 if l4buf.len() >= 4 => L4::Icmp {
                typ: l4buf[0],
                code: l4buf[1],
            },
            _ => L4::Other,
        }
    };
    Some(Ip4 {
        hl,
        len,
        offset,
        src: be32(buf, 12),
        dst: be32(buf, 16),
        l4,
    })
}

/// `dpkt.ip6.IP6(buf)` succeeds (true) or raises `UnpackError` (false).
fn ip6_ok(buf: &[u8]) -> bool {
    if buf.len() < 40 {
        return false;
    }
    let plen = usize::from(be16(buf, 4));
    let data = &buf[40..];
    let mut b = if plen != 0 {
        pyslice(data, 0, plen)
    } else {
        data
    };
    let mut next = buf[6];
    loop {
        match next {
            0 | 60 => {
                // IP6OptsHeader: walks the options; IndexError -> NeedData.
                if b.len() < 2 {
                    return false;
                }
                let length = (usize::from(b[1]) + 1) * 8;
                let d = &b[2..];
                let mut i = 0usize;
                while i < length - 2 {
                    if i >= d.len() {
                        return false;
                    }
                    if d[i] == 0 {
                        i += 1;
                        continue;
                    }
                    if i + 1 >= d.len() {
                        return false;
                    }
                    i += usize::from(d[i + 1]) + 2;
                }
                next = b[0];
                b = tail(b, length);
            },
            43 => {
                if b.len() < 8 {
                    return false;
                }
                let length = usize::from(b[1]) * 8 + 8;
                next = b[0];
                b = tail(b, length);
            },
            44 => {
                if b.len() < 8 {
                    return false;
                }
                next = b[0];
                b = tail(b, 8);
            },
            51 => {
                if b.len() < 12 {
                    return false;
                }
                let length = (usize::from(b[1]) + 2) * 4;
                next = b[0];
                b = tail(b, length);
            },
            // ESP has no next-header field: the chain ends; the upper-layer
            // dispatch then fails with KeyError, which is caught.
            50 => return b.len() >= 8,
            _ => return true,
        }
    }
}

/// `Ethernet._typesw[t](buf)`; `Err(Unpack)` also stands for `KeyError`.
fn eth_dispatch(t: u16, buf: &[u8]) -> std::result::Result<Data<'_>, Exc> {
    match t {
        0x0800 => ip4(buf).map(Data::Ip).ok_or(Exc::Unpack),
        0x86DD => {
            if ip6_ok(buf) {
                Ok(Data::Ip6)
            } else {
                Err(Exc::Unpack)
            }
        },
        0x6558 => ethernet(buf).map(|_| Data::Obj),
        // EDP, ARP, AoE, CDP, DTP, IPX, PPP, PPPoE: whether they decode or
        // not, the result is "not IP" and nothing escapes.
        0x00BB | 0x0806 | 0x88A2 | 0x2000 | 0x2004 | 0x8137 | 0x880B | 0x8864 => Ok(Data::Obj),
        _ => Err(Exc::Unpack), // KeyError
    }
}

struct EthState<'a> {
    typ: u16,
    next_type: Option<u16>,
    data: Data<'a>,
}

const QINQ: [u16; 4] = [0x8100, 0x88A8, 0x9100, 0x9200];

/// `Ethernet._unpack_data(buf)`.
fn eth_unpack_data<'a>(st: &mut EthState<'a>, buf: &'a [u8]) -> std::result::Result<(), Exc> {
    let mut buf = buf;
    match st.next_type {
        Some(nt) if QINQ.contains(&nt) => {
            for _ in 0..2 {
                if buf.len() < 4 {
                    return Err(Exc::Unpack);
                }
                let t = be16(buf, 2);
                buf = &buf[4..];
                st.next_type = Some(t);
                if t != 0x8100 {
                    break;
                }
            }
        },
        Some(0x8847 | 0x8848) => {
            for _ in 0..24 {
                if buf.len() < 4 {
                    return Err(Exc::Unpack);
                }
                let v = be32(buf, 0);
                buf = &buf[4..];
                if (v >> 8) & 1 == 1 {
                    break;
                }
            }
            if buf.is_empty() {
                return Err(Exc::Other); // IndexError on buf[0]
            }
            if buf[0] == 0x45 {
                st.next_type = Some(0x0800);
            } else if buf[0] & 0xf0 == 0x60 {
                st.next_type = Some(0x86DD);
            } else if buf.len() >= 14 {
                if buf[0] == 0 && buf[1] == 0 {
                    buf = &buf[4..];
                }
                st.next_type = Some(0x6558);
            }
        },
        _ => {},
    }
    let eth_type = match st.next_type {
        Some(t) if t != 0 => t,
        _ => st.typ,
    };
    st.data = match eth_dispatch(eth_type, buf) {
        Ok(d) => d,
        Err(Exc::Unpack) => Data::Bytes(buf),
        Err(Exc::Other) => return Err(Exc::Other),
    };
    Ok(())
}

/// `llc.LLC(buf)`: only whether (and how) it raises matters.
fn llc(buf: &[u8]) -> std::result::Result<(), Exc> {
    if buf.len() < 3 {
        return Err(Exc::Unpack);
    }
    let (dsap, ssap) = (buf[0], buf[1]);
    let d = &buf[3..];
    if dsap == 0xAA && ssap == 0xAA {
        if d.len() < 5 {
            return Err(Exc::Unpack); // struct.error -> UnpackError
        }
        match eth_dispatch(be16(d, 3), &d[5..]) {
            Err(Exc::Other) => return Err(Exc::Other),
            _ => {},
        }
    } else if dsap == 0x06 {
        ip4(d).ok_or(Exc::Unpack)?;
    } else if (dsap == 0x10 || dsap == 0xE0) && d.len() < 30 {
        return Err(Exc::Unpack); // IPX header
    } else if dsap == 0x42 && d.len() < 35 {
        return Err(Exc::Unpack); // STP header
    }
    Ok(())
}

/// `Ethernet.unpack(buf)`.
fn eth_unpack<'a>(st: &mut EthState<'a>, buf: &'a [u8]) -> std::result::Result<(), Exc> {
    if buf.len() < 14 {
        return Err(Exc::Unpack);
    }
    st.typ = be16(buf, 12);
    let data = &buf[14..];
    st.data = Data::Bytes(data);
    if st.typ > 1500 {
        st.next_type = Some(st.typ);
        eth_unpack_data(st, data)
    } else if buf[1..5] == [0x00, 0x0C, 0x00, 0x00] && (buf[0] == 0x01 || buf[0] == 0x03) {
        // Cisco ISL: 26-byte tag, then the encapsulated frame.
        if buf.len() < 26 {
            return Err(Exc::Unpack);
        }
        eth_unpack(st, &buf[26..])
    } else if data.len() >= 2 && data[0] == 0xFF && data[1] == 0xFF {
        if data.len() - 2 < 30 {
            return Err(Exc::Unpack); // raw 802.3 IPX
        }
        st.data = Data::Obj;
        Ok(())
    } else if st.typ == 0 {
        eth_unpack_data(st, data)
    } else {
        llc(pyslice(data, 0, usize::from(st.typ)))?;
        st.data = Data::Obj;
        Ok(())
    }
}

/// `dpkt.ethernet.Ethernet(buf)` -> what `.data` holds.
fn ethernet(buf: &[u8]) -> std::result::Result<Data<'_>, Exc> {
    let mut st = EthState {
        typ: 0,
        next_type: None,
        data: Data::Bytes(&[]),
    };
    eth_unpack(&mut st, buf)?;
    // Ethernet.__init__ re-runs _unpack_data when .data is still raw bytes.
    if let Data::Bytes(b) = st.data {
        if !b.is_empty() {
            eth_unpack_data(&mut st, b)?;
        }
    }
    Ok(st.data)
}

struct Row {
    src: u32,
    dst: u32,
    sport: u16,
    dport: u16,
    proto: u8,
    ip_len: i32,
    hdr_len: i16,
    payload: i32,
    flags: u8,
    win: u16,
    icmp_type: u8,
    icmp_code: u8,
}

enum Outcome {
    Row(Row),
    NonIp,
    Ipv6,
    OtherL4,
    Fragment,
    ParseError,
}

#[inline]
fn classify(buf: &[u8], linktype: u32) -> Outcome {
    let ip = if linktype == 1 {
        // Fast path, equivalent to the general one: for EtherType 0x0800 the
        // dispatch is IP(buf[14:]); on UnpackError .data stays bytes and the
        // __init__ re-dispatch fails identically, i.e. "not IP".
        if buf.len() >= 14 && buf[12] == 0x08 && buf[13] == 0x00 {
            match ip4(&buf[14..]) {
                Some(ip) => ip,
                None => return Outcome::NonIp,
            }
        } else {
            match ethernet(buf) {
                Err(_) => return Outcome::ParseError,
                Ok(Data::Ip6) => return Outcome::Ipv6,
                Ok(Data::Ip(ip)) => ip,
                Ok(_) => return Outcome::NonIp,
            }
        }
    } else {
        match ip4(buf) {
            None => return Outcome::ParseError,
            Some(ip) => ip,
        }
    };
    if ip.offset != 0 {
        return Outcome::Fragment;
    }
    let ip_len = i32::from(ip.len);
    let ihl = i32::from(ip.hl) * 4;
    match ip.l4 {
        L4::Tcp {
            sport,
            dport,
            off,
            flags,
            win,
        } => {
            let thl = i32::from(off) * 4;
            Outcome::Row(Row {
                src: ip.src,
                dst: ip.dst,
                sport,
                dport,
                proto: 6,
                ip_len,
                hdr_len: thl as i16,
                payload: (ip_len - ihl - thl).max(0),
                flags,
                win,
                icmp_type: 0,
                icmp_code: 0,
            })
        },
        L4::Udp { sport, dport } => Outcome::Row(Row {
            src: ip.src,
            dst: ip.dst,
            sport,
            dport,
            proto: 17,
            ip_len,
            hdr_len: 8,
            payload: (ip_len - ihl - 8).max(0),
            flags: 0,
            win: 0,
            icmp_type: 0,
            icmp_code: 0,
        }),
        L4::Icmp { typ, code } => Outcome::Row(Row {
            src: ip.src,
            dst: ip.dst,
            sport: 0,
            dport: 0,
            proto: 1,
            ip_len,
            hdr_len: 8,
            payload: 0,
            flags: 0,
            win: 0,
            icmp_type: typ,
            icmp_code: code,
        }),
        L4::Other => Outcome::OtherL4,
    }
}

// ---------------------------------------------------------------------------
// Parallel driver: split by bytes, resync, decode, verify
// ---------------------------------------------------------------------------
//
// Classic pcap has no index, and a serial header walk over a multi-GB file
// is itself several seconds of page faults and dependent loads. Instead the
// file is cut into fixed byte ranges; each worker finds a plausible record
// boundary in its range (`resync`) and decodes every record that *starts*
// inside the range, stopping at the first record boundary at or past the
// range end. Correctness never depends on the resync heuristic: a serial
// pass then checks, by induction from the true first record at offset 24,
// that every chunk started exactly where the previous chunk's record chain
// ended, and re-decodes any chunk that did not.

struct ChunkOut {
    /// Offset of the first record decoded.
    start: usize,
    /// Offset just past the last record decoded.
    end: usize,
    cols: PacketColumns,
    dropped: DropCounts,
    seen: u64,
    truncation: Option<String>,
    /// The reference reader (dpkt) raises at this point.
    ref_error: Option<String>,
}

/// Records whose header starts in `[start, stop)`, following the chain from `start`.
fn decode_range(raw: &[u8], fmt: Format, start: usize, stop: usize) -> ChunkOut {
    let cap = (stop.saturating_sub(start)) / 64 + 16;
    let mut cols = PacketColumns::with_capacity(cap);
    let mut dropped = DropCounts::default();
    let mut truncation = None;
    let mut ref_error = None;
    let mut off = start;
    let mut seen = 0u64;
    let h = fmt.rec_hdr_len;
    while off < stop {
        let rem = raw.len() - off;
        if rem < h {
            truncation = Some(format!(
                "capture ends inside a record header at offset {off} ({rem} of {h} bytes)"
            ));
            ref_error = truncation.clone(); // dpkt.pcap.Reader raises NeedData
            break;
        }
        let sec = rd32(raw, off, fmt.little);
        let frac = rd32(raw, off + 4, fmt.little);
        let caplen = rd32(raw, off + 8, fmt.little) as usize;
        let ds = off + h;
        let avail = raw.len() - ds;
        let de = if caplen > avail {
            truncation = Some(format!(
                "last record at offset {off} claims {caplen} bytes but only {avail} remain; \
                 decoded from the bytes present"
            ));
            raw.len()
        } else {
            ds + caplen
        };
        seen += 1;
        match classify(&raw[ds..de], fmt.linktype) {
            Outcome::Row(r) => cols.push(ts_to_us(sec, frac, fmt.nano), &r),
            Outcome::NonIp => dropped.non_ip += 1,
            Outcome::Ipv6 => dropped.ipv6 += 1,
            Outcome::OtherL4 => dropped.other_l4 += 1,
            Outcome::Fragment => dropped.fragment += 1,
            Outcome::ParseError => dropped.parse_error += 1,
        }
        off = de;
        if truncation.is_some() {
            break;
        }
    }
    ChunkOut {
        start,
        end: off,
        cols,
        dropped,
        seen,
        truncation,
        ref_error,
    }
}

/// Header at `off` looks like a real record: returns the next record offset.
#[inline]
fn plausible(raw: &[u8], fmt: Format, off: usize, cap_max: usize, sec_ref: u32) -> Option<usize> {
    if off + fmt.rec_hdr_len > raw.len() {
        return None;
    }
    // Within ~400 days of the first record: rejects fake "headers" inside
    // runs of identical packets, which chain consistently otherwise.
    if rd32(raw, off, fmt.little).abs_diff(sec_ref) > 400 * 86_400 {
        return None;
    }
    let frac = rd32(raw, off + 4, fmt.little);
    let caplen = rd32(raw, off + 8, fmt.little) as usize;
    let orig = rd32(raw, off + 12, fmt.little) as usize;
    let frac_max = if fmt.nano { 1_000_000_000 } else { 1_000_000 };
    if frac >= frac_max || caplen > cap_max || caplen > orig {
        return None;
    }
    let next = off + fmt.rec_hdr_len + caplen;
    (next <= raw.len()).then_some(next)
}

/// First offset in `[from, to)` that starts a chain of 8 plausible records
/// (or a shorter chain ending exactly at end-of-file).
fn resync(
    raw: &[u8],
    fmt: Format,
    from: usize,
    to: usize,
    cap_max: usize,
    sec_ref: u32,
) -> Option<usize> {
    'cand: for o in from..to {
        let mut p = o;
        for _ in 0..8 {
            if p == raw.len() {
                break;
            }
            match plausible(raw, fmt, p, cap_max, sec_ref) {
                Some(n) => p = n,
                None => continue 'cand,
            }
        }
        return Some(o);
    }
    None
}

// ---------------------------------------------------------------------------
// pcapng, as dpkt 1.9.8's `dpkt.pcapng.Reader` reads it
// ---------------------------------------------------------------------------
//
// dpkt's reader is much narrower than the pcapng spec, and the reference
// table follows it, so this does too (the crate's spec-conforming pcapng
// reader in `reader.rs` is therefore not reused for the table):
//   * the byte order of the FIRST section header applies to the whole file
//     (later SHBs are skipped like any other block);
//   * the FIRST interface description block gives the link type, the
//     timestamp divisor (`if_tsresol`, default 1e6) and `if_tsoffset` for
//     every packet; `iface_id` and later IDBs are ignored;
//   * only Enhanced (6) and obsolete Packet (2) blocks are yielded; Simple
//     Packet, Interface Statistics, ... blocks and any packet block before
//     the first IDB are skipped;
//   * ts = if_tsoffset + ((ts_high << 32) | ts_low) / divisor (float);
//   * a malformed or truncated packet block raises (the whole read fails);
//     fewer than 8 trailing bytes end the file silently.

/// Global state fixed by the section header and the first IDB.
#[derive(Debug, Clone, Copy)]
struct NgFormat {
    le: bool,
    divisor: f64,
    tsoffset: i64,
    linktype: u32,
    /// Offset of the first block after the first IDB.
    first: usize,
    /// Seconds of the first packet block (resync plausibility only).
    sec_ref: Option<f64>,
}

#[inline]
fn rd16(b: &[u8], off: usize, little: bool) -> u16 {
    let a = [b[off], b[off + 1]];
    if little {
        u16::from_le_bytes(a)
    } else {
        u16::from_be_bytes(a)
    }
}

/// End offset of `f.read(n)` issued at `pos` (a negative `n` reads to EOF).
#[inline]
fn py_read_end(len: usize, pos: usize, n: i64) -> usize {
    if n < 0 {
        len
    } else {
        (pos as u64).saturating_add(n as u64).min(len as u64) as usize
    }
}

/// Python `b[start:end]` with possibly negative bounds.
#[inline]
fn pyslice_i(b: &[u8], start: i64, end: i64) -> &[u8] {
    let n = b.len() as i64;
    let norm = |x: i64| if x < 0 { (x + n).max(0) } else { x.min(n) };
    let (s, e) = (norm(start), norm(end));
    if s >= e {
        &[]
    } else {
        &b[s as usize..e as usize]
    }
}

/// `_PcapngBlock._do_unpack_options(buf, oo)`: calls `on_opt` per option, or
/// returns the reason dpkt raises.
fn ng_options<'a>(
    buf: &'a [u8],
    oo: i64,
    len: i64,
    le: bool,
    mut on_opt: impl FnMut(u16, &'a [u8]),
) -> std::result::Result<(), &'static str> {
    let ol = len - oo - 4;
    let mut ob = pyslice_i(buf, oo, oo + ol);
    while !ob.is_empty() {
        if ob.len() < 4 {
            return Err("option header cut short");
        }
        let code = rd16(ob, 0, le);
        let data = pyslice(ob, 4, 4 + usize::from(rd16(ob, 2, le)));
        if code == 1 && std::str::from_utf8(data).is_err() {
            // dpkt: utf-8, else ascii up to the first NUL, else raise.
            match data.iter().position(|&c| c == 0) {
                Some(i) if data[..i].is_ascii() => {},
                _ => return Err("comment option is not valid UTF-8"),
            }
        }
        on_opt(code, data);
        ob = tail(ob, 4 + data.len().div_ceil(4) * 4);
        if code == 0 {
            break;
        }
    }
    if buf.len() < 4 {
        return Err("block shorter than 4 bytes");
    }
    if i64::from(rd32(buf, buf.len() - 4, le)) != len {
        return Err("length fields do not match");
    }
    Ok(())
}

const NG_PAST_EOF: &str = "packet block runs past end of file";

/// `EnhancedPacketBlock(buf)` / `PacketBlock(buf)`: (timestamp ticks, packet data).
#[inline]
fn ng_packet(buf: &[u8], le: bool) -> std::result::Result<(u64, &[u8]), &'static str> {
    if buf.len() < 32 {
        return Err("packet block shorter than its 32-byte header");
    }
    let len = i64::from(rd32(buf, 4, le));
    if len > buf.len() as i64 {
        return Err(NG_PAST_EOF);
    }
    let caplen = rd32(buf, 20, le) as usize;
    let pkt = pyslice(buf, 28, 28 + caplen);
    let oo = 28 + (caplen as i64 + 3) / 4 * 4;
    ng_options(buf, oo, len, le, |_, _| {})?;
    let t = (u64::from(rd32(buf, 12, le)) << 32) | u64::from(rd32(buf, 16, le));
    Ok((t, pkt))
}

/// `dpkt.pcapng.Reader.__init__`: errors are the cases where it raises.
fn parse_pcapng_header(raw: &[u8]) -> Result<NgFormat> {
    let rej = |m: &str| {
        PacketError::Io(format!(
            "pcapng: rejected (dpkt.pcapng.Reader raises too): {m}"
        ))
    };
    if raw.len() < 28 {
        return Err(rej("file shorter than a section header block"));
    }
    let le = match be32(raw, 8) {
        0x1A2B_3C4D => false,
        0x4D3C_2B1A => true,
        _ => return Err(rej("unknown byte-order magic")),
    };
    let len = i64::from(rd32(raw, 4, le));
    let end = py_read_end(raw.len(), 28, len - 28);
    let shb = &raw[..end];
    if len > shb.len() as i64 {
        return Err(rej("section header block runs past end of file"));
    }
    ng_options(shb, 24, len, le, |_, _| {}).map_err(rej)?;
    if rd16(raw, 12, le) != 1 {
        return Err(rej("unsupported pcapng major version"));
    }
    let mut pos = end;
    loop {
        if raw.len() - pos < 8 {
            return Err(rej("IDB not found"));
        }
        let bt = rd32(raw, pos, le);
        let e = py_read_end(raw.len(), pos + 8, i64::from(rd32(raw, pos + 4, le)) - 8);
        let buf = &raw[pos..e];
        pos = e;
        if bt != 1 {
            continue;
        }
        if buf.len() < 20 {
            return Err(rej("interface description block shorter than its header"));
        }
        let len = i64::from(rd32(buf, 4, le));
        if len > buf.len() as i64 {
            return Err(rej("interface description block runs past end of file"));
        }
        let (mut divisor, mut tsoffset, mut bad) = (1e6f64, 0i64, None);
        ng_options(buf, 16, len, le, |code, data| match code {
            9 if data.len() != 1 => bad = Some("if_tsresol option is not 1 byte"),
            9 => {
                let e = i32::from(data[0] & 0x7f);
                divisor = if data[0] & 0x80 != 0 {
                    2f64.powi(e)
                } else {
                    // float(10 ** e), correctly rounded
                    format!("1e{e}").parse().unwrap_or(f64::INFINITY)
                };
            },
            14 if data.len() != 8 => bad = Some("if_tsoffset option is not 8 bytes"),
            14 => {
                let a: [u8; 8] = data.try_into().unwrap_or([0; 8]);
                tsoffset = if le {
                    i64::from_le_bytes(a)
                } else {
                    i64::from_be_bytes(a)
                };
            },
            _ => {},
        })
        .map_err(rej)?;
        if let Some(m) = bad {
            return Err(rej(m));
        }
        let mut ng = NgFormat {
            le,
            divisor,
            tsoffset,
            linktype: u32::from(rd16(buf, 8, le)),
            first: pos,
            sec_ref: None,
        };
        // First packet block's time, for the resync plausibility test.
        let mut p = pos;
        for _ in 0..10_000 {
            if raw.len() - p < 8 {
                break;
            }
            let bt = rd32(raw, p, le);
            let e = py_read_end(raw.len(), p + 8, i64::from(rd32(raw, p + 4, le)) - 8);
            if bt == 6 || bt == 2 {
                if let Ok((t, _)) = ng_packet(&raw[p..e], le) {
                    ng.sec_ref = Some(ng.ts_secs(t));
                }
                break;
            }
            p = e;
        }
        return Ok(ng);
    }
}

impl NgFormat {
    #[inline]
    fn ts_secs(&self, t: u64) -> f64 {
        // Python: int + int/float  ->  float(tsoffset) + float(t)/divisor
        self.tsoffset as f64 + (t as f64) / self.divisor
    }
}

/// Blocks starting in `[start, stop)`, following dpkt's block chain from `start`.
fn decode_range_ng(raw: &[u8], ng: NgFormat, start: usize, stop: usize) -> ChunkOut {
    let cap = (stop.saturating_sub(start)) / 64 + 16;
    let mut cols = PacketColumns::with_capacity(cap);
    let mut dropped = DropCounts::default();
    let (mut truncation, mut ref_error) = (None, None);
    let mut off = start;
    let mut seen = 0u64;
    while off < stop {
        let rem = raw.len() - off;
        if rem < 8 {
            truncation = Some(format!(
                "{rem} trailing bytes after the last block at offset {off} (ignored, as dpkt does)"
            ));
            break;
        }
        let bt = rd32(raw, off, ng.le);
        let e = py_read_end(raw.len(), off + 8, i64::from(rd32(raw, off + 4, ng.le)) - 8);
        if bt == 6 || bt == 2 {
            match ng_packet(&raw[off..e], ng.le) {
                Ok((t, pkt)) => {
                    seen += 1;
                    match classify(pkt, ng.linktype) {
                        Outcome::Row(r) => {
                            let f = (ng.ts_secs(t) * 1_000_000.0).round_ties_even();
                            if !(-9.223_372_036_854_776e18..9.223_372_036_854_776e18).contains(&f) {
                                ref_error = Some(format!(
                                    "timestamp of the packet block at offset {off} does not fit \
                                     int64 microseconds (the reference table cannot hold it)"
                                ));
                                break;
                            }
                            cols.push(f as i64, &r);
                        },
                        Outcome::NonIp => dropped.non_ip += 1,
                        Outcome::Ipv6 => dropped.ipv6 += 1,
                        Outcome::OtherL4 => dropped.other_l4 += 1,
                        Outcome::Fragment => dropped.fragment += 1,
                        Outcome::ParseError => dropped.parse_error += 1,
                    }
                },
                Err(m) => {
                    let msg =
                        format!("{m} (block at offset {off}); dpkt.pcapng.Reader raises here");
                    if m == NG_PAST_EOF {
                        truncation = Some(msg.clone());
                    }
                    ref_error = Some(msg);
                    break;
                },
            }
        }
        off = e;
    }
    ChunkOut {
        start,
        end: off,
        cols,
        dropped,
        seen,
        truncation,
        ref_error,
    }
}

/// Block at `p` looks real (trailing length copy matches, sane fields).
#[inline]
fn plausible_ng(raw: &[u8], ng: NgFormat, p: usize) -> Option<usize> {
    if raw.len() - p < 12 {
        return None;
    }
    let bt = rd32(raw, p, ng.le);
    let bl = rd32(raw, p + 4, ng.le) as usize;
    if bl < 12 || bl % 4 != 0 || bl > raw.len() - p || rd32(raw, p + bl - 4, ng.le) as usize != bl {
        return None;
    }
    match bt {
        6 | 2 => {
            if bl < 32 || rd32(raw, p + 20, ng.le) as usize > bl - 32 {
                return None;
            }
            if let Some(r) = ng.sec_ref {
                let t = (u64::from(rd32(raw, p + 12, ng.le)) << 32)
                    | u64::from(rd32(raw, p + 16, ng.le));
                if (ng.ts_secs(t) - r).abs() > 400.0 * 86_400.0 {
                    return None;
                }
            }
        },
        1 | 3 | 4 | 5 | 7 | 0x0A0D_0D0A => {},
        _ => return None,
    }
    Some(p + bl)
}

fn resync_ng(raw: &[u8], ng: NgFormat, from: usize, to: usize) -> Option<usize> {
    // Candidates share the first block's alignment (blocks are 4-byte multiples).
    let from = from + (ng.first % 4 + 4 - from % 4) % 4;
    'cand: for o in (from..to).step_by(4) {
        let mut p = o;
        for _ in 0..8 {
            if p == raw.len() {
                break;
            }
            match plausible_ng(raw, ng, p) {
                Some(n) => p = n,
                None => continue 'cand,
            }
        }
        return Some(o);
    }
    None
}

/// Container-specific parts of the driver.
#[derive(Debug, Clone, Copy)]
enum Container {
    Pcap {
        fmt: Format,
        cap_max: usize,
        sec_ref: u32,
    },
    Ng(NgFormat),
}

impl Container {
    fn first(&self) -> usize {
        match self {
            Self::Pcap { .. } => 24,
            Self::Ng(ng) => ng.first,
        }
    }

    fn decode(&self, raw: &[u8], start: usize, stop: usize) -> ChunkOut {
        match *self {
            Self::Pcap { fmt, .. } => decode_range(raw, fmt, start, stop),
            Self::Ng(ng) => decode_range_ng(raw, ng, start, stop),
        }
    }

    fn resync(&self, raw: &[u8], from: usize, to: usize) -> Option<usize> {
        match *self {
            Self::Pcap {
                fmt,
                cap_max,
                sec_ref,
            } => resync(raw, fmt, from, to, cap_max, sec_ref),
            Self::Ng(ng) => resync_ng(raw, ng, from, to),
        }
    }
}

#[cfg(unix)]
fn release(mmap: &Mmap, start: usize, end: usize) {
    // Only whole pages strictly inside [start, end) are released.
    const PAGE: usize = 4096;
    let a = start.div_ceil(PAGE) * PAGE;
    let b = end / PAGE * PAGE;
    if b > a {
        // SAFETY: the mapping is read-only and file-backed; MADV_DONTNEED only
        // drops this process's page-table entries, later reads re-fault the
        // same file contents from the page cache.
        unsafe {
            let _ = mmap.unchecked_advise_range(memmap2::UncheckedAdvice::DontNeed, a, b - a);
        }
    }
}

#[cfg(not(unix))]
fn release(_mmap: &Mmap, _start: usize, _end: usize) {}

/// Concatenate one column of every chunk into a single vector, freeing the
/// chunk columns as it goes (peak = table + one column).
fn concat<T: Copy + Send + Sync>(
    parts: &mut [ChunkOut],
    total: usize,
    get: impl Fn(&mut PacketColumns) -> &mut Vec<T> + Sync,
) -> Vec<T> {
    use rayon::prelude::*;
    let mut out: Vec<T> = Vec::with_capacity(total);
    {
        let spare = &mut out.spare_capacity_mut()[..total];
        let mut slices = Vec::with_capacity(parts.len());
        let mut rest = spare;
        for p in parts.iter_mut() {
            let n = get(&mut p.cols).len();
            let (head, r) = rest.split_at_mut(n);
            slices.push((head, p));
            rest = r;
        }
        slices.into_par_iter().for_each(|(dst, p)| {
            let v = std::mem::take(get(&mut p.cols));
            for (d, s) in dst.iter_mut().zip(v.iter()) {
                d.write(*s);
            }
        });
    }
    // SAFETY: every one of the `total` slots was written above.
    unsafe { out.set_len(total) };
    out
}

/// Read a classic pcap or pcapng file into the 13-column packet table (see module docs).
pub fn read_pcap_columns(path: impl AsRef<Path>, n_threads: Option<usize>) -> Result<PacketTable> {
    read_pcap_columns_with(
        path,
        ColumnReaderOptions {
            n_threads,
            ..Default::default()
        },
    )
}

/// [`read_pcap_columns`] with explicit options.
pub fn read_pcap_columns_with(
    path: impl AsRef<Path>,
    opts: ColumnReaderOptions,
) -> Result<PacketTable> {
    let path = path.as_ref();
    let file = File::open(path)
        .map_err(|e| PacketError::Io(format!("failed to open {}: {e}", path.display())))?;
    // SAFETY: read-only mapping; the capture must not be modified while read.
    let mmap = unsafe { Mmap::map(&file) }
        .map_err(|e| PacketError::Io(format!("failed to mmap {}: {e}", path.display())))?;
    let raw: &[u8] = &mmap;
    let cont = if raw.len() >= 4 && be32(raw, 0) == 0x0A0D_0D0A {
        Container::Ng(parse_pcapng_header(raw)?)
    } else {
        let fmt = parse_global_header(raw)?;
        let snaplen = rd32(raw, 16, fmt.little) as usize;
        Container::Pcap {
            fmt,
            cap_max: if (1..=(1 << 20)).contains(&snaplen) {
                snaplen.max(65_535)
            } else {
                262_144
            },
            sec_ref: if raw.len() >= 28 {
                rd32(raw, 24, fmt.little)
            } else {
                0
            },
        }
    };
    let first = cont.first();

    let n_threads = opts
        .n_threads
        .filter(|&n| n > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()));
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(n_threads)
        .thread_name(|i| format!("sf-pcapcols-{i}"))
        .build()
        .map_err(|e| PacketError::Io(format!("failed to build thread pool: {e}")))?;

    let timing = std::env::var_os("STACKFORGE_COLUMNS_TIMING").is_some();
    let t0 = std::time::Instant::now();

    // Byte ranges [bounds[i], bounds[i+1]).
    let chunk_bytes = opts.chunk_bytes.max(1 << 16);
    let mut bounds: Vec<usize> = (first..raw.len()).step_by(chunk_bytes).collect();
    bounds.push(raw.len());
    let n_ranges = bounds.len() - 1;

    // Workers take chunks in file order (atomic counter) so that all threads
    // read neighbouring regions: friendlier to readahead on a cold cache than
    // rayon's recursive range splitting.
    let next = std::sync::atomic::AtomicUsize::new(0);
    let slots: Vec<std::sync::OnceLock<Option<ChunkOut>>> =
        (0..n_ranges).map(|_| std::sync::OnceLock::new()).collect();
    pool.scope(|s| {
        for _ in 0..n_threads {
            s.spawn(|_| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if i >= n_ranges {
                        break;
                    }
                    let (a, b) = (bounds[i], bounds[i + 1]);
                    let st = if i == 0 {
                        Some(a)
                    } else {
                        cont.resync(raw, a, b)
                    };
                    let out = st.map(|st| cont.decode(raw, st, b));
                    if opts.release_pages {
                        release(&mmap, a, b);
                    }
                    let _ = slots[i].set(out);
                }
            });
        }
    });
    let mut parts: Vec<Option<ChunkOut>> = slots
        .into_iter()
        .map(|c| c.into_inner().expect("every chunk visited"))
        .collect();
    let t_decode = t0.elapsed().as_secs_f64();

    // Verify the chain; re-decode chunks that started at the wrong offset.
    let mut expected = first;
    let mut redone = 0usize;
    let mut truncation: Option<String> = None;
    let mut reference_error: Option<String> = None;
    for i in 0..n_ranges {
        if truncation.is_some() || reference_error.is_some() || expected >= raw.len() {
            parts[i] = None;
            continue;
        }
        if !matches!(&parts[i], Some(c) if c.start == expected) {
            parts[i] = Some(cont.decode(raw, expected, bounds[i + 1]));
            redone += 1;
        }
        let c = parts[i].as_mut().expect("chunk present");
        expected = c.end;
        truncation = c.truncation.take();
        reference_error = c.ref_error.take();
    }
    let mut parts: Vec<ChunkOut> = parts.into_iter().flatten().collect();
    let t_verify = t0.elapsed().as_secs_f64();

    let mut dropped = DropCounts::default();
    let mut seen = 0u64;
    let mut total = 0usize;
    for p in &parts {
        dropped.add(&p.dropped);
        seen += p.seen;
        total += p.cols.len();
    }
    let columns = pool.install(|| PacketColumns {
        ts_us: concat(&mut parts, total, |c| &mut c.ts_us),
        src: concat(&mut parts, total, |c| &mut c.src),
        dst: concat(&mut parts, total, |c| &mut c.dst),
        sport: concat(&mut parts, total, |c| &mut c.sport),
        dport: concat(&mut parts, total, |c| &mut c.dport),
        proto: concat(&mut parts, total, |c| &mut c.proto),
        ip_len: concat(&mut parts, total, |c| &mut c.ip_len),
        hdr_len: concat(&mut parts, total, |c| &mut c.hdr_len),
        payload: concat(&mut parts, total, |c| &mut c.payload),
        flags: concat(&mut parts, total, |c| &mut c.flags),
        win: concat(&mut parts, total, |c| &mut c.win),
        icmp_type: concat(&mut parts, total, |c| &mut c.icmp_type),
        icmp_code: concat(&mut parts, total, |c| &mut c.icmp_code),
    });
    if timing {
        eprintln!(
            "read_pcap_columns: decode {t_decode:.3}s, verify {:.3}s ({redone} of {n_ranges} \
             chunks re-decoded), concat {:.3}s, rows {total}, threads {n_threads}",
            t_verify - t_decode,
            t0.elapsed().as_secs_f64() - t_verify
        );
    }
    Ok(PacketTable {
        columns,
        dropped,
        total_seen: seen,
        truncated: truncation.is_some(),
        truncation,
        reference_error,
        pcapng: matches!(cont, Container::Ng(_)),
        linktype: match cont {
            Container::Pcap { fmt, .. } => fmt.linktype,
            Container::Ng(ng) => ng.linktype,
        },
        nanosecond: matches!(cont, Container::Pcap { fmt, .. } if fmt.nano),
        ts_divisor: match cont {
            Container::Pcap { fmt, .. } => {
                if fmt.nano {
                    1e9
                } else {
                    1e6
                }
            },
            Container::Ng(ng) => ng.divisor,
        },
        bytes_consumed: expected.min(raw.len()) as u64,
        file_size: raw.len() as u64,
        n_chunks: n_ranges,
        chunks_redecoded: redone,
        n_threads,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 12];
        v[0] = 0x02;
        v.extend_from_slice(&ethertype.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn ipv4(proto: u8, l4: &[u8], frag: u16) -> Vec<u8> {
        let len = (20 + l4.len()) as u16;
        let mut v = vec![
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        v[2..4].copy_from_slice(&len.to_be_bytes());
        v[6..8].copy_from_slice(&frag.to_be_bytes());
        v.extend_from_slice(l4);
        v
    }

    fn tcp(sport: u16, dport: u16, flags: u8, win: u16, payload: usize) -> Vec<u8> {
        let mut v = vec![0u8; 20];
        v[0..2].copy_from_slice(&sport.to_be_bytes());
        v[2..4].copy_from_slice(&dport.to_be_bytes());
        v[12] = 5 << 4;
        v[13] = flags;
        v[14..16].copy_from_slice(&win.to_be_bytes());
        v.extend(std::iter::repeat_n(0xAB, payload));
        v
    }

    fn pcap(little: bool, nano: bool, recs: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
        let magic: u32 = if nano { 0xA1B2_3C4D } else { 0xA1B2_C3D4 };
        let w = |v: &mut Vec<u8>, x: u32| {
            if little {
                v.extend_from_slice(&x.to_le_bytes());
            } else {
                v.extend_from_slice(&x.to_be_bytes());
            }
        };
        let mut v = Vec::new();
        w(&mut v, magic);
        v.extend_from_slice(&if little { [2, 0, 4, 0] } else { [0, 2, 0, 4] });
        w(&mut v, 0);
        w(&mut v, 0);
        w(&mut v, 65535);
        w(&mut v, 1);
        for (s, f, d) in recs {
            w(&mut v, *s);
            w(&mut v, *f);
            w(&mut v, d.len() as u32);
            w(&mut v, d.len() as u32);
            v.extend_from_slice(d);
        }
        v
    }

    fn read(bytes: &[u8], threads: usize) -> PacketTable {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.pcap");
        std::fs::write(&p, bytes).unwrap();
        read_pcap_columns_with(
            &p,
            ColumnReaderOptions {
                n_threads: Some(threads),
                chunk_bytes: 1, // clamped to 64 KiB
                release_pages: true,
            },
        )
        .unwrap()
    }

    #[test]
    fn basic_rows_and_drops() {
        let recs = vec![
            (
                1_519_000_000,
                123_456,
                eth(0x0800, &ipv4(6, &tcp(80, 1234, 0x12, 512, 10), 0)),
            ),
            (
                1_519_000_001,
                999_999,
                eth(0x0800, &ipv4(17, &[0, 53, 4, 0, 0, 8, 0, 0], 0)),
            ),
            (1_519_000_002, 0, eth(0x0806, &[0u8; 28])),
            (1_519_000_003, 0, eth(0x86DD, &[0x60u8; 40])),
            (
                1_519_000_004,
                0,
                eth(0x0800, &ipv4(6, &tcp(1, 2, 0, 0, 0), 100)),
            ),
            (1_519_000_005, 0, eth(0x0800, &ipv4(47, &[0u8; 8], 0))),
            (1_519_000_006, 0, vec![0u8; 10]),
            (
                1_519_000_007,
                5,
                eth(0x0800, &ipv4(1, &[3, 1, 0, 0, 0, 0, 0, 0], 0)),
            ),
        ];
        for little in [false, true] {
            for threads in [1, 3] {
                let t = read(&pcap(little, false, &recs), threads);
                assert_eq!(t.total_seen, 8);
                assert_eq!(t.columns.len(), 3);
                assert_eq!(
                    t.dropped,
                    DropCounts {
                        non_ip: 1,
                        ipv6: 1,
                        other_l4: 1,
                        fragment: 1,
                        parse_error: 1
                    }
                );
                let c = &t.columns;
                assert_eq!(c.ts_us[0], 1_519_000_000_123_456);
                assert_eq!(c.ts_us[1], 1_519_000_001_999_999);
                assert_eq!((c.sport[0], c.dport[0], c.proto[0]), (80, 1234, 6));
                assert_eq!((c.ip_len[0], c.hdr_len[0], c.payload[0]), (50, 20, 10));
                assert_eq!((c.flags[0], c.win[0]), (0x12, 512));
                assert_eq!((c.proto[1], c.hdr_len[1], c.payload[1]), (17, 8, 0));
                assert_eq!((c.proto[2], c.icmp_type[2], c.icmp_code[2]), (1, 3, 1));
                assert_eq!(c.src[0], 0x0A00_0001);
                assert!(!t.truncated);
            }
        }
    }

    #[test]
    fn vlan_is_decapsulated() {
        let mut inner = vec![0x00, 0x05, 0x08, 0x00];
        inner.extend(ipv4(17, &[0, 1, 0, 2, 0, 8, 0, 0], 0));
        let t = read(&pcap(false, false, &[(1, 0, eth(0x8100, &inner))]), 1);
        assert_eq!(t.columns.len(), 1);
        assert_eq!(t.columns.dport[0], 2);
    }

    #[test]
    fn nanosecond_rounding_half_even() {
        let p = eth(0x0800, &ipv4(17, &[0, 1, 0, 2, 0, 8, 0, 0], 0));
        let recs = vec![
            (10, 1_500, p.clone()),
            (10, 2_500, p.clone()),
            (10, 2_501, p),
        ];
        let t = read(&pcap(true, true, &recs), 2);
        assert_eq!(t.columns.ts_us, vec![10_000_002, 10_000_002, 10_000_003]);
        assert!(t.nanosecond);
    }

    #[test]
    fn truncated_tail() {
        let p = eth(0x0800, &ipv4(6, &tcp(1, 2, 0x10, 9, 100), 0));
        let full = pcap(false, false, &[(1, 0, p.clone()), (2, 0, p)]);
        // Cut inside the last packet's data: decoded from what is present.
        let t = read(&full[..full.len() - 50], 1);
        assert!(t.truncated);
        assert_eq!(t.total_seen, 2);
        assert_eq!(t.columns.len(), 2);
        // Cut inside the last record header: that record is not decoded.
        let first_end = 24 + 16 + 14 + 20 + 120;
        let t = read(&full[..first_end + 7], 1);
        assert!(t.truncated);
        assert_eq!(t.total_seen, 1);
    }

    /// Many chunks: the parallel result must equal one serial decode, both
    /// when resync finds the true boundaries and when it cannot (all chunks
    /// re-decoded), and whatever the thread count.
    #[test]
    fn parallel_chunks_match_serial_decode() {
        let mut recs = Vec::new();
        let mut x: u32 = 12345;
        for i in 0..40_000u32 {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            let n = (x >> 16) as usize % 300;
            // Payload bytes that look like record headers, to provoke false syncs.
            let mut pl = tcp(1000 + (i % 7) as u16, 80, 0x18, 1024, 0);
            for k in 0..n {
                pl.push(if k % 16 < 8 { 0 } else { (x >> (k % 24)) as u8 });
            }
            recs.push((
                1_519_000_000 + i,
                (x % 1_000_000),
                eth(0x0800, &ipv4(6, &pl, 0)),
            ));
            if i % 97 == 0 {
                recs.push((1_519_000_000 + i, 1, eth(0x0806, &[0u8; 28])));
            }
        }
        let bytes = pcap(true, false, &recs);
        assert!(bytes.len() > 20 * 65_536);
        let fmt = parse_global_header(&bytes).unwrap();
        let serial = decode_range(&bytes, fmt, 24, bytes.len());
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("big.pcap");
        std::fs::write(&p, &bytes).unwrap();
        for threads in [1, 2, 7] {
            let t = read_pcap_columns_with(
                &p,
                ColumnReaderOptions {
                    n_threads: Some(threads),
                    chunk_bytes: 65_536,
                    release_pages: true,
                },
            )
            .unwrap();
            assert!(t.n_chunks > 20);
            assert_eq!(t.columns, serial.cols);
            assert_eq!(t.dropped, serial.dropped);
            assert_eq!(t.total_seen, serial.seen);
            assert_eq!(t.bytes_consumed as usize, bytes.len());
        }
        // orig_len < caplen everywhere: resync never succeeds, every chunk is
        // re-decoded from the verified offset, the result is unchanged.
        let mut bad = bytes.clone();
        let mut off = 24;
        while off < bad.len() {
            let cap = u32::from_le_bytes(bad[off + 8..off + 12].try_into().unwrap()) as usize;
            bad[off + 12..off + 16].copy_from_slice(&0u32.to_le_bytes());
            off += 16 + cap;
        }
        std::fs::write(&p, &bad).unwrap();
        let t = read_pcap_columns_with(
            &p,
            ColumnReaderOptions {
                n_threads: Some(4),
                chunk_bytes: 65_536,
                release_pages: false,
            },
        )
        .unwrap();
        assert_eq!(t.chunks_redecoded, t.n_chunks - 1);
        assert_eq!(t.columns, serial.cols);
        assert_eq!(t.total_seen, serial.seen);
    }

    fn ng_block(btype: u32, body: &[u8]) -> Vec<u8> {
        let mut body = body.to_vec();
        while body.len() % 4 != 0 {
            body.push(0);
        }
        let n = (12 + body.len()) as u32;
        let mut v = btype.to_le_bytes().to_vec();
        v.extend_from_slice(&n.to_le_bytes());
        v.extend_from_slice(&body);
        v.extend_from_slice(&n.to_le_bytes());
        v
    }

    fn ng_pkt(btype: u32, ticks: u64, data: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        if btype == 2 {
            b.extend_from_slice(&[0, 0, 0, 0]); // iface_id u16 + drops u16
        } else {
            b.extend_from_slice(&0u32.to_le_bytes());
        }
        b.extend_from_slice(&((ticks >> 32) as u32).to_le_bytes());
        b.extend_from_slice(&(ticks as u32).to_le_bytes());
        b.extend_from_slice(&(data.len() as u32).to_le_bytes());
        b.extend_from_slice(&(data.len() as u32).to_le_bytes());
        b.extend_from_slice(data);
        while b.len() % 4 != 0 {
            b.push(0);
        }
        ng_block(btype, &b)
    }

    fn ng_file(n: u32) -> Vec<u8> {
        let mut shb = 0x1A2B_3C4Du32.to_le_bytes().to_vec();
        shb.extend_from_slice(&[1, 0, 0, 0]);
        shb.extend_from_slice(&(-1i64).to_le_bytes());
        let mut f = ng_block(0x0A0D_0D0A, &shb);
        let udp = eth(0x0800, &ipv4(17, &[0, 1, 0, 2, 0, 8, 0, 0], 0));
        f.extend(ng_pkt(6, 5, &udp)); // before the first IDB: skipped
        let mut idb = vec![1, 0, 0, 0, 0xff, 0xff, 0, 0];
        idb.extend_from_slice(&[9, 0, 1, 0, 9, 0, 0, 0]); // if_tsresol = 9 (ns)
        idb.extend_from_slice(&[14, 0, 8, 0]);
        idb.extend_from_slice(&100i64.to_le_bytes()); // if_tsoffset = 100 s
        idb.extend_from_slice(&[0, 0, 0, 0]);
        f.extend(ng_block(1, &idb));
        f.extend(ng_block(1, &[101, 0, 0, 0, 0xff, 0xff, 0, 0])); // 2nd IDB: ignored
        for i in 0..n {
            let ticks = 1_519_000_000_000_000_000 + u64::from(i) * 1_500;
            let pl = tcp(1000 + (i % 7) as u16, 80, 0x18, 1024, (i % 300) as usize);
            f.extend(ng_pkt(6, ticks, &eth(0x0800, &ipv4(6, &pl, 0))));
            if i % 50 == 0 {
                f.extend(ng_block(3, &[0u8; 40])); // SPB: ignored
                f.extend(ng_pkt(2, ticks, &udp)); // obsolete PB: yielded
            }
        }
        f
    }

    #[test]
    fn pcapng_dpkt_semantics_and_parallel_chunks() {
        let bytes = ng_file(30_000);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.pcapng");
        std::fs::write(&p, &bytes).unwrap();
        let ng = parse_pcapng_header(&bytes).unwrap();
        assert_eq!((ng.divisor, ng.tsoffset, ng.linktype), (1e9, 100, 1));
        let serial = decode_range_ng(&bytes, ng, ng.first, bytes.len());
        assert_eq!(serial.seen, 30_000 + 600);
        // ts = 100 + 1519000000000000000 / 1e9 (float), in microseconds
        let want =
            ((100.0 + 1_519_000_000_000_000_000u64 as f64 / 1e9) * 1e6).round_ties_even() as i64;
        assert_eq!(serial.cols.ts_us[0], want);
        for threads in [1, 3] {
            let t = read_pcap_columns_with(
                &p,
                ColumnReaderOptions {
                    n_threads: Some(threads),
                    chunk_bytes: 65_536,
                    release_pages: true,
                },
            )
            .unwrap();
            assert!(t.pcapng && t.n_chunks > 20 && t.reference_error.is_none());
            assert_eq!(t.columns, serial.cols);
            assert_eq!(t.total_seen, serial.seen);
        }
        // Cut inside the last block: dpkt raises; rows before are kept.
        std::fs::write(&p, &bytes[..bytes.len() - 6]).unwrap();
        let t = read_pcap_columns(&p, Some(2)).unwrap();
        assert!(t.truncated && t.reference_error.is_some());
        assert_eq!(t.total_seen, serial.seen - 1);
    }

    #[test]
    fn pcapng_bad_header_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.pcapng");
        let mut b = vec![0x0A, 0x0D, 0x0D, 0x0A];
        b.extend_from_slice(&[0u8; 28]);
        std::fs::write(&p, b).unwrap();
        let e = read_pcap_columns(&p, Some(1)).unwrap_err();
        assert!(format!("{e}").contains("pcapng"));
    }
}
