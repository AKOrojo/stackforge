//! Parallel, columnar classic-PCAP reader producing a flow-feature packet table.
//!
//! [`read_pcap_columns`] memory-maps a capture, walks the record headers once
//! (classic PCAP has no index), cuts the record stream into chunks and decodes
//! the chunks in parallel on a private Rayon pool. Each packet becomes one row
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
use std::sync::Mutex;

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
    /// Link type from the global header.
    pub linktype: u32,
    /// Timestamps in the file are nanoseconds (otherwise microseconds).
    pub nanosecond: bool,
    /// Byte offset where decoding stopped (== file size for a complete file).
    pub bytes_consumed: u64,
    /// File size in bytes.
    pub file_size: u64,
    /// Number of chunks decoded in parallel.
    pub n_chunks: usize,
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
        0x0A0D_0D0A => {
            return Err(PacketError::Io(
                "pcapng is not supported by read_pcap_columns (classic pcap only); convert with \
                 `editcap -F pcap in.pcapng out.pcap` or use PcapReader"
                    .into(),
            ));
        },
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
        match ethernet(buf) {
            Err(_) => return Outcome::ParseError,
            Ok(Data::Ip6) => return Outcome::Ipv6,
            Ok(Data::Ip(ip)) => ip,
            Ok(_) => return Outcome::NonIp,
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
// Chunked parallel driver
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Chunk {
    start: usize,
    end: usize,
    n_records: usize,
}

struct ChunkOut {
    cols: PacketColumns,
    dropped: DropCounts,
    seen: u64,
}

fn decode_chunk(raw: &[u8], fmt: Format, c: Chunk) -> ChunkOut {
    let mut cols = PacketColumns::with_capacity(c.n_records);
    let mut dropped = DropCounts::default();
    let mut off = c.start;
    let mut seen = 0u64;
    while off < c.end {
        // The walker guarantees a complete record header here.
        let sec = rd32(raw, off, fmt.little);
        let frac = rd32(raw, off + 4, fmt.little);
        let caplen = rd32(raw, off + 8, fmt.little) as usize;
        let ds = off + fmt.rec_hdr_len;
        let de = ds.saturating_add(caplen).min(raw.len());
        let buf = &raw[ds..de];
        off = de;
        seen += 1;
        match classify(buf, fmt.linktype) {
            Outcome::Row(r) => cols.push(ts_to_us(sec, frac, fmt.nano), &r),
            Outcome::NonIp => dropped.non_ip += 1,
            Outcome::Ipv6 => dropped.ipv6 += 1,
            Outcome::OtherL4 => dropped.other_l4 += 1,
            Outcome::Fragment => dropped.fragment += 1,
            Outcome::ParseError => dropped.parse_error += 1,
        }
    }
    ChunkOut {
        cols,
        dropped,
        seen,
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

fn spawn_chunk<'s>(
    s: &rayon::Scope<'s>,
    slots: &'s Mutex<Vec<Option<ChunkOut>>>,
    mmap: &'s Mmap,
    fmt: Format,
    release_pages: bool,
    idx: usize,
    c: Chunk,
) {
    s.spawn(move |_| {
        let out = decode_chunk(mmap, fmt, c);
        if release_pages {
            release(mmap, c.start, c.end);
        }
        let mut g = slots.lock().unwrap();
        if g.len() <= idx {
            g.resize_with(idx + 1, || None);
        }
        g[idx] = Some(out);
    });
}

/// Read a classic pcap into the 13-column packet table (see module docs).
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
    #[cfg(unix)]
    let _ = mmap.advise(memmap2::Advice::Sequential);
    let raw: &[u8] = &mmap;
    let fmt = parse_global_header(raw)?;

    let n_threads = opts
        .n_threads
        .filter(|&n| n > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()));
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(n_threads)
        .thread_name(|i| format!("sf-pcapcols-{i}"))
        .build()
        .map_err(|e| PacketError::Io(format!("failed to build thread pool: {e}")))?;

    let chunk_bytes = opts.chunk_bytes.max(1 << 16);
    let slots: Mutex<Vec<Option<ChunkOut>>> = Mutex::new(Vec::new());
    let mut truncation: Option<String> = None;
    let mut consumed = 24usize;
    let mut n_chunks = 0usize;

    // The walker runs on one pool thread and hands each chunk to the pool as
    // soon as its extent is known, so walking and decoding overlap.
    pool.scope(|s| {
        let mut off = 24usize;
        let mut cstart = off;
        let mut cn = 0usize;
        let mut idx = 0usize;
        let (slots, mmap, rp) = (&slots, &mmap, opts.release_pages);
        loop {
            let rem = raw.len() - off;
            if rem == 0 {
                break;
            }
            if rem < fmt.rec_hdr_len {
                truncation = Some(format!(
                    "capture ends inside a record header at offset {off} ({rem} of {} bytes)",
                    fmt.rec_hdr_len
                ));
                break;
            }
            let caplen = rd32(raw, off + 8, fmt.little) as usize;
            let ds = off + fmt.rec_hdr_len;
            let avail = raw.len() - ds;
            if caplen > avail {
                truncation = Some(format!(
                    "last record at offset {off} claims {caplen} bytes but only {avail} remain; \
                     decoded from the bytes present"
                ));
                off = raw.len();
                cn += 1;
                break;
            }
            off = ds + caplen;
            cn += 1;
            if off - cstart >= chunk_bytes {
                spawn_chunk(
                    s,
                    slots,
                    mmap,
                    fmt,
                    rp,
                    idx,
                    Chunk {
                        start: cstart,
                        end: off,
                        n_records: cn,
                    },
                );
                idx += 1;
                cstart = off;
                cn = 0;
            }
        }
        if cn > 0 {
            spawn_chunk(
                s,
                slots,
                mmap,
                fmt,
                rp,
                idx,
                Chunk {
                    start: cstart,
                    end: off,
                    n_records: cn,
                },
            );
            idx += 1;
        }
        consumed = off;
        n_chunks = idx;
    });

    let mut parts: Vec<ChunkOut> = slots
        .into_inner()
        .unwrap()
        .into_iter()
        .map(|o| o.expect("chunk decoded"))
        .collect();
    let mut dropped = DropCounts::default();
    let mut seen = 0u64;
    let mut total = 0usize;
    for p in &parts {
        dropped.add(&p.dropped);
        seen += p.seen;
        total += p.cols.len();
    }
    let columns = pool.install(|| {
        let ts_us = concat(&mut parts, total, |c| &mut c.ts_us);
        let src = concat(&mut parts, total, |c| &mut c.src);
        let dst = concat(&mut parts, total, |c| &mut c.dst);
        let sport = concat(&mut parts, total, |c| &mut c.sport);
        let dport = concat(&mut parts, total, |c| &mut c.dport);
        let proto = concat(&mut parts, total, |c| &mut c.proto);
        let ip_len = concat(&mut parts, total, |c| &mut c.ip_len);
        let hdr_len = concat(&mut parts, total, |c| &mut c.hdr_len);
        let payload = concat(&mut parts, total, |c| &mut c.payload);
        let flags = concat(&mut parts, total, |c| &mut c.flags);
        let win = concat(&mut parts, total, |c| &mut c.win);
        let icmp_type = concat(&mut parts, total, |c| &mut c.icmp_type);
        let icmp_code = concat(&mut parts, total, |c| &mut c.icmp_code);
        PacketColumns {
            ts_us,
            src,
            dst,
            sport,
            dport,
            proto,
            ip_len,
            hdr_len,
            payload,
            flags,
            win,
            icmp_type,
            icmp_code,
        }
    });

    Ok(PacketTable {
        columns,
        dropped,
        total_seen: seen,
        truncated: truncation.is_some(),
        truncation,
        linktype: fmt.linktype,
        nanosecond: fmt.nano,
        bytes_consumed: consumed as u64,
        file_size: raw.len() as u64,
        n_chunks,
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

    #[test]
    fn pcapng_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.pcapng");
        let mut b = vec![0x0A, 0x0D, 0x0D, 0x0A];
        b.extend_from_slice(&[0u8; 28]);
        std::fs::write(&p, b).unwrap();
        let e = read_pcap_columns(&p, Some(1)).unwrap_err();
        assert!(format!("{e}").contains("pcapng"));
    }
}
