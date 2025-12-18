use anyhow::{Result, anyhow};
use chrono::{DateTime, Local, TimeZone};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

const NTP_EPOCH_UNIX_DIFF: u64 = 2_208_988_800; // seconds between 1900-01-01 and 1970-01-01

#[derive(Debug, Clone, Serialize)]
pub struct NtpRequestMeta {
    pub client_tx_unix_ns: u128,
    pub client_tx_ntp: NtpTimestamp,
}

#[derive(Debug, Clone, Serialize)]
pub struct NtpResponseParsed {
    pub raw_len: usize,
    pub raw_hex: String,
    pub header: NtpHeader,
    pub extension_fields: Vec<NtpExtensionField>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct NtpHeader {
    pub li: u8,
    pub vn: u8,
    pub mode: u8,

    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,

    pub root_delay_s: f64,
    pub root_dispersion_s: f64,
    pub reference_id: u32,

    pub reference_timestamp: NtpTimestamp,
    pub originate_timestamp: NtpTimestamp,
    pub receive_timestamp: NtpTimestamp,
    pub transmit_timestamp: NtpTimestamp,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct NtpTimestamp {
    pub seconds: u32,
    pub fraction: u32,
    pub unix_seconds: i64,
    pub unix_nanos: i128,
}

#[derive(Debug, Clone, Serialize)]
pub struct NtpExtensionField {
    pub field_type: u16,
    pub length: u16,
    pub value_hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NtpComputed {
    pub offset_s: f64,
    pub delay_s: f64,
    pub t1_unix_ns: i128,
    pub t2_unix_ns: i128,
    pub t3_unix_ns: i128,
    pub t4_unix_ns: i128,
}

#[derive(Debug, Clone)]
pub struct HumanOutput {
    pub server_label: String,
    pub header: NtpHeader,
    pub offset_s: f64,
    pub delay_s: f64,
    pub ntp_time_unix_ns: i128,
    pub local_time_unix_ns: i128,
    pub authenticated: Option<bool>,
}

impl HumanOutput {
    pub fn print_like_chronyc(&self) {
        let hdr = &self.header;

        // Time Diff = |NTP Time - Local Time|
        let diff_s = ((self.ntp_time_unix_ns - self.local_time_unix_ns).abs() as f64) / 1e9;

        println!("NTP Server      : {}", self.server_label);
        println!("Stratum         : {}", hdr.stratum);
        println!(
            "RefID           : {}",
            refid_to_string(hdr.stratum, hdr.reference_id)
        );
        println!("Leap Indicator  : {}", hdr.li);
        println!("Version         : {}", hdr.vn);
        println!("Mode            : {}", hdr.mode);
        println!("Poll            : {}", hdr.poll);
        println!("Precision       : {}", hdr.precision);
        println!("Root Delay      : {:.6} s", hdr.root_delay_s);
        println!("Root Dispersion : {:.6} s", hdr.root_dispersion_s);
        println!("Offset          : {:.6} s", self.offset_s);
        println!("Delay           : {:.6} s", self.delay_s);
        println!(
            "NTP Time        : {}",
            fmt_ts_local_micro(self.ntp_time_unix_ns)
        );
        println!(
            "Local Time      : {}",
            fmt_ts_local_micro(self.local_time_unix_ns)
        );
        println!("Time Diff       : {:.6} s", diff_s);

        if let Some(a) = self.authenticated {
            println!("Authenticated   : {}", a);
        }
    }
}

pub fn build_ntp_client_request() -> Result<(Vec<u8>, NtpRequestMeta)> {
    // NTP request is 48 bytes; LI=0, VN=4, Mode=3
    let mut pkt = vec![0u8; 48];
    pkt[0] = (0 << 6) | (4 << 3) | 3;

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let unix_ns = (now.as_secs() as u128) * 1_000_000_000u128 + (now.subsec_nanos() as u128);
    let ntp_ts = unix_ns_to_ntp(unix_ns);

    // Transmit Timestamp at bytes 40..48
    put_u32(&mut pkt[40..44], ntp_ts.seconds);
    put_u32(&mut pkt[44..48], ntp_ts.fraction);

    Ok((
        pkt,
        NtpRequestMeta {
            client_tx_unix_ns: unix_ns,
            client_tx_ntp: ntp_ts,
        },
    ))
}

pub fn parse_ntp_response(buf: &[u8]) -> Result<NtpResponseParsed> {
    if buf.len() < 48 {
        return Err(anyhow!("NTP response too short: {} bytes", buf.len()));
    }

    let b0 = buf[0];
    let li = (b0 >> 6) & 0x03;
    let vn = (b0 >> 3) & 0x07;
    let mode = b0 & 0x07;

    let stratum = buf[1];
    let poll = buf[2] as i8;
    let precision = buf[3] as i8;

    let root_delay = get_u32(&buf[4..8]);
    let root_dispersion = get_u32(&buf[8..12]);
    let reference_id = get_u32(&buf[12..16]);

    let reference_timestamp = parse_ts(&buf[16..24]);
    let originate_timestamp = parse_ts(&buf[24..32]);
    let receive_timestamp = parse_ts(&buf[32..40]);
    let transmit_timestamp = parse_ts(&buf[40..48]);

    // Root delay/dispersion are 16.16 fixed-point seconds
    let root_delay_s = fixed_16_16_to_seconds(root_delay);
    let root_dispersion_s = fixed_16_16_to_seconds(root_dispersion);

    let header = NtpHeader {
        li,
        vn,
        mode,
        stratum,
        poll,
        precision,
        root_delay_s,
        root_dispersion_s,
        reference_id,
        reference_timestamp,
        originate_timestamp,
        receive_timestamp,
        transmit_timestamp,
    };

    // Extension fields: type(u16) + len(u16), len includes header.
    let mut ext = Vec::new();
    let mut i = 48usize;
    while i + 4 <= buf.len() {
        let field_type = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let length = u16::from_be_bytes([buf[i + 2], buf[i + 3]]);

        if length < 4 {
            break;
        }
        let end = i + (length as usize);
        if end > buf.len() {
            break;
        }

        let value = &buf[i + 4..end];
        ext.push(NtpExtensionField {
            field_type,
            length,
            value_hex: hex_lower(value),
        });

        i = end;
    }

    Ok(NtpResponseParsed {
        raw_len: buf.len(),
        raw_hex: hex_lower(buf),
        header,
        extension_fields: ext,
    })
}

pub fn compute_offset_delay(
    t1_unix_ns: i128,
    t2_unix_ns: i128,
    t3_unix_ns: i128,
    t4_unix_ns: i128,
) -> NtpComputed {
    let t1 = t1_unix_ns as f64 / 1e9;
    let t2 = t2_unix_ns as f64 / 1e9;
    let t3 = t3_unix_ns as f64 / 1e9;
    let t4 = t4_unix_ns as f64 / 1e9;

    // Standard NTP formulas
    let delay = (t4 - t1) - (t3 - t2);
    let offset = ((t2 - t1) + (t3 - t4)) / 2.0;

    NtpComputed {
        offset_s: offset,
        delay_s: delay,
        t1_unix_ns,
        t2_unix_ns,
        t3_unix_ns,
        t4_unix_ns,
    }
}

/// RefID display:
/// - Stratum 0/1: usually ASCII (e.g. "GNSS", "GPS", "ATOM")
/// - Stratum >=2: usually IPv4 address of reference source
pub fn refid_to_string(stratum: u8, refid: u32) -> String {
    let b = refid.to_be_bytes();
    if stratum <= 1 {
        let s: String = b
            .iter()
            .map(|&x| {
                if (0x20..=0x7E).contains(&x) {
                    x as char
                } else {
                    '.'
                }
            })
            .collect();
        s.trim().to_string()
    } else {
        format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
    }
}

fn fmt_ts_local_micro(unix_ns: i128) -> String {
    let secs = (unix_ns / 1_000_000_000i128) as i64;
    let nsec = (unix_ns % 1_000_000_000i128) as u32;
    let dt: DateTime<Local> = Local.timestamp_opt(secs, nsec).single().unwrap();
    dt.format("%Y-%m-%d %H:%M:%S%.6f").to_string()
}

fn parse_ts(b: &[u8]) -> NtpTimestamp {
    let seconds = get_u32(&b[0..4]);
    let fraction = get_u32(&b[4..8]);

    let unix_seconds = seconds as i64 - (NTP_EPOCH_UNIX_DIFF as i64);

    let nanos_frac = ((fraction as u128) * 1_000_000_000u128) >> 32;
    let unix_nanos = (unix_seconds as i128) * 1_000_000_000i128 + nanos_frac as i128;

    NtpTimestamp {
        seconds,
        fraction,
        unix_seconds,
        unix_nanos,
    }
}

fn unix_ns_to_ntp(unix_ns: u128) -> NtpTimestamp {
    let unix_s = (unix_ns / 1_000_000_000u128) as i64;
    let ns = (unix_ns % 1_000_000_000u128) as u128;

    let ntp_s = unix_s + (NTP_EPOCH_UNIX_DIFF as i64);
    let frac = ((ns << 32) / 1_000_000_000u128) as u32;

    let seconds = ntp_s as u32;

    let unix_seconds = unix_s;
    let unix_nanos = (unix_seconds as i128) * 1_000_000_000i128 + (ns as i128);

    NtpTimestamp {
        seconds,
        fraction: frac,
        unix_seconds,
        unix_nanos,
    }
}

fn fixed_16_16_to_seconds(v: u32) -> f64 {
    let int_part = (v >> 16) as f64;
    let frac_part = (v & 0xFFFF) as f64 / 65536.0;
    int_part + frac_part
}

fn get_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn put_u32(b: &mut [u8], v: u32) {
    b.copy_from_slice(&v.to_be_bytes());
}

fn hex_lower(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for &x in data {
        out.push(HEX[(x >> 4) as usize] as char);
        out.push(HEX[(x & 0x0F) as usize] as char);
    }
    out
}
