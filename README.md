# NTPChecker

NTPChecker is a **Rust-based command-line tool** for checking the status and quality of an NTP server.  
It supports both **standard NTP (UDP/123)** and **Network Time Security (NTS, RFC 8915)**, providing
detailed, human-readable output similar to tools like `chronyc`, along with additional NTS-specific
diagnostic information.

This project is designed for **server operators, infrastructure engineers, and researchers** who
need to verify NTP/NTS correctness, timing quality, and authentication status.

---

## Features

- Standard NTP (NTPv4) server checking
- Network Time Security (NTS) support
- Offset / delay calculation using NTP timestamps
- Detailed server information:
  - Stratum
  - Reference ID (RefID)
  - Root Delay / Root Dispersion
  - Precision / Poll interval
- NTS diagnostics:
  - Authentication status
  - AEAD algorithm
  - NTS-KE server and negotiated NTP server
  - TLS certificate details (subject, issuer, validity, fingerprint)
- Output format similar to `chronyc tracking`
- Implemented in safe, modern Rust

---

## Project Structure

```
src/
├── main.rs   # CLI entry point, NTP / NTS logic
├── ntp.rs    # NTP packet parsing, timestamp math, output formatting
```

---

## Build

### Requirements

- Rust 1.70+ (recommended: latest stable)
- Cargo

### Build without NTS

```bash
cargo build --release
```

### Build with NTS support

```bash
cargo build --release --features nts
```

The compiled binary will be located at:

```
target/release/NTPChecker
```

---

## Usage

### Check an NTP server (standard NTP)

```bash
./NTPChecker --host ntp.mtf.edu.kg
```

This uses UDP port 123 and performs a standard NTP query.

---

### Check an NTP server with NTS enabled

```bash
./NTPChecker --host ntp.mtf.edu.kg --nts
```

This will:

1. Perform NTS-KE (TLS, usually port 4460)
2. Verify authentication
3. Use the NTS-negotiated NTP server for time queries
4. Display both NTP and NTS diagnostic information

---

### Optional Arguments

| Option                 | Description                 |
| ---------------------- | --------------------------- |
| `--host <HOST>`        | NTP/NTS server hostname     |
| `--port <PORT>`        | NTP UDP port (default: 123) |
| `--nts`                | Enable NTS mode             |
| `--nts-ke-port <PORT>` | NTS-KE port (default: 4460) |
| `--timeout-ms <MS>`    | UDP timeout in milliseconds |

---

## Example Output

```
NTP Server      : ntp.mtf.edu.kg
Stratum         : 2
RefID           : 172.16.1.4
Leap Indicator  : 0
Version         : 4
Mode            : 4
Poll            : 1
Precision       : -25
Root Delay      : 0.035324 s
Root Dispersion : 0.000290 s
Offset          : 0.006000 s
Delay           : 0.121964 s
NTP Time        : 2025-12-18 14:17:28.862087
Local Time      : 2025-12-18 14:17:28.885259
Time Diff       : 0.023172 s
Authenticated   : true

--- NTS Details ---
NTS Enabled      : true
Authenticated    : true
NTS-KE Server    : ntp.mtf.edu.kg:4460
NTP Server (KE)  : 103.40.14.12:123
AEAD Algorithm   : "AEAD_AES_SIV_CMAC_256"
Cert Subject     : CN=ntp.mtf.edu.kg
Cert Issuer      : C=US, O=Let's Encrypt, CN=E8
Cert Valid From  : "Dec 17 11:13:55 2025 +00:00"
Cert Valid Until : "Mar 17 11:13:54 2026 +00:00"
Cert SHA256 FP   : 24fcc4b3238754bb9b114328fef832d6afbe9a15074f7bf4bd8e557fa39e0d8a
Cert SelfSigned  : false
```
