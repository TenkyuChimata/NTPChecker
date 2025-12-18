use anyhow::{Context, Result, anyhow};
use clap::Parser;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::time::{Duration, timeout};

mod ntp;

#[derive(Parser, Debug)]
#[command(name = "NTPChecker", about = "Dump NTP info; optional NTS")]
struct Args {
    /// Server hostname (e.g. ntp.mtf.edu.kg)
    #[arg(long)]
    host: String,

    /// Plain NTP UDP port (usually 123)
    #[arg(long, default_value_t = 123)]
    port: u16,

    /// UDP timeout in ms
    #[arg(long, default_value_t = 2000)]
    timeout_ms: u64,

    /// Enable NTS (requires --features nts)
    #[arg(long)]
    nts: bool,

    /// NTS-KE port (usually 4460)
    #[arg(long, default_value_t = 4460)]
    nts_ke_port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.nts {
        #[cfg(feature = "nts")]
        run_nts(&args).await?;
        #[cfg(not(feature = "nts"))]
        return Err(anyhow!("Binary not built with --features nts"));
    } else {
        let out = query_plain_ntp(&args, None).await?;
        out.print_like_chronyc();
    }

    Ok(())
}

/// =======================
/// Plain NTP core function
/// =======================
async fn query_plain_ntp(args: &Args, force_addr: Option<SocketAddr>) -> Result<ntp::HumanOutput> {
    let addr: SocketAddr = if let Some(a) = force_addr {
        a
    } else {
        tokio::net::lookup_host((args.host.as_str(), args.port))
            .await?
            .next()
            .ok_or_else(|| anyhow!("DNS resolve failed"))?
    };

    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(addr).await?;

    // ---- T1
    let (req, meta) = ntp::build_ntp_client_request()?;
    let t1 = meta.client_tx_unix_ns as i128;

    sock.send(&req).await?;

    let mut buf = vec![0u8; 2048];
    let n = timeout(Duration::from_millis(args.timeout_ms), sock.recv(&mut buf)).await??;

    // ---- T4 (right after recv)
    let t4 = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let t4_ns = (t4.as_secs() as i128) * 1_000_000_000 + t4.subsec_nanos() as i128;

    buf.truncate(n);

    let parsed = ntp::parse_ntp_response(&buf)?;

    let t2 = parsed.header.receive_timestamp.unix_nanos;
    let t3 = parsed.header.transmit_timestamp.unix_nanos;

    let calc = ntp::compute_offset_delay(t1, t2, t3, t4_ns);

    Ok(ntp::HumanOutput {
        server_label: format!("{}:{}", args.host, args.port),
        header: parsed.header,
        offset_s: calc.offset_s,
        delay_s: calc.delay_s,
        ntp_time_unix_ns: t3,
        local_time_unix_ns: t4_ns,
        authenticated: None,
    })
}

#[cfg(feature = "nts")]
async fn run_nts(args: &Args) -> Result<()> {
    use rkik_nts::{NtsClient, NtsClientConfig};

    // NTS-KE + NTS time
    let cfg = NtsClientConfig::new(&args.host);
    let mut client = NtsClient::new(cfg);

    client.connect().await.context("NTS-KE connect failed")?;
    let snap = client.get_time().await.context("NTS time query failed")?;

    let ke = client
        .nts_ke_info()
        .ok_or_else(|| anyhow!("No NTS-KE info returned"))?;

    // 用 NTS-KE 返回的 NTP server 去拿 header（Stratum/RefID/...）
    let mut out = query_plain_ntp(args, Some(ke.ntp_server))
        .await
        .context("plain NTP query (for header) failed")?;

    // 覆盖：server label 按你想显示的域名；offset 用 NTS 结果
    out.server_label = args.host.clone();
    out.offset_s = (snap.offset_signed() as f64) / 1000.0;
    out.authenticated = Some(snap.authenticated);

    // 先打印“通用字段”
    out.print_like_chronyc();

    // 再追加 NTS 专属字段
    print_nts_details(args, &ke, snap.authenticated);

    Ok(())
}

#[cfg(feature = "nts")]
fn print_nts_details(args: &Args, ke: &rkik_nts::NtsKeResult, authenticated: bool) {
    println!();
    println!("--- NTS Details ---");
    println!("NTS Enabled      : true");
    println!("Authenticated    : {}", authenticated);
    println!("NTS-KE Server    : {}:{}", args.host, args.nts_ke_port);
    println!("NTP Server (KE)  : {}", ke.ntp_server); // SocketAddr Display
    println!("AEAD Algorithm   : {:?}", ke.aead_algorithm);

    if let Some(cert) = ke.certificate.as_ref() {
        println!("Cert Subject     : {}", cert.subject);
        println!("Cert Issuer      : {}", cert.issuer);
        println!("Cert Valid From  : {:?}", cert.valid_from);
        println!("Cert Valid Until : {:?}", cert.valid_until);
        println!("Cert SHA256 FP   : {}", cert.fingerprint_sha256);
        println!("Cert SelfSigned  : {}", cert.is_self_signed);
    } else {
        println!("Certificate      : <none>");
    }
}
