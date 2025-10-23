//! # Educational Network Port Scanner
//!
//! Copyright (C) 2025 Strategos Network Scanner Project
//!
//! This program is free software: you can redistribute it and/or modify
//! it under the terms of the GNU General Public License as published by
//! the Free Software Foundation, either version 3 of the License, or
//! (at your option) any later version.
//!
//! This program is distributed in the hope that it will be useful,
//! but WITHOUT ANY WARRANTY; without even the implied warranty of
//! MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//! GNU General Public License for more details.
//!
//! You should have received a copy of the GNU General Public License
//! along with this program.  If not, see <https://www.gnu.org/licenses/>.
//!
//! This is an educational TCP/UDP port scanner written in Rust that demonstrates
//! best practices for asynchronous I/O, concurrent network operations, and error handling.
//!
//! ## Key Learning Concepts
//!
//! 1. **Async/Await with Tokio**: Shows how to use Tokio's runtime for concurrent I/O operations
//! 2. **Stream Processing**: Demonstrates `futures::stream` for managing concurrent task execution
//! 3. **Rate Limiting**: Implements a cooperative token bucket pattern using `Mutex<Interval>`
//! 4. **Error Handling**: Shows proper error propagation and user-friendly error messages
//! 5. **TCP vs UDP**: Illustrates the different approaches needed for connection-oriented vs connectionless protocols
//!
//! ## Architecture Overview
//!
//! The scanner follows this flow:
//! 1. Parse CLI arguments (using `clap`)
//! 2. Resolve target hostname to IP address (unless --no-dns is set)
//! 3. Create a job list combining TCP and UDP ports to scan
//! 4. Execute jobs concurrently with rate limiting (using `buffer_unordered`)
//! 5. Sort and format results (Markdown table or JSON)

use clap::Parser;
use futures::stream::{self, StreamExt};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpStream, UdpSocket, lookup_host},
    sync::Mutex,
    time::{Instant, Interval, interval_at, timeout},
};

/// Top 25 most common TCP ports based on service frequency analysis.
/// These are the ports most likely to be open on typical servers and workstations.
/// Students can modify this list to focus on specific services.
const DEFAULT_TCP_PORTS: &[u16] = &[
    80, 443, 22, 21, 25, 23, 53, 110, 135, 139, 143, 445, 3389, 3306, 8080, 5900, 993, 995, 465,
    587, 111, 2049, 1025, 1723, 554,
];

/// Top 5 most common UDP ports.
/// UDP scanning is inherently less reliable than TCP due to the protocol's stateless nature.
const DEFAULT_UDP_PORTS: &[u16] = &[53, 123, 161, 500, 1900];

#[derive(Parser, Debug)]
#[command(
    name = "scanner",
    about = "Educational TCP/UDP network scanner.",
    long_about = "Educational TCP/UDP scanner that demonstrates how classic connect() and UDP probes behave without requiring raw sockets.",
    version,
    disable_help_subcommand = true
)]
struct Cli {
    /// Comma separated TCP ports or ranges (e.g. 22,80,1000-1010). Defaults to a curated top list.
    #[arg(long, value_name = "PORTS")]
    tcp: Option<String>,

    /// Comma separated UDP ports or ranges. Defaults to a handful of common UDP services.
    #[arg(
        long,
        value_name = "PORTS",
        long_help = "Comma separated UDP ports or ranges (e.g. 53,161,500-505).\n\
        UDP is intentionally best-effort: many services stay silent instead of replying, so lack of a response is reported as open|filtered."
    )]
    udp: Option<String>,

    /// Socket timeout for each probe in seconds.
    #[arg(long, value_name = "SECONDS", default_value_t = 3.0)]
    timeout: f64,

    /// Number of retries after the first attempt (timeouts only).
    #[arg(long, value_name = "N", default_value_t = 1)]
    retries: u32,

    /// Maximum number of concurrent probes.
    #[arg(long, value_name = "N", default_value_t = 64)]
    concurrency: usize,

    /// Maximum probes per second (across TCP and UDP). Unlimited when omitted.
    #[arg(long, value_name = "PPS")]
    rate: Option<u32>,

    /// Skip DNS resolution; interpret target literally.
    #[arg(long)]
    no_dns: bool,

    /// Emit results as JSON instead of a Markdown table.
    #[arg(long)]
    json: bool,

    /// Hostname or IP to scan. Defaults to 127.0.0.1.
    target: Option<String>,
}

/// Configuration shared across all scan jobs.
///
/// We use `Arc` (Atomic Reference Counting) to share this config across many concurrent
/// async tasks without cloning the data. This is a key Rust pattern for shared ownership
/// in concurrent contexts.
#[derive(Clone)]
struct ScanConfig {
    /// Maximum time to wait for a response from a single probe attempt
    timeout: Duration,
    /// Number of times to retry after initial timeout (only for timeouts, not errors)
    retries: u32,
    /// The resolved IP address of the scan target
    target_ip: IpAddr,
    /// Optional rate limiter to control probes per second across all concurrent tasks
    rate_limiter: Option<Arc<RateLimiter>>,
}

/// Protocol type for scan jobs - TCP or UDP.
///
/// ## Derive Traits Explained
///
/// - `Clone, Copy`: Allows cheap copying of this enum (it's just 1 byte)
/// - `Debug`: Auto-generates debug output (e.g., `Protocol::Tcp`)
/// - `PartialEq, Eq`: Enables equality comparison (`tcp == tcp`)
/// - `PartialOrd, Ord`: Enables ordering (for sorting results by protocol)
///
/// These traits are fundamental to Rust's type system and demonstrate
/// how Rust enforces explicit behavior through the trait system.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    /// Returns uppercase protocol name for table display
    fn as_table_label(self) -> &'static str {
        match self {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
        }
    }
}

/// Implements Display trait for user-facing protocol output
impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

/// Represents a single scan job to be executed.
#[derive(Debug)]
struct ScanJob {
    port: u16,
    protocol: Protocol,
}

/// Result of scanning a single port.
///
/// The `Serialize` derive enables automatic JSON serialization via serde.
#[derive(Debug, Serialize)]
struct ScanResult {
    port: u16,
    proto: String,
    state: String,
    service: String,
    reason: String,
}

/// Complete JSON report structure when `--json` flag is used.
#[derive(Debug, Serialize)]
struct JsonReport {
    target: JsonTarget,
    settings: JsonSettings,
    results: Vec<ScanResult>,
}

/// Target information for JSON output.
#[derive(Debug, Serialize)]
struct JsonTarget {
    input: String,     // User's original input
    resolved: String,  // Resolved IP address
}

/// Scan configuration settings for JSON output.
#[derive(Debug, Serialize)]
struct JsonSettings {
    tcp_ports: Vec<u16>,
    udp_ports: Vec<u16>,
    timeout_seconds: f64,
    retries: u32,
    concurrency: usize,
    rate: Option<u32>,
}

/// Internal target information after resolution.
struct TargetInfo {
    input: String,       // User's original input string
    resolved: IpAddr,    // Resolved IP address to scan
}

/// Rate limiter implementing a token bucket pattern for controlling scan probe rate.
///
/// ## How It Works
///
/// This rate limiter uses Tokio's `Interval` to enforce a maximum probes-per-second limit.
/// Each time a task wants to send a probe, it calls `wait()`, which:
/// 1. Acquires a lock on the interval (async mutex - doesn't block the thread)
/// 2. Waits for the next "tick" from the interval timer
/// 3. Releases the lock so other tasks can proceed
///
/// ## Why Use a Mutex?
///
/// Tokio's `Interval` is not `Sync`, meaning it can't be shared between threads safely.
/// By wrapping it in a `Mutex`, we make it safe to share across concurrent async tasks.
/// The mutex ensures only one task polls the interval at a time, creating a cooperative
/// token bucket where tasks "wait in line" for permission to send their probe.
///
/// ## Educational Note
///
/// This pattern demonstrates how to share non-thread-safe resources in async Rust.
/// The `Mutex` here is an *async* mutex from Tokio, not the standard library's mutex.
/// Async mutexes yield to the scheduler when waiting, avoiding thread blocking.
struct RateLimiter {
    /// The interval timer wrapped in a mutex for shared access across async tasks
    interval: Mutex<Interval>,
}

impl RateLimiter {
    /// Creates a new rate limiter that permits `pps` (probes per second) operations.
    ///
    /// ## Calculation
    /// If we want N probes per second, each probe must wait 1/N seconds.
    /// For example, 100 PPS means 0.01 seconds (10ms) between probes.
    fn new(pps: u32) -> Self {
        // Calculate the delay between each probe
        let per_probe = Duration::from_secs_f64(1.0 / pps as f64);
        let start = Instant::now();
        Self {
            // Ensure minimum interval of 1 microsecond to avoid division by zero edge cases
            interval: Mutex::new(interval_at(start, per_probe.max(Duration::from_micros(1)))),
        }
    }

    /// Wait for permission to send the next probe.
    ///
    /// This is an async function that yields to other tasks while waiting.
    /// The caller will be suspended until the interval timer ticks.
    async fn wait(&self) {
        // Acquire the lock (will wait if another task holds it)
        let mut guard = self.interval.lock().await;
        // Wait for the next tick (this is where rate limiting happens)
        guard.tick().await;
        // Lock is automatically released when `guard` goes out of scope
    }
}

/// Main entry point - sets up Tokio async runtime.
///
/// The `#[tokio::main]` macro expands to create a multi-threaded Tokio runtime
/// and run our async `run()` function. This is the standard pattern for async
/// Rust applications.
#[tokio::main]
async fn main() {
    // All actual logic is in run() to allow proper error handling
    if let Err(err) = run().await {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

/// Main application logic - parses args, validates config, executes scan.
///
/// ## Error Handling Strategy
///
/// We return `Result<(), Box<dyn Error>>` which allows any error type to propagate
/// upward. This is more flexible than defining a custom error type for this
/// educational scanner, though production code might use `thiserror` or `anyhow`.
async fn run() -> Result<(), Box<dyn Error>> {
    // Parse command-line arguments using clap
    let cli = Cli::parse();

    // Validate concurrency setting
    if cli.concurrency == 0 {
        return Err("concurrency must be greater than zero".into());
    }

    // Validate rate limit setting (if provided)
    if let Some(rate) = cli.rate {
        if rate == 0 {
            return Err("rate must be greater than zero".into());
        }
    }

    // Convert timeout to Duration, with a minimum of 100ms
    let timeout = if cli.timeout <= 0.0 {
        Duration::from_millis(100)
    } else {
        Duration::from_secs_f64(cli.timeout)
    };

    // Parse TCP ports or use defaults
    // The `.transpose()` converts Option<Result<T, E>> to Result<Option<T>, E>
    // This is a common Rust pattern when working with nested Option/Result types
    let tcp_ports = match cli.tcp.as_ref().map(|s| parse_ports(s)).transpose() {
        Ok(Some(ports)) => ports,                    // User provided ports
        Ok(None) => DEFAULT_TCP_PORTS.to_vec(),      // Use defaults
        Err(e) => return Err(e.into()),              // Parsing error
    };

    // Parse UDP ports or use defaults (same pattern as TCP)
    let udp_ports = match cli.udp.as_ref().map(|s| parse_ports(s)).transpose() {
        Ok(Some(ports)) => ports,
        Ok(None) => DEFAULT_UDP_PORTS.to_vec(),
        Err(e) => return Err(e.into()),
    };

    if tcp_ports.is_empty() && udp_ports.is_empty() {
        return Err("select at least one TCP or UDP port".into());
    }

    let target_raw = cli
        .target
        .clone()
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let target = resolve_target(&target_raw, cli.no_dns).await?;

    let rate_limiter = cli.rate.map(|pps| Arc::new(RateLimiter::new(pps)));
    let config = Arc::new(ScanConfig {
        timeout,
        retries: cli.retries,
        target_ip: target.resolved,
        rate_limiter,
    });

    // Build a list of all scan jobs (TCP ports + UDP ports)
    let mut jobs = Vec::new();
    jobs.extend(tcp_ports.iter().copied().map(|port| ScanJob {
        port,
        protocol: Protocol::Tcp,
    }));
    jobs.extend(udp_ports.iter().copied().map(|port| ScanJob {
        port,
        protocol: Protocol::Udp,
    }));

    // Execute all scan jobs concurrently with controlled concurrency
    //
    // ## How This Works
    //
    // 1. `stream::iter(...)` - Creates a stream from our job iterator
    // 2. `.map(|job| async move { ... })` - Converts each job into a Future (async task)
    // 3. `.buffer_unordered(N)` - Executes up to N futures concurrently, completing in any order
    // 4. `.collect::<Vec<_>>()` - Gathers all results into a vector
    //
    // ## Why buffer_unordered?
    //
    // Unlike `.buffer(N)` which maintains order, `buffer_unordered` allows results to complete
    // in any order. This is more efficient because faster probes (e.g., closed ports that
    // immediately RST) don't wait behind slower probes (e.g., filtered ports that timeout).
    //
    // ## Arc::clone() Pattern
    //
    // Each async task gets its own Arc clone, which increments the reference count but
    // doesn't clone the actual data. When the task completes, the Arc is dropped and
    // the reference count decrements. This is how we share the config safely.
    let mut results = stream::iter(jobs.into_iter().map(|job| {
        let cfg = Arc::clone(&config);
        async move { execute_job(job, cfg).await }
    }))
    .buffer_unordered(cli.concurrency)
    .collect::<Vec<_>>()
    .await;

    results.sort_by(|a, b| a.port.cmp(&b.port).then_with(|| a.proto.cmp(&b.proto)));

    if cli.json {
        let report = JsonReport {
            target: JsonTarget {
                input: target.input.clone(),
                resolved: target.resolved.to_string(),
            },
            settings: JsonSettings {
                tcp_ports,
                udp_ports,
                timeout_seconds: timeout.as_secs_f64(),
                retries: cli.retries,
                concurrency: cli.concurrency,
                rate: cli.rate,
            },
            results,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render_markdown(&target, &results);
    }

    Ok(())
}

/// Executes a single scan job (TCP or UDP port scan).
///
/// This function is called concurrently for each port to be scanned.
/// Rate limiting happens here before delegating to protocol-specific functions.
async fn execute_job(job: ScanJob, config: Arc<ScanConfig>) -> ScanResult {
    // If rate limiting is enabled, wait for permission before scanning
    if let Some(limiter) = &config.rate_limiter {
        limiter.wait().await;
    }

    // Delegate to the appropriate protocol-specific scanner
    match job.protocol {
        Protocol::Tcp => scan_tcp(job.port, &config).await,
        Protocol::Udp => scan_udp(job.port, &config).await,
    }
}

/// Performs a TCP connect scan on a single port.
///
/// ## TCP Scanning Fundamentals
///
/// TCP is a connection-oriented protocol that uses a three-way handshake:
/// 1. Client sends SYN (synchronize)
/// 2. Server responds with SYN-ACK (if port is open) or RST (if port is closed)
/// 3. Client sends ACK to complete the connection
///
/// This scanner uses full `connect()` calls, which complete the entire handshake.
/// This makes it slower than "SYN scan" (which only sends SYN) but doesn't require
/// raw socket privileges.
///
/// ## Port States
///
/// - **open**: `connect()` succeeded - server accepted the connection
/// - **closed**: Received RST packet - server actively rejected connection
/// - **filtered**: No response within timeout - likely blocked by firewall
///
/// ## Retry Logic
///
/// We only retry on timeouts, not on definitive errors (like connection refused).
/// This is because timeouts could be transient network issues, but an RST or other
/// error is a definitive answer from the target or network.
async fn scan_tcp(port: u16, config: &ScanConfig) -> ScanResult {
    let addr = SocketAddr::new(config.target_ip, port);
    // Default to filtered state in case all attempts time out
    let mut state = "filtered".to_string();
    let mut reason = format!("timed out after {:.1}s", config.timeout.as_secs_f64());

    // Attempt initial probe + retries (e.g., retries=1 means 2 total attempts)
    for attempt in 0..=config.retries {
        // Wrap the connect() in a timeout to avoid hanging indefinitely
        let probe = timeout(config.timeout, TcpStream::connect(addr)).await;
        match probe {
            // Success: connect() completed within timeout
            Ok(Ok(stream)) => {
                // Explicitly drop the connection - we don't need to keep it open
                drop(stream);
                state = "open".to_string();
                reason = "connect() succeeded".to_string();
                break; // No need to retry on success
            }
            // connect() returned an error (not a timeout)
            Ok(Err(err)) => {
                state = "closed".to_string();
                // Match on different error kinds to provide educational feedback
                reason = match err.kind() {
                    // ConnectionRefused = server sent RST packet (port is closed)
                    std::io::ErrorKind::ConnectionRefused => {
                        "connect() refused (RST from target)".to_string()
                    }
                    // Connection was reset during the handshake process
                    std::io::ErrorKind::ConnectionReset => {
                        "connection reset during handshake".to_string()
                    }
                    // System-level permission issue (not common but possible)
                    std::io::ErrorKind::PermissionDenied => {
                        "permission denied (target rejected)".to_string()
                    }
                    // Address not reachable - could be routing issue or firewall
                    std::io::ErrorKind::AddrNotAvailable => {
                        "address not available (likely filtered)".to_string()
                    }
                    // Catch-all for any other error types
                    other => format!("connect() failed: {}", other),
                };
                break; // Definitive error - no point in retrying
            }
            // Timeout occurred (outer timeout wrapper triggered)
            Err(_) if attempt == config.retries => {
                // This was our last retry - mark as filtered
                state = "filtered".to_string();
                reason = format!(
                    "timed out after {:.1}s (no SYN/ACK or RST)",
                    config.timeout.as_secs_f64()
                );
                // Note: No break needed, loop will end naturally
            }
            Err(_) => {
                // Intermediate timeout on an earlier attempt - continue to next retry
                // This could be transient packet loss or network congestion
                continue;
            }
        }
    }

    ScanResult {
        port,
        proto: Protocol::Tcp.as_table_label().to_string(),
        state,
        service: guess_service(port),
        reason,
    }
}

/// Performs a UDP scan on a single port.
///
/// ## UDP Scanning Fundamentals
///
/// UDP is a connectionless, stateless protocol - it doesn't have a handshake like TCP.
/// This makes scanning UDP much more ambiguous:
///
/// - If we send a UDP packet and receive a response: **Port is OPEN**
/// - If we receive ICMP "Port Unreachable": **Port is CLOSED**
/// - If we receive nothing: **Port could be OPEN or FILTERED** (we can't tell!)
///
/// Many UDP services don't respond to random data, so silence doesn't mean closed.
/// Firewalls may silently drop UDP packets, also causing silence.
/// This is why UDP results are often reported as "open|filtered".
///
/// ## Implementation Details
///
/// 1. We send a single null byte (minimal probe)
/// 2. We wait for a response within the timeout period
/// 3. We interpret the results based on what we receive (or don't receive)
///
/// ## Why bind() once instead of per-attempt?
///
/// Creating a new UDP socket for each retry would:
/// - Waste system resources (file descriptors)
/// - Be problematic in sandboxed environments that restrict socket creation
/// - Be slower due to repeated syscalls
///
/// By binding once and reusing the socket, we're more efficient and reliable.
///
/// ## connect() on UDP?
///
/// Yes! Even though UDP is connectionless, you can still "connect" a UDP socket.
/// This doesn't establish a connection, but it:
/// - Associates the socket with a specific remote address
/// - Allows us to use send()/recv() instead of sendto()/recvfrom()
/// - Enables the kernel to deliver ICMP errors (like Port Unreachable) to our socket
async fn scan_udp(port: u16, config: &ScanConfig) -> ScanResult {
    let remote = SocketAddr::new(config.target_ip, port);
    // Default to open|filtered (the most common result for UDP scans)
    let mut state = "open|filtered".to_string();
    let mut reason = format!("no reply after {:.1}s", config.timeout.as_secs_f64());

    // Determine the appropriate bind address based on target IP version
    // We bind to UNSPECIFIED (0.0.0.0 for IPv4, :: for IPv6) on port 0 (OS chooses port)
    let bind_addr = match config.target_ip {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };

    // Bind the UDP socket once for all retries.
    // This is more efficient than binding a new socket for each attempt.
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(sock) => sock,
        Err(err) => {
            state = "error".to_string();
            reason = match err.kind() {
                // Some environments (containers, sandboxes) restrict UDP socket creation
                std::io::ErrorKind::PermissionDenied => {
                    "binding UDP socket requires elevated privileges or a looser sandbox"
                        .to_string()
                }
                _ => format!("bind() failed: {}", err),
            };
            // Early return - can't proceed without a socket
            return ScanResult {
                port,
                proto: Protocol::Udp.as_table_label().to_string(),
                state,
                service: guess_service(port),
                reason,
            };
        }
    };

    // "Connect" the UDP socket to associate it with the remote address
    // This allows ICMP errors to be delivered to our socket
    if let Err(err) = socket.connect(remote).await {
        state = "error".to_string();
        reason = format!("connect() failed: {}", err);
        return ScanResult {
            port,
            proto: Protocol::Udp.as_table_label().to_string(),
            state,
            service: guess_service(port),
            reason,
        };
    }

    // Retry loop for UDP probes
    for attempt in 0..=config.retries {
        // Send a minimal probe (single null byte)
        // Most UDP services will either ignore it or send an error response
        if let Err(err) = socket.send(&[0u8]).await {
            state = "error".to_string();
            reason = format!("send() failed: {}", err);
            break;
        }

        // Prepare a buffer to receive potential response data
        let mut buf = [0u8; 512];
        let recv = timeout(config.timeout, socket.recv(&mut buf)).await;

        match recv {
            // Received data - port is definitely open!
            Ok(Ok(n)) => {
                // Show a preview of the received data (useful for learning)
                let preview = String::from_utf8_lossy(&buf[..n.min(16)]);
                state = "open".to_string();
                reason = format!("received {} bytes (\"{}\"...)", n, preview);
                break;
            }
            // ConnectionRefused error = kernel received ICMP Port Unreachable
            // This is the ONLY definitive way to know a UDP port is closed
            Ok(Err(err)) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
                state = "closed".to_string();
                reason = "ICMP Port Unreachable received".to_string();
                break;
            }
            // Some other error occurred during recv()
            Ok(Err(err)) => {
                state = "error".to_string();
                reason = format!("recv() failed: {}", err);
                break;
            }
            // Timeout on the last retry - no definitive answer
            Err(_) if attempt == config.retries => {
                state = "open|filtered".to_string();
                reason = format!("no reply after {:.1}s", config.timeout.as_secs_f64());
            }
            // Timeout on an intermediate attempt - try again
            Err(_) => continue,
        }
    }

    ScanResult {
        port,
        proto: Protocol::Udp.as_table_label().to_string(),
        state,
        service: guess_service(port),
        reason,
    }
}

/// Renders scan results as a Markdown table.
///
/// ## Formatting Details
///
/// The table uses Markdown alignment syntax:
/// - `|-----:|` - Right-aligned (for port numbers)
/// - `|:-----:|` - Center-aligned (for protocol)
/// - `|:------|` - Left-aligned (for state, service, reason)
///
/// The `println!` formatting codes:
/// - `{:>4}` - Right-align in 4 characters
/// - `{:^5}` - Center-align in 5 characters
/// - `{:<12}` - Left-align in 12 characters
fn render_markdown(target: &TargetInfo, results: &[ScanResult]) {
    // Show hostname and IP if different, otherwise just IP
    if target.input == target.resolved.to_string() {
        println!("Scanning {}", target.resolved);
    } else {
        println!("Scanning {} ({})", target.input, target.resolved);
    }

    // Print Markdown table header
    println!("| Port | Proto | State | Service (guess) | Reason |");
    println!("|-----:|:-----:|:------|:-----------------|:-------|");

    // Print each result as a table row
    for result in results {
        println!(
            "| {:>4} | {:^5} | {:<12} | {:<15} | {} |",
            result.port, result.proto, result.state, result.service, result.reason
        );
    }
}

/// Resolves a target string to an IP address.
///
/// ## Resolution Logic
///
/// 1. First, try to parse the target as an IP address directly
/// 2. If that fails and DNS is enabled, perform a DNS lookup
/// 3. If `--no-dns` is set, reject non-IP inputs with an error
///
/// ## Why Support Both?
///
/// - Direct IP: Faster, no DNS overhead, works in restricted networks
/// - Hostname: More user-friendly, handles dynamic IPs
///
/// ## Error Handling
///
/// We use `Result<T, Box<dyn Error>>` which is a common Rust pattern for functions
/// that can fail in multiple ways. The `Box<dyn Error>` allows us to return any
/// error type, making this function flexible and easy to work with.
async fn resolve_target(target: &str, no_dns: bool) -> Result<TargetInfo, Box<dyn Error>> {
    // Attempt to parse as IP address first (fastest path)
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(TargetInfo {
            input: target.to_string(),
            resolved: ip,
        });
    }

    // If it's not a valid IP and DNS is disabled, fail early
    if no_dns {
        return Err(format!("unable to parse IP address: {target}").into());
    }

    // Perform DNS lookup using Tokio's async resolver
    // lookup_host returns a stream of SocketAddr results
    let addrs: Vec<IpAddr> = lookup_host((target, 0))
        .await?
        .map(|sock| sock.ip())
        .collect();

    // Take the first resolved address (usually the A or AAAA record)
    // In production scanners, you might want to handle multiple IPs differently
    let resolved = addrs
        .first()
        .copied()
        .ok_or_else(|| format!("DNS lookup returned no addresses for {target}"))?;

    Ok(TargetInfo {
        input: target.to_string(),
        resolved,
    })
}

/// Parses a comma-separated list of ports and port ranges.
///
/// ## Accepted Formats
///
/// - Individual ports: `"22,80,443"`
/// - Ranges: `"1000-1010"`
/// - Mixed: `"22,80,1000-1010,443"`
/// - Whitespace is trimmed
///
/// ## Why BTreeSet?
///
/// We use `BTreeSet` instead of `Vec` for several reasons:
/// 1. **Automatic deduplication**: `"22,22,22"` becomes just `22`
/// 2. **Automatic sorting**: Results come out in numerical order
/// 3. **Efficient insertion**: O(log n) for each port
///
/// This is a great example of choosing the right data structure for the job!
fn parse_ports(input: &str) -> Result<Vec<u16>, String> {
    let mut ports = BTreeSet::new();

    // Split by commas and process each part
    for part in input.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue; // Skip empty parts (handles trailing commas gracefully)
        }

        // Check if this part is a range (contains '-')
        if let Some((start, end)) = trimmed.split_once('-') {
            let start = parse_port_number(start)?;
            let end = parse_port_number(end)?;
            // Validate that the range makes sense
            if start > end {
                return Err(format!("invalid port range: {trimmed}"));
            }
            // Insert all ports in the range (inclusive on both ends)
            for port in start..=end {
                ports.insert(port);
            }
        } else {
            // Single port number
            let port = parse_port_number(trimmed)?;
            ports.insert(port);
        }
    }

    // Convert BTreeSet to Vec - maintains sorted order
    Ok(ports.into_iter().collect())
}

/// Parses and validates a single port number string.
///
/// ## Port Number Constraints
///
/// - Valid range: 1-65535 (u16::MAX)
/// - Port 0 is reserved and not scannable
/// - We parse as u32 first to detect numbers > 65535
///
/// ## Error Handling Pattern
///
/// This function demonstrates Rust's `Result` type for error handling:
/// - `map_err()` converts parsing errors to custom error messages
/// - Early returns with `?` operator propagate errors up the call stack
/// - Clear error messages help users understand what went wrong
fn parse_port_number(input: &str) -> Result<u16, String> {
    // Parse as u32 first to catch values > 65535
    let parsed = u32::from_str(input).map_err(|_| format!("invalid port number: {input}"))?;
    // Validate the range (ports are 1-65535)
    if parsed == 0 || parsed > u16::MAX as u32 {
        return Err(format!("port out of range: {input}"));
    }
    // Safe to cast now that we've validated the range
    Ok(parsed as u16)
}

/// Provides a best-guess service name for a given port number.
///
/// ## Educational Purpose
///
/// This function demonstrates the common association between port numbers and services
/// based on IANA (Internet Assigned Numbers Authority) port registry. These are
/// **conventions**, not guarantees - any service can run on any port.
///
/// ## Why "guess"?
///
/// We explicitly call this a "guess" because:
/// - Ports can be reconfigured (SSH on 2222, HTTP on 8080, etc.)
/// - Multiple services might claim the same port
/// - Some ports are ambiguous (different services on TCP vs UDP)
///
/// Real service identification requires banner grabbing or protocol-specific probes.
///
/// ## Implementation Note
///
/// We use a `match` statement which:
/// - Is exhaustive (compiler checks all cases are handled)
/// - Is optimized by the compiler (often into a jump table)
/// - Provides clear, readable code
fn guess_service(port: u16) -> String {
    match port {
        7 => "echo",
        20 => "ftp-data",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        67 => "dhcp",
        68 => "dhcp",
        69 => "tftp",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        123 => "ntp",
        135 => "epmap",
        137 => "netbios-ns",
        138 => "netbios-dgm",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        162 => "snmptrap",
        443 => "https",
        445 => "microsoft-ds",
        465 => "smtps",
        500 => "isakmp",
        587 => "submission",
        590 => "http-alt",
        993 => "imaps",
        995 => "pop3s",
        1025 => "blackjack",
        1723 => "pptp",
        1900 => "ssdp",
        2049 => "nfs",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        3478 => "stun",
        3690 => "svn",
        5060 => "sip",
        5222 => "xmpp-client",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        8080 => "http-alt",
        8443 => "https-alt",
        _ => "unknown",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ports_mixes_ranges_and_values() {
        let ports = parse_ports("80, 1000-1002, 443").unwrap();
        assert_eq!(ports, vec![80, 443, 1000, 1001, 1002]);
    }

    #[test]
    fn parse_ports_rejects_invalid_range() {
        assert!(parse_ports("100-99").is_err());
    }

    #[test]
    fn parse_ports_rejects_zero() {
        assert!(parse_ports("0").is_err());
    }

    #[test]
    fn guess_service_matches_known_port() {
        assert_eq!(guess_service(22), "ssh");
        assert_eq!(guess_service(1900), "ssdp");
    }

    #[test]
    fn guess_service_defaults_to_unknown() {
        assert_eq!(guess_service(6553), "unknown");
    }
}
