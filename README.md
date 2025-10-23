# Educational Network Scanner (Rust)

This project builds an educational port scanner that implements the requirements in `SPECIFICATIONS.md`. The goal is to keep the code approachable while demonstrating how real-world scanning primitives behave.

## Highlights
- Preloaded default scan set: top 25 TCP ports and top 5 UDP ports derived from common service frequency data.
- TCP connect() scanning and UDP best-effort probing with human-readable state reasons.
- DNS resolution with a `--no-dns` escape hatch, optional JSON output, and Markdown tables by default.
- Concurrency and rate limiting controls so learners can experiment with probe volume safely.
- Simple service name guesses sourced from IANA registrations (clearly labelled as guesses).

## Getting Started
```bash
cargo run -- --help
```

The help output explains each flag, including why UDP scans often end up in an `open|filtered` state.

## Run the Scanner
Compile and launch directly with Cargo:

```bash
cargo run -- <flags> <target>
```

Example local scan:

```bash
cargo run -- --tcp 22,80 --udp 53 localhost
```

For repeated scans without recompiling each time:

```bash
cargo build --release
./target/release/scanner --tcp 22,80 --udp 53 localhost
```

## CLI
```
scanner [--tcp PORTS] [--udp PORTS] [--timeout SECONDS] [--retries N] \
        [--concurrency N] [--rate PPS] [--no-dns] [--json] <target>
```

- `<target>` defaults to `127.0.0.1`. Hostnames are resolved unless `--no-dns` is supplied.
- `PORTS` accepts comma-separated numbers and ranges (e.g., `22,53,1000-1010`).
- `--timeout` controls the socket timeout in seconds; `--retries` only replays probes that timed out.
- `--concurrency` caps simultaneous probes; `--rate` optionally throttles total probes per second.
- `--json` switches the Markdown table to a structured JSON report.

## Example
```
cargo run -- --tcp 22,80 --udp 53 localhost
```

Example Markdown output:

```markdown
Scanning localhost (127.0.0.1)
| Port | Proto | State | Service (guess) | Reason |
|-----:|:-----:|:------|:-----------------|:-------|
|   22 |  TCP  | closed        | ssh             | connect() refused (RST from target) |
|   53 |  UDP  | open|filtered | dns             | no reply after 3.0s |
|   80 |  TCP  | closed        | http            | connect() refused (RST from target) |
```

Your results will vary based on the services that are actually reachable from your machine.

## Notes & Limitations
- TCP scans use standard `connect()` calls. That keeps the tool unprivileged at the cost of speed (no half-open SYN scans).
- UDP scans treat `ICMP Port Unreachable` as closed. Silence is reported as `open|filtered`, mirroring how ambiguous UDP results are in practice.
- Rate limiting relies on Tokio timers; extraordinarily high probe rates may still be constrained by the host scheduler.
- Some sandboxed or containerized environments block UDP sockets entirely; when that happens the scanner reports an `error` state rather than failing the whole run.
- Banner grabbing and service verification are deliberately omitted to keep the code concise.

## Development
```bash
cargo check
```

`cargo fmt` requires the Rustfmt component. If it is not installed in your toolchain, add it with `rustup component add rustfmt`.

Refer to [`AGENTS.md`](AGENTS.md) for detailed contributor guidelines, coding standards, and review expectations.

## Educational Focus

This scanner is **heavily documented** for educational purposes. The source code includes:

- **Module-level documentation** explaining the overall architecture and key concepts
- **Function-level documentation** describing what each function does and why
- **Inline comments** explaining tricky code sections and Rust idioms
- **Educational sections** highlighting important concepts like:
  - Async/await patterns with Tokio
  - Concurrent stream processing with `buffer_unordered`
  - Rate limiting using cooperative token buckets
  - TCP vs UDP scanning differences
  - Error handling with `Result` types
  - Rust traits and derive macros

Students are encouraged to:
1. Read the source code in `src/main.rs` from top to bottom
2. Run the scanner with different flags to see how behavior changes
3. Modify the default port lists to focus on specific services
4. Experiment with concurrency and rate limiting settings
5. Extend the scanner with new features (IPv6, custom payloads, etc.)

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
