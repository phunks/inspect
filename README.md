# inspect

`inspect` is a Rust-based HTTP/HTTPS MITM proxy with a terminal UI for live traffic inspection.

It captures request/response metadata into SQLite and stores raw headers/bodies on disk per flow.

## Features
- HTTP and HTTPS proxying
- MITM inspection for TLS traffic
- Live terminal UI for captured packets
- SQLite-backed metadata storage
- Per-flow request/response header and body dumps
- Optional upstream proxy support
- Optional SSL key log file output for TLS debugging
- File-based structured logging via `tracing_subscriber`

## Build
```bash
cargo build
```

## Setup
### CA
Generate a local CA certificate for client trust setup:
```text
$HOME/.inspect/mitm-root-ca.crt
```

```bash
cargo run -- --generate-ca
```

## Run
```bash
cargo run -- --ip 127.0.0.1 --port 62019
```

## Usage
```text
Usage: inspect [OPTIONS]

Options:
  -p, --port <PORT>
          Set port to listen on [default: 62019]
  -i, --ip <IP>
          Set ip to listen on [default: 127.0.0.1]
  -v...
          Log verbosity level. -vv for more verbosity. Environmental variable `RUST_LOG` overrides this flag!
      --upstream-proxy [<UPSTREAM_PROXY>]

      --generate-ca
          Generate (or reuse) persistent local MITM root CA and exit
      --force-regenerate-ca
          Force regenerate local MITM root CA
      --preshared-key-log [<PRESHARED_KEY_LOG>]
          SSLKEYLOGFILE environment variable
  -h, --help
          Print help
  -V, --version
          Print version
```

## Output
Capture data is written under `capture/<timestamp>/`.

Typical layout:
```text
capture/
 20260602143000Z/
  index.sqlite
  flows/
   000001-xxxxxxxx/
    request.head
    request.body
    response.head
    response.body
```

## TUI keys
- `q` / `Ctrl+C`: quit
- `j` / `Down`: move down
- `k` / `Up`: move up
- `J` / `Shift+Down`: page down
- `K` / `Shift+Up`: page up
- `G`: jump to bottom
- `Enter` / `l`: open details

## Notes
- HTTPS inspection requires trusting the local CA/certificate used by the proxy.
- Bodies are stored with a size limit, so large payloads may be truncated.
- This project is intended for local debugging and traffic analysis.
- CA certificate can be generated/exported locally for client trust setup.
- Metadata is stored in SQLite using SQLx.
- Non-text bodies may be rendered as hex for inspection.
- The packet detail view includes the flow directory for easier correlation with on-disk captures.


