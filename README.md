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

## Build
```bash
cargo build
```

## Setup
### CA
Generate a local CA certificate for client trust setup:
$HOME/.inspect/mitm-root-ca.crt
```bash
cargo run -- --generate-ca
```
### Client trust
Trust the local CA certificate for client trust setup:
$HOME/.inspect/mitm-root-ca.crt

## Run
```bash
cargo run -- --ip 127.0.0.1 --port 62019
```

## CLI options
```text
 --ip Bind address (default: 127.0.0.1)
 --port Bind port (default: 62019)
 --upstream-proxy Upstream HTTP proxy
 --generate-ca Generate a local CA certificate
 --force-regenerate-ca Force regeneration of local CA certificate
 -v Increase log verbosity
 -q Suppress logs
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

You can override the capture root with:
```bash
INSPECT_CAPTURE_DIR=./my-captures
cargo run -- --port 62019
```

## TUI keys
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
- CA certificate can be generated/exported locally for client trust setup
- Metadata is stored in SQLite using SQLx
- Non-text bodies may be rendered as hex for inspection

## Status
This project is still under active development.

Current rough edges include:
- the detail pane is still minimal and not yet well structured
- documentation and setup flow are still evolving

## TODO
- document SQLx / database development workflow
- polish capture browsing experience in the TUI