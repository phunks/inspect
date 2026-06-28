# TODO / Roadmap

## Near-term

- [ ] Show pre-HTTP connection errors in the TUI
    - BoringSSL accept failures
    - upstream CONNECT failures
    - upstream TLS handshake failures
    - Requires provisional connection context before `RequestDispatchContext`.

- [ ] Improve Roto action ergonomics
    - `RequestAction.pass()` is currently required as builder entrypoint.
    - Consider constructor helpers if Roto supports a clean naming scheme.

- [ ] Improve outbound HTTP observability
    - Show enqueue/drop/send failures in logs or TUI.
    - Include client name, path, timeout, and status.

## Filters / Roto

- [ ] Add safer JSON building helpers for Roto
    - Avoid manually escaped JSON strings.
    - Useful for Logstash/SIEM/Snort-style event payloads.

- [ ] Expose more request/response fields to Roto
    - headers
    - body metadata
    - flow id / flow key
    - elapsed time

## TUI

- [ ] Display request marks more clearly
- [ ] Show proxy/upstream error reason in detail pane
- [ ] Add filter/action info to flow detail

## Capture / Storage

- [ ] Decide how to store connection-level failures
- [ ] Consider indexing marks/tags/notes in DB

## Integrations

- [ ] Document Logstash outbound HTTP example
- [ ] Document Snort raw HTTP forwarding example
- [ ] Consider syslog / webhook presets