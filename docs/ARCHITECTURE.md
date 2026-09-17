# Architecture and flow

Two views of `secondeye`: the operator's end-to-end workflow, and the
per-connection scope decision the daemon makes internally. See the main
[README](../README.md) for full command usage.

## Operator workflow

```mermaid
flowchart TD
    A[Install secondeye via pipx from GitHub] --> B[secondeye ca export, then trust the CA in browser or device]
    B --> C{Chaining through Burp or ZAP?}
    C -->|Yes| D[secondeye ca import-upstream --from-burp]
    C -->|No| E[Plan to use --no-upstream]
    D --> F[Terminal 1: secondeye proxy start --target domain]
    E --> F
    F --> G[Point client proxy settings at 127.0.0.1:8079]
    G --> H[Traffic flows normally, nothing recorded yet]
    H --> I[Terminal 2: secondeye capture start --name label]
    I --> J[Drive the target through the client: browser clicks, curl, other tooling]
    J --> K[secondeye capture stop]
    K --> L[raw.har, manifest.json, and ANALYSIS.md written to disk]
    L --> M[Paste ANALYSIS.md into an AI chat for flow analysis]
    M --> N{More scenarios to capture?}
    N -->|Yes| I
    N -->|No| O[Ctrl+C the daemon, which auto-flushes any active capture]
```

## Per-connection scope decision

```mermaid
flowchart TD
    A[Client connects via CONNECT or plain HTTP] --> B[Buffer the TLS ClientHello and parse SNI]
    B --> C{SNI matches scope via target, target-regex, or capture-all?}
    C -->|No| D[Blind TCP relay of raw bytes, zero TLS operations]
    C -->|Yes| E[Terminate TLS with a per-SNI leaf cert signed by secondeye's CA]
    E --> F[Parse as HTTP/1.1 via h11]
    F --> G{Capture currently active?}
    G -->|Yes| H[Record request and response to the capture buffer]
    G -->|No| I[Nothing written to disk]
    H --> J{--no-upstream set?}
    I --> J
    J -->|No| K[Forward to upstream Burp or ZAP]
    J -->|Yes| L[Connect directly to the destination]
```
