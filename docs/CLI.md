# CLI reference

Every help block on this page is captured from the real argument parser by
`scripts/generate_doc_examples.py` and verified by `tests/test_doc_examples.py`
— if a flag is renamed and this page isn't regenerated, the test suite goes
red. Don't edit between the `BEGIN GENERATED` / `END GENERATED` markers; change
the parser in [`src/secondeye/cli.py`](../src/secondeye/cli.py) and re-run:

```sh
python scripts/generate_doc_examples.py
```

The prose around each block is hand-written and safe to edit.

> **Note on scope flags:** at least one of `--target`, `--target-file`,
> `--target-regex`, or `--target-all` is required. Each is a legitimate
> standalone scope mechanism; they're OR'd together when combined.

---

## `secondeye`

<!-- BEGIN GENERATED: cli-help-root -->
```text
usage: secondeye [-h] [--version] {proxy,capture,ca} ...

A scope-gated, passive HTTP/HTTPS recording proxy for offensive security operators.

positional arguments:
  {proxy,capture,ca}
    proxy             Run and control the recording proxy daemon.
    capture           Control recording windows against a running proxy daemon.
    ca                Manage secondeye's root CA and upstream trust.

options:
  -h, --help          show this help message and exit
  --version, -V       show program's version number and exit
```
<!-- END GENERATED: cli-help-root -->

---

## `secondeye proxy start`

The main entry point: starts the daemon in the foreground and keeps it running
until `Ctrl+C` or `secondeye proxy stop`. Any active capture is auto-flushed on
exit, so you can't lose a capture by forgetting to stop it first.

<!-- BEGIN GENERATED: cli-help-proxy-start -->
```text
usage: secondeye proxy start [-h] [--target TARGET] [-tf TARGET_FILE]
                             [--target-regex TARGET_REGEX] [--listen-address LISTEN_ADDRESS]
                             [--upstream-proxy UPSTREAM_PROXY] [--no-upstream]
                             [--upstream-ca UPSTREAM_CA] [--upstream-insecure] [--target-all]
                             [--cluster-window CLUSTER_WINDOW] [--max-connections MAX_CONNECTIONS]
                             [-v] [-q]

Start the secondeye daemon in the foreground. Stays running until Ctrl+C or 'secondeye proxy
stop', auto-flushing any active capture on exit.

options:
  -h, --help            show this help message and exit
  --target TARGET       A domain to scope in, matched exactly plus all subdomains, or an explicit
                        glob (e.g. '*.corp.internal'). Repeatable. At least one of --target,
                        --target-file, --target-regex, or --target-all is required.
  -tf, --target-file TARGET_FILE
                        A line-delimited file of --target-style entries (one per line; blank lines
                        and lines starting with # are ignored). Repeatable, and merges with any
                        --target values. Satisfies the 'at least one target' requirement on its
                        own.
  --target-regex TARGET_REGEX
                        A regular expression to scope in, for patterns a glob can't express
                        (alternation, numeric ranges, wildcards on both sides). Repeatable. Prefer
                        --target/--target-file for the common case.
  --listen-address LISTEN_ADDRESS
                        The host:port the proxy listens on, as 'host:port' (e.g. '[::1]:8079' for
                        IPv6). Host must be loopback (127.0.0.1 or ::1) — no override exists.
                        Default: 127.0.0.1:8079.
  --upstream-proxy UPSTREAM_PROXY
                        The upstream intercepting proxy's host:port (e.g. Burp or ZAP) to chain
                        in-scope traffic through. Ignored if --no-upstream is set. Default:
                        127.0.0.1:8080.
  --no-upstream         Skip the upstream proxy entirely and connect directly to each destination,
                        with full system trust store validation on that leg.
  --upstream-ca UPSTREAM_CA
                        PEM file of the upstream proxy's CA certificate, used to validate the
                        secondeye-to-upstream TLS leg. Mutually exclusive with --upstream-
                        insecure. See 'secondeye ca import-upstream' to fetch one.
  --upstream-insecure   Skip TLS verification on the upstream leg only (logs a warning at
                        startup). Mutually exclusive with --upstream-ca.
  --target-all          Bypass scope matching entirely: every domain is terminated/inspected for
                        the life of this daemon. Useful for flows that redirect through third-
                        party domains (OAuth/OIDC) that --target was never meant to enumerate.
                        Recording still only happens while a capture is active.
  --cluster-window CLUSTER_WINDOW
                        Milliseconds within which repeated near-identical requests (e.g. polling)
                        are clustered together in ANALYSIS.md instead of listed individually.
                        Default: 2000.
  --max-connections MAX_CONNECTIONS
                        Maximum number of simultaneous client connections the proxy will accept.
                        Default: 256.
  -v, --verbose         Log at DEBUG level instead of INFO.
  -q, --quiet           Log at WARNING level instead of INFO.
```
<!-- END GENERATED: cli-help-proxy-start -->

---

## `secondeye proxy status`

<!-- BEGIN GENERATED: cli-help-proxy-status -->
```text
usage: secondeye proxy status [-h]

Report whether a daemon is running, its scope, and active capture.

options:
  -h, --help  show this help message and exit
```
<!-- END GENERATED: cli-help-proxy-status -->

---

## `secondeye capture start`

<!-- BEGIN GENERATED: cli-help-capture-start -->
```text
usage: secondeye capture start [-h] --name NAME

Start recording a named window of in-scope traffic.

options:
  -h, --help   show this help message and exit
  --name NAME  A label for this capture. Must be unique among today's captures for the current
               target; used in the output directory name.
```
<!-- END GENERATED: cli-help-capture-start -->

---

## `secondeye capture stop`

Writes `raw.har`, `manifest.json`, and `ANALYSIS.md` to the capture's output
directory. See [examples/ANALYSIS.sample.md](examples/ANALYSIS.sample.md) for a
complete worked example of what the analysis document looks like.

<!-- BEGIN GENERATED: cli-help-capture-stop -->
```text
usage: secondeye capture stop [-h]

Stop the active capture and write raw.har/manifest.json/ANALYSIS.md.

options:
  -h, --help  show this help message and exit
```
<!-- END GENERATED: cli-help-capture-stop -->

---

## `secondeye ca export`

Writes the root CA certificate to stdout, for importing into a browser or
passing to a client as `--cacert`. The first-run note goes to stderr, so
redirecting stdout gives you clean certificate bytes.

<!-- BEGIN GENERATED: cli-help-ca-export -->
```text
usage: secondeye ca export [-h] [--format {der,pem}]

Export secondeye's root CA for import into a browser/device trust store.

options:
  -h, --help          show this help message and exit
  --format {der,pem}  Output encoding, written to stdout. Default: pem.
```
<!-- END GENERATED: cli-help-ca-export -->
