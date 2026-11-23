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

> **Note on upstream trust:** `proxy start` also requires exactly one of
> `--upstream-ca`, `--upstream-insecure`, or `--no-upstream`. There is no
> default, by design: how the secondeye-to-upstream TLS leg is trusted is a
> decision worth making explicitly rather than inheriting.

---

## `secondeye`

<!-- BEGIN GENERATED: cli-help-root -->
```text
usage: secondeye [-h] [--version] COMMAND ...

A scope-gated, passive HTTP/HTTPS recording proxy for offensive security operators. Terminate and
record only the traffic you are scoped for; everything else is relayed blind and never touched.

Commands
  proxy    Run and control the recording proxy daemon.
  capture  Control recording windows, and revisit finished captures.
  doctor   Check whether this machine is ready to capture, and say what isn't.
  ca       Manage secondeye's root CA and upstream trust.

Options
  -h, --help     show this help message and exit
  --version, -V  show program's version number and exit

Examples
  # One-time setup: trust secondeye's CA in your browser.
  secondeye ca install
  # Check this machine is ready before an engagement.
  secondeye doctor
  # Terminal 1: run the daemon, chaining through Burp.
  secondeye proxy start --target example.com --upstream-ca burp-ca.pem
  # Terminal 2: record a window of traffic, then write it up.
  secondeye capture start --name auth-flow
  secondeye capture stop
```
<!-- END GENERATED: cli-help-root -->

---

## `secondeye proxy start`

The main entry point: starts the daemon in the foreground and keeps it running
until `Ctrl+C` or `secondeye proxy stop`. Any active capture is auto-flushed on
exit, so you can't lose a capture by forgetting to stop it first.

<!-- BEGIN GENERATED: cli-help-proxy-start -->
```text
usage: secondeye proxy start [-h] [--target DOMAIN] [-tf FILE] [--target-regex REGEX] [--target-all]
                             [--upstream-proxy HOST:PORT]
                             (--upstream-ca FILE | --upstream-insecure | --no-upstream)
                             [--listen-address HOST:PORT] [--captures-dir DIR] [--cluster-window MS]
                             [--max-connections N] [-v | -q]

Start the secondeye daemon in the foreground. Stays running until Ctrl+C or 'secondeye proxy stop',
auto-flushing any active capture on exit. Requires a scope — at least one of --target,
--target-file, --target-regex or --target-all — and an explicit decision about upstream TLS trust.

Scope
  What gets terminated and inspected. At least one is required; everything you pass is OR'd
  together.

  --target DOMAIN          A domain to scope in, matched exactly plus all subdomains, or an explicit
                           glob (e.g. '*.corp.internal'). Repeatable.
  -tf, --target-file FILE  A line-delimited file of --target-style entries (one per line; blank
                           lines and lines starting with # are ignored). Repeatable, and merges with
                           any --target values.
  --target-regex REGEX     A regular expression to scope in, for patterns a glob can't express
                           (alternation, numeric ranges, wildcards on both sides). Repeatable.
                           Prefer --target/--target-file for the common case.
  --target-all             Bypass scope matching entirely: every domain is terminated/inspected for
                           the life of this daemon. Useful for flows that redirect through
                           third-party domains (OAuth/OIDC) that --target was never meant to
                           enumerate. Recording still only happens while a capture is active.

Upstream
  Whether in-scope traffic is chained through an intercepting proxy, and how that leg's TLS is
  trusted. Exactly one trust decision is required — there is no silent default.

  --upstream-proxy HOST:PORT  The upstream intercepting proxy's host:port (e.g. Burp or ZAP) to
                              chain in-scope traffic through. Default: 127.0.0.1:8080.
  --upstream-ca FILE          PEM file of the upstream proxy's CA certificate, used to validate the
                              secondeye-to-upstream TLS leg. See 'secondeye ca import-upstream' to
                              fetch one.
  --upstream-insecure         Skip TLS verification on the upstream leg only (logs a warning at
                              startup).
  --no-upstream               Skip the upstream proxy entirely and connect directly to each
                              destination, with full system trust store validation on that leg.

Listener and output
  Where the proxy listens, and where captures are written.

  --listen-address HOST:PORT  The host:port the proxy listens on (e.g. '[::1]:8079' for IPv6). Host
                              must be loopback (127.0.0.1 or ::1) — no override exists. Default:
                              127.0.0.1:8079.
  --captures-dir DIR          Directory to write capture output into, so captures can live alongside
                              your engagement notes instead of under the state directory. Default:
                              <state-dir>/captures (~/.local/state/secondeye/captures).
  --cluster-window MS         Milliseconds within which a request is grouped with the page
                              navigation that preceded it, so its static assets are summarized in
                              ANALYSIS.md rather than listed one by one. Does not affect polling
                              deduplication, which keys off request interval rather than this
                              window. Default: 2000.
  --max-connections N         Maximum number of simultaneous client connections the proxy will
                              accept. Default: 256.

Logging
  Log verbosity on stderr. The startup banner is printed either way.

  -v, --verbose  Log at DEBUG level instead of INFO.
  -q, --quiet    Log at WARNING level instead of INFO.

Options
  -h, --help  show this help message and exit

Examples
  # Chain in-scope traffic through Burp, pinning Burp's CA.
  secondeye proxy start --target example.com --upstream-ca burp-ca.pem
  # Connect straight to each destination instead.
  secondeye proxy start --target example.com --no-upstream
  # Several targets, plus a pattern a glob can't express.
  secondeye proxy start --target example.com --target '*.corp.internal' \
      --target-regex '^(dev|stg)-.*\.example\.com$' --no-upstream
```
<!-- END GENERATED: cli-help-proxy-start -->

---

## `secondeye proxy status`

<!-- BEGIN GENERATED: cli-help-proxy-status -->
```text
usage: secondeye proxy status [-h] [--json]

Report whether a daemon is running, its scope, its upstream, and the active capture's live request
count. Exits 0 whether or not one is running — 'is it running?' is a question, not an error.

Options
  -h, --help  show this help message and exit
  --json      Emit the status as JSON on stdout instead of a table, for scripting.

Examples
  secondeye proxy status
  secondeye proxy status --json | jq .active_capture
```
<!-- END GENERATED: cli-help-proxy-status -->

---

## `secondeye capture start`

<!-- BEGIN GENERATED: cli-help-capture-start -->
```text
usage: secondeye capture start [-h] --name LABEL

Start recording a named window of in-scope traffic. Requires a running daemon; only one capture may
be active at a time.

Options
  -h, --help    show this help message and exit
  --name LABEL  A label for this capture. Must be unique among today's captures for the current
                target; used in the output directory name.

Examples
  secondeye capture start --name auth-flow
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

Stop the active capture and write raw.har, manifest.json and ANALYSIS.md into its output directory.
Requires a running daemon.

Options
  -h, --help  show this help message and exit

Examples
  secondeye capture stop
```
<!-- END GENERATED: cli-help-capture-stop -->

---

## `secondeye proxy stop`

<!-- BEGIN GENERATED: cli-help-proxy-stop -->
```text
usage: secondeye proxy stop [-h]

Stop a running secondeye daemon from another terminal. Any active capture is flushed to disk first,
exactly as Ctrl+C would. Requires a running daemon.

Options
  -h, --help  show this help message and exit

Examples
  secondeye proxy stop
```
<!-- END GENERATED: cli-help-proxy-stop -->

---

## `secondeye capture list`

Reads the captures directory rather than asking the daemon, so it answers "what
have I recorded?" across every previous run, with no daemon running.

<!-- BEGIN GENERATED: cli-help-capture-list -->
```text
usage: secondeye capture list [-h] [--captures-dir DIR] [--json]

List captures on disk, newest first. Reads the captures directory, so it works with no daemon
running and shows captures from previous runs too. No daemon required.

Options
  -h, --help          show this help message and exit
  --captures-dir DIR  Captures directory to list. Default: <state-dir>/captures.
  --json              Emit the listing as JSON on stdout instead of a table, for scripting.

Examples
  secondeye capture list
  secondeye capture list --captures-dir ~/engagements/acme/captures
```
<!-- END GENERATED: cli-help-capture-list -->

---

## `secondeye capture analyze`

Re-renders `manifest.json` and `ANALYSIS.md` from a capture's `raw.har`, so a
capture recorded under an older renderer isn't frozen there. `raw.har` is never
modified.

<!-- BEGIN GENERATED: cli-help-capture-analyze -->
```text
usage: secondeye capture analyze [-h] [--cluster-window MS] DIRECTORY

Re-render manifest.json and ANALYSIS.md from an existing capture's raw.har. Use this to bring an
older capture up to the current analysis renderer, or to re-cluster it with a different
--cluster-window. raw.har is never modified. No daemon required.

Positional arguments
  DIRECTORY  A capture directory containing raw.har and manifest.json.

Options
  -h, --help           show this help message and exit
  --cluster-window MS  Clustering window in milliseconds for this re-render: how close a request
                       must be to the preceding navigation to have its assets summarized rather than
                       listed. Default: 2000.

Examples
  secondeye capture analyze ~/.local/state/secondeye/captures/2026-11-20_example-com/auth-flow
  # Re-group with a wider navigation window.
  secondeye capture analyze ./auth-flow --cluster-window 5000
```
<!-- END GENERATED: cli-help-capture-analyze -->

---

## `secondeye capture recover`

Rebuilds a capture from the incremental JSONL buffer a crashed daemon left
behind, writing the three output files `capture stop` would have.

<!-- BEGIN GENERATED: cli-help-capture-recover -->
```text
usage: secondeye capture recover [-h] [--name LABEL] [--keep-buffer] [--cluster-window MS] PATH

Rebuild a capture from the incremental JSONL buffer a crashed daemon left behind, writing the three
output files that 'capture stop' would have. No daemon required.

Positional arguments
  PATH  A capture directory containing a .buffer.jsonl, or that file itself.

Options
  -h, --help           show this help message and exit
  --name LABEL         Capture name to record in the outputs. Default: the capture directory's own
                       name.
  --keep-buffer        Leave the JSONL buffer in place instead of removing it once the capture has
                       been written.
  --cluster-window MS  Clustering window in milliseconds. Default: 2000.

Examples
  secondeye capture recover ./2026-11-20_example-com/auth-flow
  secondeye capture recover ./auth-flow/.buffer.jsonl --keep-buffer
```
<!-- END GENERATED: cli-help-capture-recover -->

---

## `secondeye doctor`

Collects the environment failures an operator would otherwise meet one at a
time. Read-only — in particular it never generates a CA, which is why
`tls/ca.py` has a `load_ca_certificate()` alongside `load_or_create_ca()`.

<!-- BEGIN GENERATED: cli-help-doctor -->
```text
usage: secondeye doctor [-h] [--listen-address HOST:PORT] [--upstream-proxy HOST:PORT]
                        [--no-upstream] [--upstream-ca FILE] [--upstream-insecure]
                        [--captures-dir DIR] [--json]

Check this machine is ready to capture: CA present and valid, state directory locked down, captures
directory writable, listen port free, upstream reachable, certutil available, shell completion
active. Changes nothing — in particular it never generates a CA. Exits non-zero if any check fails;
warnings alone exit 0.

Options
  -h, --help                  show this help message and exit
  --listen-address HOST:PORT  The host:port to test for availability. Default: 127.0.0.1:8079.
  --upstream-proxy HOST:PORT  The upstream proxy to test for reachability. Ignored with
                              --no-upstream. Default: 127.0.0.1:8080.
  --no-upstream               Check the direct-connection setup instead of an upstream proxy.
  --upstream-ca FILE          Check that this upstream CA file exists and is readable.
  --upstream-insecure         Check the setup that skips upstream TLS verification.
  --captures-dir DIR          Captures directory to test for writability. Default:
                              <state-dir>/captures.
  --json                      Emit the report as JSON on stdout instead of a table, for scripting.

Examples
  secondeye doctor
  # Check the direct-connect setup rather than a Burp chain.
  secondeye doctor --no-upstream
  secondeye doctor --json
```
<!-- END GENERATED: cli-help-doctor -->

---

## `secondeye ca export`

Writes the root CA certificate to stdout, for importing into a browser or
passing to a client as `--cacert`. The first-run note goes to stderr, so
redirecting stdout gives you clean certificate bytes.

<!-- BEGIN GENERATED: cli-help-ca-export -->
```text
usage: secondeye ca export [-h] [--format ENCODING]

Export secondeye's root CA for import into a browser/device trust store. The certificate goes to
stdout, so redirect it to a file. Generates the CA if this is the first run.

Options
  -h, --help         show this help message and exit
  --format ENCODING  Output encoding, written to stdout: der or pem. Default: pem.

Examples
  secondeye ca export > secondeye-ca.pem
  secondeye ca export --format der > secondeye-ca.der
```
<!-- END GENERATED: cli-help-ca-export -->

---

## `secondeye ca install`

Automates the NSS half of trust-store setup (Firefox, Chromium, and the shared
`~/.pki/nssdb`) via `certutil`. The system store needs `sudo` and is never
written automatically — the commands are printed for you to run.

<!-- BEGIN GENERATED: cli-help-ca-install -->
```text
usage: secondeye ca install [-h] [--remove] [--print-only] [--dry-run]

Install secondeye's CA into the local NSS trust stores (Firefox, Chromium, and the shared
~/.pki/nssdb) using certutil, then print the two commands to trust it system-wide. The system store
needs sudo and is never written automatically — you should see the command that touches your root
trust before it runs.

Options
  -h, --help    show this help message and exit
  --remove      Remove secondeye's CA from the NSS trust stores instead of adding it.
  --print-only  Change nothing: just print the manual steps, including the system-store commands.
                Useful when certutil isn't installed.
  --dry-run     List the trust stores that would be modified, without touching them.

Examples
  secondeye ca install
  # See what would change, without changing it.
  secondeye ca install --dry-run
  secondeye ca install --remove
```
<!-- END GENERATED: cli-help-ca-install -->

---

## `secondeye ca status`

<!-- BEGIN GENERATED: cli-help-ca-status -->
```text
usage: secondeye ca status [-h]

Report the persisted CA's fingerprint and validity. Read-only: unlike 'ca export' and 'proxy start',
this never generates a CA as a side effect of being run.

Options
  -h, --help  show this help message and exit

Examples
  secondeye ca status
```
<!-- END GENERATED: cli-help-ca-status -->

---

## `secondeye ca import-upstream`

<!-- BEGIN GENERATED: cli-help-ca-import-upstream -->
```text
usage: secondeye ca import-upstream [-h] --from-burp [--upstream-proxy HOST:PORT] [--output FILE]

Fetch an upstream intercepting proxy's CA certificate for use with 'proxy start --upstream-ca'.
Requires the upstream proxy to be running.

Options
  -h, --help                  show this help message and exit
  --from-burp                 Fetch the CA from Burp Suite's well-known /cert export endpoint.
                              Currently the only supported source; required.
  --upstream-proxy HOST:PORT  The upstream proxy's host:port to fetch the CA from. Default:
                              127.0.0.1:8080.
  --output FILE               Where to write the converted PEM certificate. Default: burp-ca.pem.

Examples
  secondeye ca import-upstream --from-burp
  secondeye ca import-upstream --from-burp --upstream-proxy 127.0.0.1:8081 \
      --output ~/engagements/acme/burp-ca.pem
```
<!-- END GENERATED: cli-help-ca-import-upstream -->
