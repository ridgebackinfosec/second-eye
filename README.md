# second-eye

> The name borrows from marksmanship: a sniper or hunter keeps their non-dominant
> eye — the "off eye," or second eye — open alongside the aiming eye, not to aim,
> but to hold situational awareness of the wider field while the dominant eye
> stays locked on the target. `secondeye` plays that role in an engagement: it
> runs alongside your primary tooling — your browser, Burp, ZAP — quietly
> building situational awareness of the traffic your target generates, so
> nothing outside your immediate focus goes unnoticed.

A scope-gated, passive HTTP/HTTPS recording proxy for offensive security operators.

`secondeye` sits between your client (browser, curl, another tool) and either the
destination directly or an upstream intercepting proxy (Burp Suite, OWASP ZAP).
Traffic to explicitly scoped target domains is recorded to disk and rendered into
an AI-consumable analysis document; everything else passes through untouched, with
zero TLS termination or inspection.

**Core value proposition:** low-effort, structured capture of a specific target's
traffic — packaged for handoff to an AI chat (corporate-agreement AI or in-house
LLM) for flow analysis — without giving up the ability to chain through a
traditional interception proxy for manual testing.

Author context: Ridgeback InfoSec LLC — offensive security training/consulting
tooling. License: MIT. **Platform: Linux only** (v1); macOS may work incidentally
but is untested/unsupported, and there is no Windows support planned.

---

## Install

```sh
pipx install second-eye
```

`pipx` is the primary supported install path — it keeps `secondeye` and its
dependencies isolated from your system/project Python environments.

**Manual venv fallback:**

```sh
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

## One-time setup: trust secondeye's CA

`secondeye` terminates TLS for in-scope traffic using its own locally-generated
root CA (never shared, never uploaded anywhere). Your client needs to trust it
before in-scope HTTPS traffic will work.

```sh
secondeye ca export --format der > secondeye-ca.der
```

Import `secondeye-ca.der` into your browser's or device's trust store as a
trusted root certificate authority. `--format pem` is also available if your
target trust store prefers PEM.

The CA is generated once on first run and persisted to
`~/.local/state/secondeye/ca/`; every subsequent run reuses it, so you only need
to re-import it into a given trust store once.

### Chaining through Burp or ZAP

If you're chaining `secondeye` through an intercepting proxy for manual testing,
you also need `secondeye`'s connection *to that proxy* to trust its CA:

```sh
secondeye ca import-upstream --from-burp --upstream 127.0.0.1:8080 --output burp-ca.pem
```

This fetches Burp's CA from its well-known `/cert` export endpoint and converts it
to PEM. Use the resulting file with `--upstream-ca` when starting the daemon (see
below). If you'd rather export it yourself: Burp/ZAP → Proxy → Options → CA
Certificate → export DER, then `openssl x509 -inform der -in burp-ca.der -out
burp-ca.pem`.

Not chaining through anything? Use `--no-upstream` instead — see below.

---

## Basic usage

**Terminal 1 — start the daemon** (stays running in the foreground all day):

```sh
secondeye proxy start \
  --target example.com \
  --target-regex '^(dev|stg)-.*\.example\.com$' \
  --upstream-ca burp-ca.pem
```

Or, without chaining through Burp/ZAP:

```sh
secondeye proxy start --target example.com --no-upstream
```

### Multiple targets

`--target` is repeatable — pass it once per apex domain, plus a glob wildcard for
cases where the apex itself is unknown/variable:

```sh
secondeye proxy start \
  --target example.com \
  --target corp-example.net \
  --target '*.corp.internal' \
  --no-upstream
```

`--target-regex` is separately repeatable too, for patterns a glob can't express
(alternation, numeric ranges, wildcards on both sides — see `--help` for
examples). Everything you pass — every `--target` and every `--target-regex` — is
OR'd together: a domain is in scope if it matches *any* of them.

One quirk worth knowing if you mix multiple targets: only the *first* `--target`
value feeds the capture output directory's name
(`captures/<date>_<label>/<name>/`, e.g. `2026-09-15_example-com`). The other
targets/regexes are still fully enforced for scope matching and are all recorded
in `manifest.json`'s scope block and `ANALYSIS.md`'s header — they just don't
affect the directory name.

Point your client at the proxy — `127.0.0.1:8079` by default (browser proxy
settings, or `curl -x 127.0.0.1:8079 ...`). Traffic flows normally from this point
on; nothing is recorded yet.

**Terminal 2 — record a labeled window of traffic:**

```sh
secondeye capture start --name auth-flow-test
```

Interact with the target through your client — browser clicks, curl calls,
whatever tooling you're using through the proxy. In-scope traffic is recorded
incrementally; nothing else is touched.

```sh
secondeye capture stop
```

This writes `raw.har`, `manifest.json`, and `ANALYSIS.md` to
`~/.local/state/secondeye/captures/<date>_<target>/<name>/`. Repeat
`capture start`/`capture stop` as many times as you like for different test
scenarios while the daemon keeps running.

**Analyze:** open `ANALYSIS.md` and paste it into your AI chat of choice
(corporate-agreement AI or in-house LLM — this tool assumes no redaction is
necessary because output only ever goes to a trusted destination you control). It's
purpose-built, clustered, and noise-reduced for exactly this. Reach for `raw.har`
only when you need exact ground truth (precise headers, byte-for-byte payloads)
beyond what the narrative captured — each flow in `ANALYSIS.md` carries a
`har_entry_index` cross-reference to jump straight to the right entry.
`manifest.json` is the structured/machine-readable form, meant for your own future
tooling rather than routine AI handoff.

**Done for now?** `Ctrl+C` the daemon in Terminal 1 — it auto-flushes any active
capture before exiting, so you never lose a capture by forgetting to run
`capture stop` first.

---

## Other commands

```
secondeye proxy status                    # daemon running? scope? active capture?
secondeye proxy stop                      # stop a daemon from another terminal
secondeye capture list                    # captures completed so far this run
```

Run `secondeye <noun> <verb> --help` for the full flag reference on any
subcommand (`--listen`, `--capture-all`, `--cluster-window`, `--max-connections`,
`-v`/`-q`, etc.).

### A note on OAuth/OIDC and other third-party redirects

If the flow you're testing hops out to a third-party identity provider
(`accounts.google.com`, Okta, Auth0, Azure AD, ...), `--target`/`--target-regex`
were never meant to enumerate those. Use `--capture-all` to bypass scope matching
entirely for the life of the daemon — every domain gets terminated and inspected,
but (per the no-active-capture invariant below) nothing is written to disk unless
a capture is actively running.

**Caveat:** some IdP mobile SDKs or hardened consent-flow implementations pin
certificates and will hard-fail against `secondeye`'s CA regardless of trust store
installation. This is an inherent limitation of any MITM-based interception proxy,
not a `secondeye` defect.

---

## Explicit non-goals (v1)

These are deliberate exclusions, not oversights:

- **No GUI/DOM rendering capture.** This is an HTTP proxy; it sees wire bytes, not
  rendered visual state or client-side SPA state changes.
- **No WebSocket recording.** HTTP request/response only. WebSocket frames on
  in-scope domains are passed through but not recorded or analyzed.
- **No redaction.** All captured data (headers, tokens, credentials, bodies) is
  recorded in full fidelity in both `raw.har` and `ANALYSIS.md`. This is
  deliberate — output is only ever handed to an AI chat under corporate agreement
  or an in-house LLM, so exposure to third parties isn't a concern in this threat
  model.
- **No config file support.** CLI flags only.
- **No Windows or macOS support.** Linux only.
- **No multi-session/nested capture support.** One active capture at a time,
  enforced as a hard error.
- **No remote/non-loopback operation.** The proxy listener and control socket are
  loopback-only, always. No flag exists to override this.

---

## How it works, briefly

`secondeye` inspects the SNI from the TLS ClientHello *before* completing any
handshake, decides whether the domain is in scope, and only then branches:
out-of-scope traffic is blindly relayed byte-for-byte (zero cert operations, zero
inspection); in-scope traffic gets TLS-terminated with a per-SNI leaf cert signed
by `secondeye`'s own CA, parsed as HTTP/1.1, and — if a capture is currently
active — recorded. This is a deliberate contrast to blanket-MITM tools: your
client only needs to trust `secondeye`'s CA for the domains you actually scoped
in, cert-pinned out-of-scope apps aren't broken unnecessarily, and no crypto work
is spent decrypting traffic that's immediately discarded.

Recording is capture-gated, not scope-gated: in-scope traffic flows normally
whether or not a capture is active, but nothing is buffered or written to disk
until you explicitly run `capture start`. This bounds memory usage on a
long-running daemon and means captures only ever contain what you explicitly
asked for.

---

## Development

```sh
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check .
mypy --strict src/secondeye
```
