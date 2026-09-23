# Security Policy

## Reporting a Vulnerability

Please report suspected vulnerabilities using
[GitHub Security Advisories](https://github.com/ridgebackinfosec/second-eye/security/advisories/new)
rather than a public issue. This lets us assess and fix the report
privately before any details become public.

Include, if possible: the affected version, the command/flag combination
that reproduces it, and the potential impact. You should expect an initial
response within a few business days.

## Threat Model

`secondeye` is a local, loopback-only, MITM recording proxy built for
**authorized** offensive-security engagements — an operator runs it
against a target they already have permission to test, to capture and
analyze that target's own traffic. It is explicitly **not** designed to
resist a hostile *operator's own machine* (a compromised operator host is
already game over for the engagement, independent of this tool), but it
is designed to behave correctly and safely on a machine the operator
shares with other, less-trusted local users.

Two design decisions worth knowing before reading the code or reporting
against it, since both are deliberate and already known:

- **The root CA private key is stored unencrypted on disk**, protected
  only by filesystem permissions (`chmod 0600` on the key file itself,
  and the containing state directory is locked to `0700`, owner-only —
  see below). This matches standard practice for this class of tool
  (mitmproxy, Burp, and similar interception proxies all do the same) —
  passphrase-protecting it would force an interactive unlock into every
  daemon start, a workflow regression for a tool meant to be scripted
  during an engagement. If your threat model requires an encrypted CA
  key, please open a discussion rather than a vulnerability report — this
  is a known, intentional tradeoff, not an oversight.
- **Captured output is stored in full fidelity, unredacted, by design.**
  `raw.har`, `manifest.json`, `ANALYSIS.md`, and the live capture buffer
  record headers, cookies, tokens, and bodies exactly as observed — this
  is the tool's entire purpose. `secondeye`'s state directory
  (`~/.local/state/secondeye`, containing the CA, all captured output,
  and the control socket) is locked to `0700` (owner-only) on every
  daemon start, so this data is not readable by other local users on a
  shared host — but nothing redacts or encrypts the *content* itself.
  Handle exported captures (and any copy, backup, or transfer of the
  state directory) with the same care you'd give the credentials they
  contain.

## Supported Versions

Only the latest released version is supported. `secondeye` is distributed
via `pipx install git+https://github.com/ridgebackinfosec/second-eye.git`
(never published to PyPI, intentionally) — there is no LTS branch; running
the latest commit on `main` is the supported configuration.
