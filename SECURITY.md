# Security Policy

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue.

- Email: **priyanshukumarthakur.dev@gmail.com**
- Include the affected rule or file, the input that triggers it, and what you expected to
  happen.

You can expect an acknowledgement within a few days. Fixes for confirmed issues are released
as a new patch version, and the advisory names the reporter unless you ask otherwise.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | yes |

This project is pre-1.0. Only the latest minor release receives fixes.

## How secrets are handled in reports

The auditor's job is to point at dangerous content, and dangerous content often contains a
live credential. Two mechanisms keep that credential out of the report:

1. **Redaction before rendering.** Every excerpt passes through `redact()` before it is
   written to the JSON or Markdown report. Known token formats (AWS access key ids, GitHub
   tokens, Slack tokens, generic `sk-` keys) are replaced with a short prefix/suffix hint
   such as `AKIA…MPLE`. PEM private key blocks are replaced with a `[REDACTED PRIVATE KEY]`
   marker. `key = value` credential assignments keep the key name and mask the value.
2. **Placeholder detection.** Values that are obviously not real secrets — `your_api_key_here`,
   `xxx`, `<your-token>`, `changeme`, `example.com`, `REPLACE_ME` — are left untouched, so a
   report stays readable.

A masked value can still be **recognised** and, in rare cases, guessed from context. Treat a
report as sensitive if the package you audited contained live secrets, and rotate any
credential that the auditor flagged. Finding a secret in a skill package means that secret is
already exposed: the auditor is the point at which you learn about it, not the point at which
it leaks.

## What the auditor does and does not do

- It performs **structural checks only**. It ships no advisory database, makes no network
  calls, and sends no telemetry.
- It does **not** execute anything it reads. It parses text and matches patterns.
- It is a **review aid**, not a guarantee. A package that passes the audit can still be
  malicious in ways no pattern list covers, and a package that fails it may be harmless.
  Read the code before you run it.
- It is **not** a malware sandbox and does not claim to be one.

## Reporting scope

In scope: the auditor printing a full secret into a report, bypassing a size cap, reading
outside the target directory, or crashing on hostile input.

Out of scope: false positives in rule matching (report them, but they are correctness issues
rather than vulnerabilities), and the auditor not detecting a malicious package (it is a
pattern list, not a guarantee).
