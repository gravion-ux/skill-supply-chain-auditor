# Skill Supply Chain Auditor

Audits AI agent **skill packages** for the risks that only matter when an agent runs someone
else's instructions and code: prompt injection, unsafe shell commands, obfuscated payloads,
embedded secrets and unpinned dependencies.

An agent skill is a folder with a `SKILL.md` and often a `package.json`. The `SKILL.md`
frontmatter declares what the agent is allowed to do, and the body is text the agent will
follow as instructions. That makes a skill package a supply chain: it ships *instructions*
that get executed with the user's privileges. A skill that says `curl ... | sh`, or that asks
the agent to upload `~/.ssh/id_rsa`, is not a normal code smell — it is an attack that ships
inside a README.

This tool reads a directory of skill packages and tells you what it finds, with the evidence
redacted so the report can be shared.

- **Zero runtime dependencies** — Node built-ins only
- **Structural checks only** — no advisory database, no network calls, no telemetry
- **Deterministic output** — same input, same report, every time
- **Secrets never reach the report in full** — evidence is masked before it is written

## Why it matters

Installing a skill package means granting an agent the right to run code that a stranger
wrote. Reviewing the diff of that package by eye does not scale: the dangerous parts are a
single line of shell, an invisible zero-width character, or a frontmatter field that quietly
grants `Bash(*)`.

The auditor turns that review into a repeatable check that can run in CI on every pull
request that touches a skill.

## Install

```bash
git clone https://github.com/gravion-ux/skill-supply-chain-auditor.git
cd skill-supply-chain-auditor
npm install          # installs nothing; there are no dependencies
```

Node 18 or newer is required.

## Usage

```bash
# audit a directory of skills
node src/cli.js audit ./skills

# write machine-readable and human-readable reports
node src/cli.js audit ./skills --json report.json --md report.md

# fail the build on anything at or above medium
node src/cli.js audit ./skills --fail-on medium

# print the rule catalogue
node src/cli.js rules
node src/cli.js rules --json
```

Installed as a package, the same commands are available as `skill-auditor`.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | no findings at or above the `--fail-on` threshold |
| `1` | findings at or above the threshold |
| `2` | usage error |
| `3` | target path is missing or is not a directory |

The default threshold is `high`. `--quiet` suppresses the human summary; the JSON and
Markdown files are still written.

## Supported skill formats

| Format | What is discovered | What is scanned |
| --- | --- | --- |
| `SKILL.md` folder | any directory containing `SKILL.md` | frontmatter (manifest + prompt-injection rules) and body (shell, prompt-injection, obfuscation rules) |
| `package.json` folder | any directory containing `package.json` | dependency and manifest rules |
| Both | same directory | both sets of rules run against the same package |

`node_modules`, `.git`, `dist`, `build` and `vendor` are skipped. See
[docs/USAGE.md](docs/USAGE.md) for the frontmatter parser limits and the size caps.

## Rule table

| ID | Category | Severity | Detection |
| --- | --- | --- | --- |
| SHELL-001 | shell | critical | Remote script piped straight into a shell (`curl ... \| sh`) |
| SHELL-002 | shell | critical | Base64-decoded payload piped into a shell |
| SHELL-003 | shell | high | `eval` of a computed value |
| SHELL-004 | shell | critical | Recursive force delete of a root or home path |
| SHELL-005 | shell | medium | World-writable permissions (`chmod 777`) |
| SHELL-006 | shell | critical | Reverse shell or FIFO command execution |
| SHELL-007 | shell | high | Shell history tampering |
| SHELL-008 | shell | medium | Privilege escalation with `sudo` |
| SHELL-009 | shell | high | Clone-and-run of an external repository |
| SHELL-010 | shell | medium | Backgrounded execution of a downloaded program |
| PI-001 | prompt-injection | critical | "ignore previous instructions" |
| PI-002 | prompt-injection | critical | "do not tell the user" / silent execution |
| PI-003 | prompt-injection | critical | Instruction to send data to an external endpoint |
| PI-004 | prompt-injection | critical | Reference to a sensitive credential path |
| PI-005 | prompt-injection | high | Attempt to extract the system prompt |
| PI-006 | prompt-injection | high | Attempt to remove confirmation or safety gates |
| PI-007 | prompt-injection | critical | "disregard the above" |
| OBF-001 | obfuscation | medium | Long base64-looking blob (>= 200 chars) |
| OBF-002 | obfuscation | medium | Long hexadecimal blob (>= 120 chars) |
| OBF-003 | obfuscation | high | Zero-width characters |
| OBF-004 | obfuscation | critical | Bidirectional control characters (Trojan Source) |
| SEC-001 | secrets | critical | Embedded PEM private key block |
| SEC-002 | secrets | critical | AWS access key id |
| SEC-003 | secrets | critical | GitHub token (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`) |
| SEC-004 | secrets | high | Credential assigned to a literal value |
| SEC-005 | secrets | critical | Slack token (`xox[baprs]-`) |
| SEC-006 | secrets | high | Generic `sk-` API key (>= 20 chars) |
| DEP-001 | dependencies | high | Dependency not pinned to an exact version |
| DEP-002 | dependencies | high | `preinstall` / `install` / `postinstall` lifecycle script |
| DEP-003 | dependencies | high | Dependency fetched from a git or http URL |
| MAN-001 | manifest | high | `allowed-tools` grants wildcard access (`Bash(*)`) |
| MAN-002 | manifest | low | Frontmatter is missing a `version` |
| MAN-003 | manifest | medium | Frontmatter is missing a `name` |
| MAN-004 | manifest | low | Frontmatter is missing a `description` |

Every rule has a positive and a negative test, so a rule that starts matching ordinary prose
is caught by the test suite rather than by a user.

## Risk scoring

Each finding contributes a fixed weight to a 0-100 score, capped at 100:

| Severity | Weight |
| --- | --- |
| critical | 20 |
| high | 10 |
| medium | 4 |
| low | 2 |
| info | 0 |

The score maps to a letter grade:

| Score | Grade |
| --- | --- |
| 0-9 | A+ |
| 10-19 | A |
| 20-34 | B |
| 35-49 | C |
| 50-69 | D |
| 70-100 | F |

The exact formula and the reasoning behind the weights are in [docs/RULES.md](docs/RULES.md).

## Library use

```js
const { createAuditor, toJson, toMarkdown } = require('skill-supply-chain-auditor');

const { packages, findings, summary } = createAuditor('./skills');
console.log(summary.grade, summary.total);

fs.writeFileSync('report.md', toMarkdown(findings, summary, { target: './skills' }));
```

`loadPackages`, `scanPackage`, `scanAll`, `summarize`, `computeScore`, `gradeForScore`,
`sortFindings`, `createFinding`, `toJson`, `toMarkdown`, `redact`, `maskValue`,
`ruleCatalogue`, `getRule` and `RULES` are also exported.

## Development

```bash
npm test      # node:test suite
npm run check # syntax check every source file
```

The test suite must be run with explicit file enumeration (`node --test test/*.test.js`);
`node --test <directory>` is not reliable for this layout.

## CI

![CI](https://github.com/gravion-ux/skill-supply-chain-auditor/actions/workflows/ci.yml/badge.svg)

The workflow runs the test suite and the syntax check on Node 18, 20 and 22.

## Security

Findings are evidence, and evidence can contain the secret you were looking for. Every
excerpt is passed through the redactor before it reaches a report: private key blocks are
replaced, known token formats are masked to a short prefix/suffix hint, and credential
assignments keep only the key name. See [SECURITY.md](SECURITY.md) for how secrets are
handled and how to report a vulnerability.

## License

MIT — see [LICENSE](LICENSE).

Copyright (c) 2026 Priyanshu Kumar Thakur.
