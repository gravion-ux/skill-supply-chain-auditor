# Rules and scoring

## How a rule is defined

Every rule in `src/rules.js` is an object with:

```js
{
  id: 'SHELL-001',
  category: 'shell',
  severity: 'critical',
  description: 'Remote script downloaded and piped straight into a shell',
  message: 'Downloads and executes a remote script via a pipe-to-shell command',
  remediation: 'Download to a file, verify its checksum or signature, review it, then run it.',
  test(text, context) { /* returns matches, or a falsy value */ }
}
```

`test` receives the text of the region being scanned and a context object holding the
package's `frontmatter`, `manifest`, `packageName` and `file`. It returns either an array
of hits or a falsy value.

Text rules return one hit per regex match, so the scanner can report an exact line and
column for each one. A hit may carry its own `message` when the generic rule message is not
specific enough — `DEP-001` uses that to name the dependency it found.

Manifest rules inspect the parsed `package.json` rather than raw text, so a dependency
cannot be flagged by a string that merely looks like one.

## Rule catalogue

### Shell

| ID | Severity | What it matches |
| --- | --- | --- |
| SHELL-001 | critical | `curl`/`wget` piped into `sh`, `bash`, `zsh`, `ksh` or `dash` |
| SHELL-002 | critical | `base64 -d`/`--decode` piped into a shell, in either order |
| SHELL-003 | high | `eval` applied to a call, a string, or a variable |
| SHELL-004 | critical | `rm -rf /`, `rm -rf ~`, `rm -rf $HOME`, `rm -rf /*`, `--no-preserve-root` |
| SHELL-005 | medium | `chmod 777` or `chmod a+rwx` |
| SHELL-006 | critical | `/dev/tcp` reverse shells, `nc -e`, `mkfifo` piped into a shell |
| SHELL-007 | high | `history -c`, `unset HISTFILE`, deleting `.bash_history` |
| SHELL-008 | medium | `sudo <command>` |
| SHELL-009 | high | `git clone ... && cd ... && ./run.sh` (clone and immediately run) |
| SHELL-010 | medium | `nohup` or a trailing `&` applied to a downloaded program |

### Prompt injection

| ID | Severity | What it matches |
| --- | --- | --- |
| PI-001 | critical | "ignore all previous instructions" and close variants |
| PI-002 | critical | "do not tell the user", "without informing the user", "silently" |
| PI-003 | critical | "send ... to http(s)://", "upload ... to", "post the contents to", "exfiltrat*" |
| PI-004 | critical | `~/.ssh`, `.ssh/id_rsa`, `~/.aws/credentials`, `.env`, `~/.npmrc`, `~/.git-credentials` |
| PI-005 | high | "print your system prompt", "reveal your instructions", "repeat the words above" |
| PI-006 | high | "you are now in developer mode", "ignore your guidelines", "without asking for confirmation", "no need to ask permission" |
| PI-007 | critical | "disregard all the above", "disregard previous" |

### Obfuscation

| ID | Severity | What it matches |
| --- | --- | --- |
| OBF-001 | medium | 200 or more characters of the base64 alphabet |
| OBF-002 | medium | 120 or more hexadecimal characters |
| OBF-003 | high | zero-width characters (U+200B-U+200D, U+FEFF, U+2060) |
| OBF-004 | critical | bidirectional control characters (U+202A-U+202E, U+2066-U+2069) |

### Secrets

| ID | Severity | What it matches |
| --- | --- | --- |
| SEC-001 | critical | a `-----BEGIN ... PRIVATE KEY-----` block |
| SEC-002 | critical | `AKIA` followed by 16 uppercase alphanumerics |
| SEC-003 | critical | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` plus 36+ characters, and `github_pat_` |
| SEC-004 | high | a credential name assigned a literal value of 8+ characters |
| SEC-005 | critical | `xox[baprs]-` plus a numeric team id and a long secret |
| SEC-006 | high | `sk-` plus 20 or more alphanumerics |

SEC-004 and the placeholder rules below are what keep a rule catalogue from becoming a noise
generator: a documented placeholder is never a finding.

### Dependencies

| ID | Severity | What it matches |
| --- | --- | --- |
| DEP-001 | high | a dependency version that is not an exact release (`^4.17.21`, `~1.0`, `*`, `latest`) |
| DEP-002 | high | a `preinstall`, `install` or `postinstall` script |
| DEP-003 | high | a dependency given as a `git+`, `git:`, `http://` or `https://` URL |

Only `dependencies`, `devDependencies`, `optionalDependencies` and `peerDependencies` are
inspected.

A dependency is **pinned** only when it names one exact release (`4.17.21`, `1.0.0-beta.1`).
A caret or tilde range still floats — `^4.17.21` installs a different patch release over
time — so it is reported.

### Manifest

| ID | Severity | What it matches |
| --- | --- | --- |
| MAN-001 | high | an `allowed-tools` value containing `*` (`Bash(*)`) |
| MAN-002 | low | frontmatter without a `version` |
| MAN-003 | medium | frontmatter without a `name` |
| MAN-004 | low | frontmatter without a `description` |

## Where each rule runs

| Region | Categories |
| --- | --- |
| `SKILL.md` frontmatter | manifest, prompt-injection |
| `SKILL.md` body | shell, prompt-injection, obfuscation |
| `SKILL.md` whole document | secrets |
| `package.json` | dependencies, secrets |
| every other file | shell, obfuscation, secrets |

Shell rules deliberately do not run against the frontmatter. A skill may legitimately
document `curl ... | sh` in a frontmatter summary; what matters is what the body tells the
agent to run.

Secrets run against the whole `SKILL.md` because a leaked token in frontmatter is just as
leaked as one in the body.

## Scoring

Each finding contributes a fixed weight:

| Severity | Weight |
| --- | --- |
| critical | 20 |
| high | 10 |
| medium | 4 |
| low | 2 |
| info | 0 |

```
score = min(100, sum(weight(finding.severity) for finding in findings))
```

The weights are fixed rather than scaled by finding count, so one critical finding is not
washed out by twenty low ones and the score stays comparable between runs. The `low` weight
is 2 (not 1) so that a critical plus a high plus a low reaches 32, which lands inside the
`B` band rather than on its boundary.

The score maps to a grade:

| Score | Grade | Label |
| --- | --- | --- |
| 0-9 | A+ | low risk |
| 10-19 | A | low risk |
| 20-34 | B | moderate risk |
| 35-49 | C | elevated risk |
| 50-69 | D | high risk |
| 70-100 | F | critical risk |

Bands are inclusive of their upper bound. The scale is monotone: a higher score never
produces a better grade.

`computeScore` and `gradeForScore` are deterministic and order-independent — the same set of
findings always produces the same score and grade, whatever order they arrive in.

## Redaction

Every excerpt is passed through `redact()` before it reaches a report.

| Secret | Becomes |
| --- | --- |
| PEM private key block | `-----BEGIN RSA PRIVATE KEY----- [REDACTED PRIVATE KEY] -----END RSA PRIVATE KEY-----` |
| `AKIAIOSFODNN7EXAMPLE` | `AKIA…MPLE` |
| `ghp_...` (36+ chars) | `ghp_…aaaa` |
| `xoxb-...` | `xoxb…mnop` |
| `sk-...` (20+ chars) | `sk-b…bbbb` |
| `password = "hunter2hunter2"` | `password = "hunt…ter2"` |

A value shorter than 8 characters is masked completely (`…`), because splitting it would
leave most of it visible.

Values that are obviously placeholders are left untouched: `your_api_key_here`, `xxx`,
`<your-token>`, `changeme`, `example.com`, `REPLACE_ME`, `$VAR`, `${VAR}`, `{{VAR}}`.

## False positives

Every rule has one test that it fires and one that it does not. The benign samples are
deliberately close to the malicious ones — `rm -rf ./build` is not `rm -rf /`,
`chmod 755 script.sh` is not `chmod 777`, `git clone URL` is not `git clone URL && cd repo
&& ./run.sh` — because a rule that only works on an obviously malicious sample is a rule
that will fire on ordinary prose.
