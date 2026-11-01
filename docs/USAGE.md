# Usage

## Command line

```
skill-auditor audit <path> [--json <out.json>] [--md <out.md>] [--fail-on <severity>] [--quiet]
skill-auditor rules [--json]
```

### `audit <path>`

Walks `<path>`, discovers skill packages, scans them, and writes reports.

| Option | Effect |
| --- | --- |
| `--json <file>` | write the JSON report to `<file>`. Parent directories are created. |
| `--md <file>` | write the Markdown report to `<file>`. Parent directories are created. |
| `--fail-on <severity>` | threshold for the exit code. One of `critical`, `high`, `medium`, `low`, `info`. Default `high`. |
| `--quiet` | do not print the human summary. Report files are still written. |

Without `--quiet` the CLI prints the package count, the finding count by severity, the risk
score and grade, one line per finding, and the paths of any written reports.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | no findings at or above the `--fail-on` threshold |
| `1` | at least one finding at or above the threshold |
| `2` | usage error (unknown command, missing option value, invalid severity) |
| `3` | target path does not exist, is not a directory, or could not be read |

A finding is "at or above" the threshold when its severity is more severe than or equal to
the threshold severity.

### `rules [--json]`

Prints the rule catalogue. Without `--json` each line is
`SEVERITY  ID  CATEGORY  DESCRIPTION`. With `--json` the output is a JSON array of rule
objects, suitable for piping into another tool.

## Package discovery

A directory is a skill package when it contains `SKILL.md` or `package.json`. The walk
starts at the target directory itself, so auditing a single skill folder works.

Directories named `node_modules`, `.git`, `dist`, `build` and `vendor` are never descended
into. A package nested inside another package is audited as its own package, and its files
are not counted twice in the parent.

If a package's every file is rejected by the size caps, the package is left out of the
report entirely rather than reported as clean.

## Frontmatter parsing

`SKILL.md` frontmatter is the block between the first `---` line and the next `---` or
`...` line. A block that is never closed is treated as absent.

The parser is a deliberately small YAML subset — there is no YAML dependency, and a full
YAML parser would add an attack surface to a tool whose job is reading untrusted files.

Supported:

```yaml
---
name: demo                  # scalar
version: 1.2.3              # scalar
description: "quoted value" # double quoted
summary: 'single quoted'    # single quoted
enabled: true               # boolean
allowed-tools: [Read, Grep] # inline array
metadata:                   # one level of nesting
  author: someone
  license: MIT
---
```

Not supported (and ignored, or read as a plain string):

- multi-line scalars (`|`, `>`)
- block sequences (`- item` lists)
- flow mappings (`{ key: value }`)
- anchors, aliases and tags (`&`, `*`, `!`)
- multiple documents in one file
- nesting deeper than one level
- YAML-specific types other than `true` and `false`

Keys are matched as `[A-Za-z0-9_.-]+`. A line that is blank, or that starts with `#`, is
ignored. A trailing ` # comment` is stripped from an unquoted scalar.

## Size caps

| Limit | Default | Option |
| --- | --- | --- |
| Per file | 512 KiB | `maxFileSize` |
| Per package | 500 files | `maxFilesPerPackage` |
| Total files | 5000 files | `maxFiles` |
| Total bytes | 10 MiB | `maxTotalBytes` |

An oversized file is **skipped**, never truncated: a rule must never match against half a
file, because a truncated secret is still a secret and a truncated payload is misleading.

## Library API

```js
const {
  loadPackages, loadPackagesDetailed,
  scanPackage, scanAll,
  summarize, computeScore, gradeForScore, sortFindings, createFinding,
  toJson, toMarkdown,
  redact, maskValue,
  ruleCatalogue, getRule, RULES,
  createAuditor
} = require('skill-supply-chain-auditor');
```

### `loadPackages(targetPath, options?)`

Returns an array of packages:

```js
{
  name: 'demo',            // frontmatter name, else manifest name, else the relative path
  path: '/abs/path/demo',  // absolute path of the package
  relativePath: 'demo',
  frontmatter: { name: 'demo', version: '1.0.0' }, // parsed data, or null
  frontmatterRaw: 'name: demo\nversion: 1.0.0',
  body: { raw: '...', line: 5 },
  manifest: { name: 'demo', dependencies: {} },    // parsed package.json, or null
  files: [{ path: 'SKILL.md', absolutePath: '...', content: '...', size: 42 }]
}
```

Options: `maxFileSize`, `maxFiles`, `maxTotalBytes`, `maxFilesPerPackage`, `sort`.

Throws an error with `code === 'TARGET_NOT_FOUND'` when the target does not exist, and one
with `code === 'ENOTDIR'` when it is not a directory.

### `loadPackagesDetailed(targetPath, options?)`

Returns `{ packages, stats }`, where `stats` reports `packagesFound`, `packagesLoaded`,
`filesRead`, `bytesRead`, `skippedFiles` and the list of skipped files with their reasons.

### `scanPackage(pkg)` / `scanAll(packages)`

Returns findings sorted by severity, then file, then line, then rule id. Each finding is:

```js
{
  ruleId: 'SHELL-001',
  category: 'shell',
  severity: 'critical',
  packageName: 'demo',
  file: 'SKILL.md',
  line: 8,
  column: 11,
  excerpt: 'curl https://example.com/install.sh | sh',
  message: 'Downloads and executes a remote script via a pipe-to-shell command',
  remediation: 'Download to a file, verify its checksum or signature, review it, then run it.'
}
```

Line and column are 1-based. A rule is never reported twice for the same file and line.

### `createAuditor(targetPath)`

Convenience wrapper returning `{ packages, findings, summary }`.

### `toJson(findings, summary, meta?)` / `toMarkdown(findings, summary, meta?)`

`meta` may carry `target`, `packageCount` (or `packages`), `generatedAt` and `failOn`. Both
renderers sort the findings themselves, so the output does not depend on the input order.

## CI usage

```yaml
- name: Audit skill packages
  run: node src/cli.js audit ./skills --fail-on high --json audit.json --md audit.md
```

Exit code `1` fails the job when a finding reaches the threshold.
