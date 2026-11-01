# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-31

### Added

- Skill package discovery for directories containing `SKILL.md` or `package.json`, with
  `node_modules`, `.git`, `dist`, `build` and `vendor` skipped.
- A tolerant YAML-subset frontmatter parser supporting scalars, inline arrays, quoted
  strings and one level of nested maps, with no YAML dependency.
- 32 detection rules across six categories: shell, prompt-injection, obfuscation, secrets,
  dependencies and manifest. Every rule has a positive and a negative test.
- File scanning with accurate 1-based line and column positions, and de-duplication so a
  rule is never reported twice for the same file and line.
- Per-file size cap, per-package file cap and total file cap, all configurable through the
  loader options.
- Risk scoring with fixed severity weights and an A+ to F grade.
- JSON and Markdown reports, both with redacted evidence.
- A CLI with `audit` and `rules` commands, `--json`, `--md`, `--fail-on` and `--quiet`, and
  documented exit codes 0, 1, 2 and 3.
- Secret redaction for private key blocks, AWS access key ids, AWS secret access keys,
  GitHub tokens, Slack tokens, generic `sk-` keys and `key = value` credential assignments.
  Obvious placeholders are left untouched.

### Notes

- The risk score weights are `critical=20, high=10, medium=4, low=2, info=0`, capped at 100.
  Grade bands are A+ (0-9), A (10-19), B (20-34), C (35-49), D (50-69), F (70-100).
- Structural checks only: the auditor ships no advisory database and makes no network calls.

[0.1.0]: https://github.com/gravion-ux/skill-supply-chain-auditor/releases/tag/v0.1.0
