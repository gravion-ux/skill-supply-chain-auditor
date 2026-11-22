# Contributing to Skill Supply Chain Auditor

Thanks for helping! This tool audits AI agent **skill packages** for
the risks that only matter when an agent runs someone else's
instructions and code: prompt injection, unsafe shell commands,
obfuscated payloads, embedded secrets and unpinned dependencies. A
skill package is a supply chain — it ships *instructions* that get
executed with the user's privileges — and this auditor reads a
directory of skill packages and reports what it finds, with the
evidence.

The most valuable contributions are new detection rules and tests,
especially tests built from real malicious-skill shapes.

## Ground rules

- **Read-only by design.** The auditor inspects skill packages; it
  must never execute, install or follow instructions found inside
  one. Treat every audited package as hostile input — including in
  tests, where fixtures must be inert text, never runnable payloads.
- **Zero runtime dependencies — hard rule.** Node.js built-ins only.
- **Evidence with every finding.** Each finding quotes the exact
  content that triggered it; a rule that cannot show its evidence
  does not ship.

## Development setup

Requires Node.js 18 or newer:

```bash
git clone https://github.com/gravion-ux/skill-supply-chain-auditor.git
cd skill-supply-chain-auditor
npm install --no-audit --no-fund
npm test
```

## Running the tests

```bash
npm test        # the full suite
npm run check   # syntax-check every source file
npm run audit   # run the auditor against this repository itself
```

CI runs install, tests and checks on Node 18, 20 and 22.

## Adding a rule

Rules live in `src/rules.js` and produce findings via
`src/findings.js`. A new rule needs:

1. A stable rule id and a plain-language explanation of the attack
   it detects.
2. Tests in `test/rules.test.js` / `test/findings.test.js`: a
   package that triggers it and a benign package that must not.
   Fixtures are text only — defang anything modelled on a real
   malicious skill.
3. Conservative tuning: a false accusation against a healthy skill
   is worse than a missed edge case.

If you add a source file, add it to the `check` and `test` scripts
in `package.json` — both list files explicitly.

## Code style

- Plain Node.js, no build step; tests use the built-in `node --test`
  runner and live in `test/`.
- Comments explain *why* a pattern is treated as hostile.

## Pull request workflow

1. Fork and branch from `main`: `feat/<short-name>`,
   `fix/<short-name>`, `rule/<rule-id>`, `docs/<short-name>`.
2. Run `npm run check` and the full suite locally.
3. Open the PR against `main` with: what changed, why, how you
   tested it.
4. CI must be green. One logical change per PR.
