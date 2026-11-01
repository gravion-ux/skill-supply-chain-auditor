'use strict';
// Command line entry point: argument parsing, report writing, and exit codes.

const fs = require('node:fs');
const path = require('node:path');
const process = require('node:process');

const { loadPackages, loadPackagesDetailed } = require('./loader');
const { scanAll } = require('./scanner');
const { summarize, severityRank, SEVERITIES } = require('./findings');
const { toJson, toMarkdown } = require('./report');
const { ruleCatalogue } = require('./rules');

const EXIT_OK = 0;
const EXIT_FINDINGS = 1;
const EXIT_USAGE = 2;
const EXIT_TARGET = 3;

const USAGE = `Usage:
  skill-auditor audit <path> [--json <out.json>] [--md <out.md>] [--fail-on <severity>] [--quiet]
  skill-auditor rules [--json]

Exit codes:
  0  no findings at or above the --fail-on threshold
  1  findings at or above the threshold
  2  usage error
  3  target path does not exist or is not a directory`;

class UsageError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UsageError';
  }
}

function parseArgs(argv) {
  const args = Array.isArray(argv) ? argv.slice() : [];
  const command = args[0];

  if (!command || command === '--help' || command === '-h' || command === 'help') {
    return { command: 'help' };
  }

  if (command === 'rules') {
    const options = { command: 'rules', jsonOnly: false };
    for (let i = 1; i < args.length; i += 1) {
      const arg = args[i];
      if (arg === '--json') options.jsonOnly = true;
      else if (arg === '--help' || arg === '-h') return { command: 'help' };
      else throw new UsageError(`Unknown option for 'rules': ${arg}`);
    }
    return options;
  }

  if (command !== 'audit') {
    throw new UsageError(`unknown command: ${command}`);
  }

  const options = {
    command: 'audit',
    target: null,
    jsonPath: null,
    mdPath: null,
    failOn: 'high',
    quiet: false
  };

  for (let i = 1; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--json') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) throw new UsageError('--json requires a value');
      options.jsonPath = value;
      i += 1;
      continue;
    }
    if (arg === '--md') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) throw new UsageError('--md requires a value');
      options.mdPath = value;
      i += 1;
      continue;
    }
    if (arg === '--fail-on') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) throw new UsageError('--fail-on requires a severity');
      if (!SEVERITIES.includes(value)) {
        throw new UsageError(`Invalid severity for --fail-on: ${value} (expected one of ${SEVERITIES.join(', ')})`);
      }
      options.failOn = value;
      i += 1;
      continue;
    }
    if (arg === '--quiet') {
      options.quiet = true;
      continue;
    }
    if (arg === '--help' || arg === '-h') {
      return { command: 'help' };
    }
    if (arg.startsWith('-')) {
      throw new UsageError(`Unknown option: ${arg}`);
    }
    if (options.target === null) {
      options.target = arg;
      continue;
    }
    throw new UsageError(`Unexpected argument: ${arg}`);
  }

  if (options.target === null) {
    throw new UsageError("The 'audit' command requires a target path");
  }

  return options;
}

function writeOutput(filePath, contents) {
  const resolved = path.resolve(filePath);
  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  fs.writeFileSync(resolved, contents, 'utf8');
  return resolved;
}

function printRules(options, out) {
  const catalogue = ruleCatalogue();
  if (options.jsonOnly) {
    out(`${JSON.stringify(catalogue, null, 2)}\n`);
    return EXIT_OK;
  }
  out(`Skill Supply Chain Auditor - ${catalogue.length}\n`);
  for (const rule of catalogue) {
    out(`${rule.severity.toUpperCase().padEnd(8)} ${rule.id.padEnd(10)} ${rule.category.padEnd(16)} ${rule.description}\n`);
  }
  return EXIT_OK;
}

// The io hook accepts a writer function (io.out / io.err) or a writable stream
// (io.stdout / io.stderr). A writer function wins, because io.stdout is also used as a
// read-back getter by test harnesses.
function resolveWriter(io, writerKey, streamKey, stream) {
  if (io && typeof io[writerKey] === 'function') return io[writerKey];
  const candidate = io ? io[streamKey] : null;
  if (candidate && typeof candidate.write === 'function') return (text) => candidate.write(text);
  if (typeof candidate === 'function' && io && io[writerKey] === undefined && streamKey === 'stdout') {
    return (text) => candidate(text);
  }
  return (text) => stream.write(text);
}

function run(argv, io = {}) {
  const out = resolveWriter(io, 'out', 'stdout', process.stdout);
  const err = resolveWriter(io, 'err', 'stderr', process.stderr);

  let options;
  try {
    options = parseArgs(argv);
  } catch (error) {
    err(`skill-auditor: error: ${error.message}\n\n${USAGE}\n`);
    return EXIT_USAGE;
  }

  if (options.command === 'help') {
    out(`${USAGE}\n`);
    return EXIT_OK;
  }

  if (options.command === 'rules') {
    return printRules(options, out);
  }

  const target = path.resolve(options.target);
  let stat;
  try {
    stat = fs.statSync(target);
  } catch {
    err(`skill-auditor: error: target path does not exist: ${target}\n`);
    return EXIT_TARGET;
  }
  if (!stat.isDirectory()) {
    err(`skill-auditor: error: target path is not a directory: ${target}\n`);
    return EXIT_TARGET;
  }

  let loaded;
  try {
    loaded = loadPackagesDetailed(target);
  } catch (error) {
    err(`skill-auditor: error: could not load packages from ${target}: ${error.message}\n`);
    return EXIT_TARGET;
  }

  const packages = loaded.packages;
  const findings = scanAll(packages);
  const summary = summarize(findings);

  const meta = {
    target,
    packageCount: packages.length,
    failOn: options.failOn
  };

  if (options.jsonPath) {
    writeOutput(options.jsonPath, toJson(findings, summary, meta));
  }
  if (options.mdPath) {
    writeOutput(options.mdPath, toMarkdown(findings, summary, meta));
  }

  if (!options.quiet) {
    out(`Audited ${packages.length} package(s) in ${target}\n`);
    out(
      `Findings: ${summary.total} finding(s) (critical ${summary.bySeverity.critical}, high ${summary.bySeverity.high}, medium ${summary.bySeverity.medium}, low ${summary.bySeverity.low}, info ${summary.bySeverity.info})\n`
    );
    out(`Risk score: ${summary.score}/100 (grade ${summary.grade})\n`);
    for (const finding of findings) {
      out(
        `  - ${finding.ruleId} ${finding.severity} ${finding.file}:${finding.line} ${finding.message}\n`
      );
    }
    if (loaded.stats.skippedFiles > 0) {
      out(`Skipped ${loaded.stats.skippedFiles} file(s) that exceeded the size limits\n`);
    }
    if (options.jsonPath) out(`JSON report: ${path.resolve(options.jsonPath)}\n`);
    if (options.mdPath) out(`Markdown report: ${path.resolve(options.mdPath)}\n`);
  }

  const threshold = severityRank(options.failOn);
  const tripped = findings.some((finding) => severityRank(finding.severity) <= threshold);
  return tripped ? EXIT_FINDINGS : EXIT_OK;
}

if (require.main === module) {
  process.exitCode = run(process.argv.slice(2));
}

const runCli = run;

module.exports = {
  run,
  runCli,
  parseArgs,
  UsageError,
  USAGE,
  EXIT_OK,
  EXIT_FINDINGS,
  EXIT_USAGE,
  EXIT_TARGET
};
