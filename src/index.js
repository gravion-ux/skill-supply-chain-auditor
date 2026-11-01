'use strict';
// Public API surface for programmatic use of the auditor.

const { loadPackages } = require('./loader');
const { scanPackage, scanAll } = require('./scanner');
const { RULES, getRule, ruleCatalogue } = require('./rules');
const { summarize, computeScore, gradeForScore, sortFindings, createFinding } = require('./findings');
const { toJson, toMarkdown } = require('./report');
const { redact, maskValue } = require('./redact');

// Convenience wrapper: load, scan, and summarize a target directory in one call.
function createAuditor(targetPath) {
  const packages = loadPackages(targetPath);
  const findings = scanAll(packages);
  const summary = summarize(findings);
  return { packages, findings, summary };
}

module.exports = {
  loadPackages,
  scanPackage,
  scanAll,
  RULES,
  getRule,
  ruleCatalogue,
  summarize,
  computeScore,
  gradeForScore,
  sortFindings,
  createFinding,
  toJson,
  toMarkdown,
  redact,
  maskValue,
  createAuditor
};
