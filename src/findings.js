'use strict';
// Finding construction, severity ordering, risk scoring and summarising.

// Severity ordering highest-risk-first.
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

// Fixed weights keep the risk score deterministic and explainable (see docs/RULES.md).
// critical=20, high=10, medium=4, low=2, info=0 gives:
//   computeScore([critical, high]) = 30
//   20 critical findings = 100 (capped)
//   critical+high+low = 32 => low=2
const SEVERITY_WEIGHTS = { critical: 20, high: 10, medium: 4, low: 2, info: 0 };

// Grade bands matching the test expectations:
// A+ = 0-9, A = 10-19, B = 20-34, C = 35-49, D = 50-69, F = 70-100
const GRADE_BANDS = [
  { max: 9, grade: 'A+', label: 'low risk' },
  { max: 19, grade: 'A', label: 'low risk' },
  { max: 34, grade: 'B', label: 'moderate risk' },
  { max: 49, grade: 'C', label: 'elevated risk' },
  { max: 69, grade: 'D', label: 'high risk' },
  { max: 100, grade: 'F', label: 'critical risk' },
];

function severityRank(severity) {
  const index = SEVERITIES.indexOf(severity);
  return index === -1 ? SEVERITIES.length : index;
}

function compareSeverity(a, b) {
  return severityRank(a) - severityRank(b);
}

function isValidSeverity(severity) {
  return SEVERITIES.includes(severity);
}

// Compute a deterministic risk score from findings, capped at 100.
function computeScore(findings) {
  let total = 0;
  for (const finding of findings) {
    total += SEVERITY_WEIGHTS[finding.severity] || 0;
  }
  return Math.min(100, total);
}

// Return a grade label given a numeric score.
function gradeForScore(score) {
  const value = Math.max(0, Math.min(100, Math.round(score)));
  for (const band of GRADE_BANDS) {
    if (value <= band.max) return band.grade;
  }
  return 'F';
}

// Return a human-readable label given a numeric score.
function gradeLabel(score) {
  const value = Math.max(0, Math.min(100, Math.round(score)));
  for (const band of GRADE_BANDS) {
    if (value <= band.max) return band.label;
  }
  return 'critical risk';
}

// Summarise findings into a structured summary object.
function summarize(findings) {
  const bySeverity = {};
  for (const severity of SEVERITIES) bySeverity[severity] = 0;
  const byCategory = {};
  const packages = new Set();

  for (const finding of findings) {
    bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;
    byCategory[finding.category] = (byCategory[finding.category] || 0) + 1;
    if (finding.packageName) packages.add(finding.packageName);
  }

  const score = computeScore(findings);
  return {
    total: findings.length,
    bySeverity,
    byCategory,
    affectedPackages: packages.size,
    score,
    grade: gradeForScore(score),
    gradeLabel: gradeLabel(score),
  };
}

// Create a finding from input, normalising line/column to 1-based numbers.
function createFinding(input) {
  return {
    ruleId: String(input.ruleId || 'UNKNOWN'),
    category: String(input.category || 'unknown'),
    severity: isValidSeverity(input.severity) ? input.severity : 'info',
    packageName: String(input.packageName || 'unknown'),
    file: String(input.file || ''),
    line: Number.isFinite(input.line) ? input.line : 1,
    column: Number.isFinite(input.column) ? input.column : 1,
    excerpt: String(input.excerpt || ''),
    message: String(input.message || ''),
    remediation: String(input.remediation || ''),
  };
}

// Deterministic ordering: severity, then file, then line, then rule id.
function compareFindings(a, b) {
  const bySeverity = compareSeverity(a.severity, b.severity);
  if (bySeverity !== 0) return bySeverity;
  if (a.file !== b.file) return a.file < b.file ? -1 : 1;
  if (a.line !== b.line) return a.line - b.line;
  if (a.ruleId !== b.ruleId) return a.ruleId < b.ruleId ? -1 : 1;
  return 0;
}

function sortFindings(findings) {
  return findings.slice().sort(compareFindings);
}

module.exports = {
  SEVERITIES,
  SEVERITY_WEIGHTS,
  GRADE_BANDS,
  severityRank,
  compareSeverity,
  isValidSeverity,
  createFinding,
  compareFindings,
  sortFindings,
  computeScore,
  gradeForScore,
  gradeLabel,
  summarize,
};
