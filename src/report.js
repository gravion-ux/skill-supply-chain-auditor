'use strict';
// Renders findings as a stable JSON document and a human-readable Markdown report.

const { SEVERITIES, sortFindings, summarize } = require('./findings');
const { redact } = require('./redact');

const TOOL_NAME = 'skill-supply-chain-auditor';

function safeExcerpt(finding) {
  return redact(finding.excerpt || '');
}

function escapeCell(value) {
  return String(value === undefined || value === null ? '' : value)
    .replace(/\|/g, '\\|')
    .replace(/\r?\n/g, ' ');
}

// Stable, pretty-printed JSON report.
function toJson(findings, summary, meta = {}) {
  const list = findings || [];
  const sorted = sortFindings(list);
  const resolvedSummary = summary || summarize(list);
  const report = {
    tool: TOOL_NAME,
    schemaVersion: 1,
    target: meta.target || null,
    generatedAt: meta.generatedAt || null,
    summary: resolvedSummary,
    findings: sorted.map((finding) => ({
      ruleId: finding.ruleId,
      category: finding.category,
      severity: finding.severity,
      packageName: finding.packageName,
      file: finding.file,
      line: finding.line,
      column: finding.column,
      excerpt: safeExcerpt(finding),
      message: finding.message,
      remediation: finding.remediation
    }))
  };
  return `${JSON.stringify(report, null, 2)}\n`;
}

function severityTable(summary) {
  const lines = [
    '| Severity | Count |',
    '| --- | --- |'
  ];
  const bySeverity = (summary && summary.bySeverity) || {};
  for (const severity of SEVERITIES) {
    lines.push(`| ${severity} | ${bySeverity[severity] || 0} |`);
  }
  return lines.join('\n');
}

// One row per category with the severity mix, so a reviewer sees whether a category is
// mostly critical noise or mostly low-severity hygiene.
function categoryTable(findings, summary) {
  const lines = [
    `| Category | ${SEVERITIES.join(' | ')} | Count |`,
    `| --- | ${SEVERITIES.map(() => '---').join(' | ')} | --- |`
  ];

  const counts = new Map();
  for (const finding of findings) {
    if (!counts.has(finding.category)) {
      counts.set(finding.category, { total: 0, bySeverity: {} });
    }
    const row = counts.get(finding.category);
    row.total += 1;
    row.bySeverity[finding.severity] = (row.bySeverity[finding.severity] || 0) + 1;
  }

  const byCategory = (summary && summary.bySeverity) ? summary.byCategory || {} : {};
  const categories = new Set([...counts.keys(), ...Object.keys(byCategory)]);

  if (categories.size === 0) {
    lines.push(`| (none) | ${SEVERITIES.map(() => 0).join(' | ')} | 0 |`);
    return lines.join('\n');
  }

  for (const category of [...categories].sort()) {
    const row = counts.get(category) || { total: 0, bySeverity: {} };
    const severityCounts = SEVERITIES.map((severity) => row.bySeverity[severity] || 0);
    lines.push(`| ${escapeCell(category)} | ${severityCounts.join(' | ')} | ${row.total} |`);
  }
  return lines.join('\n');
}

function findingsTable(findings) {
  if (findings.length === 0) return 'No findings.';
  const lines = [
    '| Severity | Rule | Package | Location | Message |',
    '| --- | --- | --- | --- | --- |'
  ];
  for (const finding of findings) {
    lines.push(
      `| ${finding.severity} | ${escapeCell(finding.ruleId)} | ${escapeCell(
        finding.packageName
      )} | ${escapeCell(finding.file)}:${finding.line} | ${escapeCell(finding.message)} |`
    );
  }
  return lines.join('\n');
}

function evidenceSection(findings) {
  if (findings.length === 0) return '';
  const lines = ['## Evidence (redacted)', ''];
  for (const finding of findings) {
    lines.push(
      `- **${finding.severity.toUpperCase()} ${finding.ruleId}** - ${escapeCell(
        finding.packageName
      )} (${escapeCell(finding.file)}:${finding.line}:${finding.column})`
    );
    lines.push(`  > ${escapeCell(safeExcerpt(finding))}`);
  }
  lines.push('');
  return lines.join('\n');
}

// One subsection per rule so the remediation text is readable and deduplicated.
function remediationSection(findings) {
  const lines = ['## Remediation', ''];
  const seen = new Set();

  for (const finding of findings) {
    if (seen.has(finding.ruleId)) continue;
    seen.add(finding.ruleId);
    lines.push(`### ${finding.ruleId} — ${finding.severity}`);
    lines.push('');
    lines.push(finding.message);
    lines.push('');
    lines.push(finding.remediation);
    lines.push('');
  }

  if (seen.size === 0) {
    lines.push('Nothing to remediate.');
    lines.push('');
  }
  return lines.join('\n');
}

// Markdown report with summary, findings, category breakdown, and remediation.
function toMarkdown(findings, summary, meta = {}) {
  const list = findings || [];
  const sorted = sortFindings(list);
  const safeSummary = summary || summarize(list);

  const packageCount =
    meta.packageCount === undefined
      ? meta.packages === undefined
        ? safeSummary.affectedPackages || 0
        : meta.packages
      : meta.packageCount;

  const lines = [
    '# Skill Supply Chain Audit Report',
    '',
    `- Target: \`${meta.target || '(not specified)'}\``,
    `- Packages audited: ${packageCount}`,
    `- Findings: ${safeSummary.total === undefined ? sorted.length : safeSummary.total}`,
    `- Risk score: ${safeSummary.score === undefined ? 0 : safeSummary.score}/100`,
    `- Grade: ${safeSummary.grade === undefined ? 'A+' : safeSummary.grade}`
  ];

  if (meta.generatedAt) lines.push(`- Generated: ${meta.generatedAt}`);
  if (meta.failOn) lines.push(`- Fail-on threshold: ${meta.failOn}`);

  lines.push('', '## Severity summary', '', severityTable(safeSummary), '');
  lines.push('## Findings', '', findingsTable(sorted), '');
  lines.push(evidenceSection(sorted));
  lines.push('## Category breakdown', '', categoryTable(sorted, safeSummary), '');
  lines.push(remediationSection(sorted));

  return `${lines.join('\n').replace(/\n{3,}/g, '\n\n').replace(/\n+$/, '\n')}`;
}

module.exports = {
  toJson,
  toMarkdown
};
