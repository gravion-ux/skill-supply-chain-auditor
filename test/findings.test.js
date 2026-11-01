'use strict';
// Unit tests for finding construction, ordering, and risk scoring.

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  createFinding,
  sortFindings,
  computeScore,
  gradeForScore,
  summarize,
  severityRank,
  SEVERITIES
} = require('../src/findings.js');

function finding(overrides = {}) {
  return createFinding({
    ruleId: 'TEST-001',
    category: 'shell',
    severity: 'medium',
    packageName: 'pkg',
    file: 'SKILL.md',
    line: 1,
    column: 1,
    excerpt: 'excerpt',
    message: 'message',
    remediation: 'fix it',
    ...overrides
  });
}

test('severity ordering places critical before high before medium', () => {
  assert.ok(severityRank('critical') < severityRank('high'));
  assert.ok(severityRank('high') < severityRank('medium'));
  assert.ok(severityRank('medium') < severityRank('low'));
  assert.ok(severityRank('low') < severityRank('info'));
  assert.deepEqual(SEVERITIES, ['critical', 'high', 'medium', 'low', 'info']);
});

test('sortFindings sorts by severity then file then line', () => {
  const sorted = sortFindings([
    finding({ severity: 'medium', file: 'b.md', line: 2 }),
    finding({ severity: 'critical', file: 'z.md', line: 9 }),
    finding({ severity: 'critical', file: 'a.md', line: 5 }),
    finding({ severity: 'critical', file: 'a.md', line: 1 })
  ]);
  assert.deepEqual(
    sorted.map((f) => `${f.severity}:${f.file}:${f.line}`),
    ['critical:a.md:1', 'critical:a.md:5', 'critical:z.md:9', 'medium:b.md:2']
  );
});

test('computeScore is deterministic regardless of finding order', () => {
  const a = finding({ severity: 'critical' });
  const b = finding({ severity: 'high' });
  assert.equal(computeScore([a, b]), computeScore([b, a]));
  assert.equal(computeScore([a, b]), 30);
});

test('computeScore caps at 100', () => {
  const many = Array.from({ length: 20 }, () => finding({ severity: 'critical' }));
  assert.equal(computeScore(many), 100);
});

test('gradeForScore respects documented boundaries', () => {
  assert.equal(gradeForScore(0), 'A+');
  assert.equal(gradeForScore(9), 'A+');
  assert.equal(gradeForScore(10), 'A');
  assert.equal(gradeForScore(19), 'A');
  assert.equal(gradeForScore(20), 'B');
  assert.equal(gradeForScore(34), 'B');
  assert.equal(gradeForScore(35), 'C');
  assert.equal(gradeForScore(49), 'C');
  assert.equal(gradeForScore(50), 'D');
  assert.equal(gradeForScore(69), 'D');
  assert.equal(gradeForScore(70), 'F');
  assert.equal(gradeForScore(100), 'F');
});

test('summarize counts severities, categories, and affected packages', () => {
  const summary = summarize([
    finding({ severity: 'critical', category: 'shell', packageName: 'a' }),
    finding({ severity: 'low', category: 'manifest', packageName: 'a' }),
    finding({ severity: 'high', category: 'shell', packageName: 'b' })
  ]);
  assert.equal(summary.total, 3);
  assert.equal(summary.bySeverity.critical, 1);
  assert.equal(summary.bySeverity.high, 1);
  assert.equal(summary.bySeverity.low, 1);
  assert.equal(summary.bySeverity.medium, 0);
  assert.equal(summary.byCategory.shell, 2);
  assert.equal(summary.byCategory.manifest, 1);
  assert.equal(summary.affectedPackages, 2);
  assert.equal(summary.score, 32);
  assert.equal(summary.grade, 'B');
});

test('summarize handles an empty finding list', () => {
  const summary = summarize([]);
  assert.equal(summary.total, 0);
  assert.equal(summary.score, 0);
  assert.equal(summary.grade, 'A+');
  assert.equal(summary.affectedPackages, 0);
});

test('createFinding normalises line and column to 1-based numbers', () => {
  const created = finding({ line: undefined, column: undefined });
  assert.equal(created.line, 1);
  assert.equal(created.column, 1);
});
