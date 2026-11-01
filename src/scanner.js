'use strict';
// Applies the rule catalogue to loaded packages and produces located findings.

const { RULES } = require('./rules');
const { createFinding, sortFindings } = require('./findings');
const { redact } = require('./redact');
const { parseSkillDocument } = require('./loader');

const BODY_CATEGORIES = new Set(['shell', 'prompt-injection', 'obfuscation']);
const FRONTMATTER_CATEGORIES = new Set(['manifest', 'prompt-injection']);
const MANIFEST_CATEGORIES = new Set(['dependencies', 'secrets']);
const OTHER_CATEGORIES = new Set(['shell', 'obfuscation', 'secrets']);

function lineColumn(text, index) {
  const safeIndex = Math.max(0, Math.min(index, text.length));
  let line = 1;
  let lastNewline = -1;
  for (let i = 0; i < safeIndex; i += 1) {
    if (text.charCodeAt(i) === 10) {
      line += 1;
      lastNewline = i;
    }
  }
  return { line, column: safeIndex - lastNewline };
}

function excerptFor(text, index) {
  const { line } = lineColumn(text, index);
  const lines = text.split(/\r?\n/);
  const raw = lines[line - 1] === undefined ? '' : lines[line - 1];
  const trimmed = raw.trim();
  if (trimmed.length <= 200) return trimmed;
  return `${trimmed.slice(0, 197)}...`;
}

function rulesFor(categories) {
  return RULES.filter((rule) => categories.has(rule.category));
}

// Public locator: turns a character offset into a 1-based line/column plus the source line.
function locate(text, index) {
  const { line, column } = lineColumn(text, index);
  return { line, column, excerpt: excerptFor(text, index) };
}

// Runs one rule over one text region and returns located, redacted hits.
function applyRule(rule, text, baseLine, context, packageName, fileName) {
  if (!text) return [];
  const hits = rule.test(text, context);
  if (!hits || hits.length === 0) return [];
  const results = [];
  for (const hit of hits) {
    const index = typeof hit.index === 'number' ? hit.index : 0;
    const local = lineColumn(text, index);
    const excerpt = excerptFor(text, index);
    results.push(
      createFinding({
        ruleId: rule.id,
        category: rule.category,
        severity: rule.severity,
        packageName,
        file: fileName,
        line: baseLine + local.line - 1,
        column: local.column,
        excerpt: redact(excerpt),
        // A rule may describe the hit more precisely than its generic message.
        message: hit.message || rule.message,
        remediation: rule.remediation
      })
    );
  }
  return results;
}

function effectiveFiles(pkg) {
  if (Array.isArray(pkg.files) && pkg.files.length > 0) return pkg.files;
  const files = [];
  if (pkg.frontmatter || pkg.body) {
    const frontmatterRaw = pkg.frontmatterRaw || (pkg.frontmatter ? pkg.frontmatter.raw || '' : '');
    const bodyRaw = pkg.body ? pkg.body.raw || '' : '';
    files.push({
      path: 'SKILL.md',
      content: `${frontmatterRaw}\n---\n${bodyRaw}`,
      size: frontmatterRaw.length + bodyRaw.length
    });
  }
  if (pkg.manifest) {
    files.push({
      path: 'package.json',
      content: JSON.stringify(pkg.manifest, null, 2),
      size: 0
    });
  }
  return files;
}

// Scans one loaded package and returns its findings.
function scanPackage(pkg) {
  const packageName = pkg.name || '(unknown)';
  const findings = [];
  const seen = new Set();

  const push = (finding) => {
    const key = `${finding.ruleId}|${finding.file}|${finding.line}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(finding);
  };

  for (const file of effectiveFiles(pkg)) {
    const fileName = file.path || '(unknown)';
    const basename = fileName.split('/').pop();

    if (basename === 'SKILL.md') {
      const parsed = parseSkillDocument(file.content || '');
      const parsedFrontmatter = parsed.frontmatter;
      const frontmatter = parsedFrontmatter || pkg.frontmatter || null;
      // A package built in memory may carry a flat frontmatter object without raw text.
      const frontmatterRaw = parsedFrontmatter ? parsedFrontmatter.raw : pkg.frontmatterRaw || '';
      const frontmatterLine = parsedFrontmatter ? parsedFrontmatter.line || 1 : 1;
      const body = parsed.body || pkg.body || { raw: file.content || '', line: 1 };

      if (frontmatter) {
        const context = {
          frontmatter,
          manifest: pkg.manifest || null,
          packageName,
          file: fileName
        };
        for (const rule of rulesFor(FRONTMATTER_CATEGORIES)) {
          for (const finding of applyRule(
            rule,
            frontmatterRaw,
            frontmatterLine,
            context,
            packageName,
            fileName
          )) {
            push(finding);
          }
        }
      }

      const bodyContext = {
        frontmatter: frontmatter || null,
        manifest: pkg.manifest || null,
        packageName,
        file: fileName
      };
      for (const rule of rulesFor(BODY_CATEGORIES)) {
        for (const finding of applyRule(
          rule,
          body.raw,
          body.line || 1,
          bodyContext,
          packageName,
          fileName
        )) {
          push(finding);
        }
      }

      // Secrets are searched across the whole document so frontmatter leaks are caught too.
      const secretRules = rulesFor(new Set(['secrets']));
      for (const rule of secretRules) {
        for (const finding of applyRule(
          rule,
          file.content || '',
          1,
          bodyContext,
          packageName,
          fileName
        )) {
          push(finding);
        }
      }
      continue;
    }

    if (basename === 'package.json') {
      const context = {
        frontmatter: null,
        manifest: pkg.manifest || null,
        packageName,
        file: fileName
      };
      for (const rule of rulesFor(MANIFEST_CATEGORIES)) {
        for (const finding of applyRule(
          rule,
          file.content || '',
          1,
          context,
          packageName,
          fileName
        )) {
          push(finding);
        }
      }
      continue;
    }

    const otherContext = {
      frontmatter: null,
      manifest: pkg.manifest || null,
      packageName,
      file: fileName
    };
    for (const rule of rulesFor(OTHER_CATEGORIES)) {
      for (const finding of applyRule(
        rule,
        file.content || '',
        1,
        otherContext,
        packageName,
        fileName
      )) {
        push(finding);
      }
    }
  }

  return sortFindings(findings);
}

function scanAll(packages) {
  const all = [];
  for (const pkg of packages || []) {
    for (const finding of scanPackage(pkg)) all.push(finding);
  }
  return sortFindings(all);
}

module.exports = {
  scanPackage,
  scanAll,
  locate,
  lineColumn,
  excerptFor
};
