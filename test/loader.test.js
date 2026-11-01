// Tests for package discovery and frontmatter parsing.

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { loadPackages, loadPackagesDetailed, parseFrontmatter } = require('../src/loader.js');

function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sca-loader-'));
}

function writeFile(root, relative, content) {
  const target = path.join(root, relative);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content, 'utf8');
  return target;
}

test('parses a simple frontmatter block', () => {
  const { present, data } = parseFrontmatter('---\nname: demo\nversion: 1.2.3\n---\nbody\n');
  assert.equal(present, true);
  assert.equal(data.name, 'demo');
  assert.equal(data.version, '1.2.3');
});

test('parses arrays, quoted strings and one-level nested maps', () => {
  const source = [
    '---',
    'name: "quoted-name"',
    "description: 'single quoted'",
    'allowed-tools: [Read, Grep, Bash]',
    'metadata:',
    '  author: someone',
    '  license: MIT',
    '---',
    'body',
  ].join('\n');
  const { data } = parseFrontmatter(source);
  assert.equal(data.name, 'quoted-name');
  assert.equal(data.description, 'single quoted');
  assert.deepEqual(data['allowed-tools'], ['Read', 'Grep', 'Bash']);
  assert.deepEqual(data.metadata, { author: 'someone', license: 'MIT' });
});

test('returns empty frontmatter when the block is absent or unterminated', () => {
  assert.equal(parseFrontmatter('# just markdown\n').present, false);
  assert.equal(parseFrontmatter('---\nname: demo\nbody without closing\n').present, false);
});

test('discovers directories containing SKILL.md and package.json', (t) => {
  const dir = makeTempDir();
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  writeFile(dir, 'alpha/SKILL.md', '---\nname: alpha\nversion: 1.0.0\ndescription: a\n---\nhello\n');
  writeFile(dir, 'beta/package.json', JSON.stringify({ name: 'beta', version: '2.0.0' }));

  const packages = loadPackages(dir);
  assert.equal(packages.length, 2);
  const names = packages.map((pkg) => pkg.name).sort();
  assert.deepEqual(names, ['alpha', 'beta']);
});

test('returns the documented package shape', (t) => {
  const dir = makeTempDir();
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  writeFile(dir, 'skill/SKILL.md', '---\nname: shaped\nversion: 1.0.0\ndescription: d\n---\nbody\n');
  writeFile(dir, 'skill/helper.sh', '#!/bin/sh\necho hi\n');

  const [pkg] = loadPackages(dir);
  assert.equal(pkg.name, 'shaped');
  assert.equal(typeof pkg.path, 'string');
  assert.equal(pkg.frontmatter.version, '1.0.0');
  assert.equal(pkg.manifest, null);
  assert.deepEqual(
    pkg.files.map((file) => file.path).sort(),
    ['SKILL.md', 'helper.sh']
  );
  assert.ok(pkg.files.every((file) => typeof file.size === 'number' && typeof file.content === 'string'));
});

test('reads manifest dependencies, devDependencies, scripts and bin', (t) => {
  const dir = makeTempDir();
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  writeFile(
    dir,
    'tool/package.json',
    JSON.stringify({
      name: 'tool',
      dependencies: { lodash: '4.17.21' },
      devDependencies: { tap: '18.0.0' },
      scripts: { postinstall: 'node setup.js' },
      bin: { tool: 'bin/tool.js' },
    })
  );

  const [pkg] = loadPackages(dir);
  assert.equal(pkg.manifest.name, 'tool');
  assert.equal(pkg.manifest.dependencies.lodash, '4.17.21');
  assert.equal(pkg.manifest.devDependencies.tap, '18.0.0');
  assert.equal(pkg.manifest.scripts.postinstall, 'node setup.js');
  assert.equal(pkg.manifest.bin.tool, 'bin/tool.js');
});

test('skips node_modules, .git, dist, build and vendor directories', (t) => {
  const dir = makeTempDir();
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  writeFile(dir, 'real/SKILL.md', '---\nname: real\nversion: 1.0.0\ndescription: d\n---\nbody\n');
  writeFile(dir, 'node_modules/dep/SKILL.md', '---\nname: dep\n---\nbody\n');
  writeFile(dir, 'dist/SKILL.md', '---\nname: dist\n---\nbody\n');
  writeFile(dir, 'build/SKILL.md', '---\nname: build\n---\nbody\n');
  writeFile(dir, 'vendor/SKILL.md', '---\nname: vendor\n---\nbody\n');
  writeFile(dir, '.git/SKILL.md', '---\nname: git\n---\nbody\n');

  const packages = loadPackages(dir);
  assert.equal(packages.length, 1);
  assert.equal(packages[0].name, 'real');
});

test('enforces the per-file size cap', (t) => {
  const dir = makeTempDir();
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  writeFile(dir, 'big/SKILL.md', `---\nname: big\n---\n${'x'.repeat(500)}\n`);
  writeFile(dir, 'small/package.json', JSON.stringify({ name: 'small' }));

  const packages = loadPackages(dir, { maxFileSize: 100 });
  assert.equal(packages.length, 1);
  assert.equal(packages[0].name, 'small');
});

test('enforces the total file cap', (t) => {
  const dir = makeTempDir();
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  writeFile(dir, 'skill/SKILL.md', '---\nname: capped\n---\nbody\n');
  writeFile(dir, 'skill/a.txt', 'a');
  writeFile(dir, 'skill/b.txt', 'b');
  writeFile(dir, 'skill/c.txt', 'c');

  const { stats } = loadPackagesDetailed(dir, { maxFiles: 2 });
  assert.ok(stats.filesRead <= 2, `expected at most 2 files, got ${stats.filesRead}`);
});

test('throws a typed error for a missing target', () => {
  assert.throws(
    () => loadPackages(path.join(os.tmpdir(), 'definitely-missing-sca-target')),
    (error) => error.code === 'TARGET_NOT_FOUND'
  );
});
