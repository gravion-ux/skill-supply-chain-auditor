'use strict';
// Discovers skill packages on disk and loads their frontmatter, manifest, and file contents.

const fs = require('node:fs');
const path = require('node:path');

const MAX_FILE_BYTES = 512 * 1024;
const MAX_FILES_PER_PACKAGE = 500;
const MAX_TOTAL_BYTES = 10 * 1024 * 1024;
const MAX_TOTAL_FILES = 5000;
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'vendor']);

function stripBom(text) {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

function unquote(value) {
  if (value.length >= 2) {
    const first = value[0];
    const last = value[value.length - 1];
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      return value.slice(1, -1);
    }
  }
  return value;
}

// Tolerant subset parser: scalars, inline arrays, quoted strings, and one level of nesting.
function parseScalar(rawValue) {
  const value = rawValue.trim();
  if (value === '') return '';
  if (value.startsWith('[') && value.endsWith(']')) {
    const inner = value.slice(1, -1).trim();
    if (inner === '') return [];
    return splitTopLevel(inner).map((item) => unquote(item.trim()));
  }
  if (value.startsWith('"') || value.startsWith("'")) {
    return unquote(value);
  }
  const comment = value.indexOf(' #');
  const cleaned = comment === -1 ? value : value.slice(0, comment).trim();
  if (cleaned === 'true') return true;
  if (cleaned === 'false') return false;
  return cleaned;
}

function splitTopLevel(text) {
  const parts = [];
  let current = '';
  let quote = null;
  for (const char of text) {
    if (quote) {
      current += char;
      if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      current += char;
      continue;
    }
    if (char === ',') {
      parts.push(current);
      current = '';
      continue;
    }
    current += char;
  }
  if (current.trim() !== '') parts.push(current);
  return parts;
}

function parseFrontmatterText(raw) {
  const data = {};
  const lines = raw.split(/\r?\n/);
  let currentKey = null;

  for (const line of lines) {
    if (line.trim() === '' || line.trim().startsWith('#')) continue;

    const indented = /^\s+/.test(line);
    const match = line.match(/^\s*([A-Za-z0-9_.\-]+)\s*:\s*(.*)$/);
    if (!match) continue;

    const key = match[1];
    const rawValue = match[2];

    if (indented && currentKey !== null) {
      const parent = data[currentKey];
      if (parent && typeof parent === 'object' && !Array.isArray(parent)) {
        if (rawValue.trim() === '') {
          parent[key] = '';
        } else {
          parent[key] = parseScalar(rawValue);
        }
      }
      continue;
    }

    if (rawValue.trim() === '') {
      data[key] = {};
      currentKey = key;
      continue;
    }

    data[key] = parseScalar(rawValue);
    currentKey = null;
  }

  return data;
}

// Splits a SKILL.md into frontmatter and body, keeping 1-based source line offsets.
function parseSkillDocument(content) {
  const text = stripBom(content === undefined || content === null ? '' : String(content));
  const lines = text.split(/\r?\n/);

  let fenceIndex = -1;
  for (let i = 0; i < lines.length; i += 1) {
    if (lines[i].trim() === '---') {
      fenceIndex = i;
      break;
    }
  }
  if (fenceIndex === -1) {
    return { frontmatter: null, body: { raw: text, line: 1 } };
  }

  let closeIndex = -1;
  for (let i = fenceIndex + 1; i < lines.length; i += 1) {
    if (lines[i].trim() === '---' || lines[i].trim() === '...') {
      closeIndex = i;
      break;
    }
  }
  if (closeIndex === -1) {
    return { frontmatter: null, body: { raw: text, line: 1 } };
  }

  const raw = lines.slice(fenceIndex + 1, closeIndex).join('\n');
  const bodyLines = lines.slice(closeIndex + 1);
  return {
    frontmatter: {
      data: parseFrontmatterText(raw),
      raw,
      line: fenceIndex + 2
    },
    body: {
      raw: bodyLines.join('\n'),
      line: closeIndex + 2
    }
  };
}

// Public frontmatter helper: { present, data, raw, line }.
// A block that is absent or never closed is reported as absent rather than guessed.
function parseFrontmatter(text) {
  const parsed = parseSkillDocument(text);
  if (!parsed.frontmatter) {
    return { present: false, data: {}, raw: '', line: 1 };
  }
  return {
    present: true,
    data: parsed.frontmatter.data,
    raw: parsed.frontmatter.raw,
    line: parsed.frontmatter.line
  };
}

function readJsonSafe(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object') return parsed;
    return null;
  } catch {
    return null;
  }
}

function listDirs(root) {
  const dirs = [];
  const stack = [root];
  while (stack.length > 0) {
    const current = stack.pop();
    dirs.push(current);
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (SKIP_DIRS.has(entry.name)) continue;
      stack.push(path.join(current, entry.name));
    }
  }
  return dirs;
}

function isPackageDir(dir) {
  return (
    fs.existsSync(path.join(dir, 'SKILL.md')) ||
    fs.existsSync(path.join(dir, 'package.json'))
  );
}

// Reads the files of one package, honouring the per-file cap, the per-package file cap
// and the shared global budget. Oversized files are skipped rather than truncated, so a
// rule never matches against half a file.
function collectFiles(packageDir, nestedPackageDirs, limits, budget) {
  const files = [];
  const skipped = [];

  const walk = (dir) => {
    if (files.length >= limits.maxFilesPerPackage) return;
    if (budget.filesRead >= limits.maxFiles) return;
    if (nestedPackageDirs.has(dir)) return;

    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        if (nestedPackageDirs.has(full)) continue;
        walk(full);
        continue;
      }
      if (!entry.isFile()) continue;
      if (files.length >= limits.maxFilesPerPackage) return;
      if (budget.filesRead >= limits.maxFiles) return;

      let stat;
      try {
        stat = fs.statSync(full);
      } catch {
        continue;
      }

      if (stat.size > limits.maxFileSize) {
        skipped.push({ path: full, reason: 'too-large', size: stat.size });
        continue;
      }
      if (budget.bytesRead + stat.size > limits.maxTotalBytes) {
        skipped.push({ path: full, reason: 'total-bytes-exceeded', size: stat.size });
        return;
      }

      let content;
      try {
        content = fs.readFileSync(full, 'utf8');
      } catch {
        continue;
      }

      budget.filesRead += 1;
      budget.bytesRead += stat.size;
      files.push({
        path: path.relative(packageDir, full).split(path.sep).join('/'),
        absolutePath: full,
        content,
        size: stat.size
      });
    }
  };

  walk(packageDir);
  return { files, skipped };
}

function packageNameFor(packageDir, rootDir, frontmatter, manifest) {
  const relative = path.relative(rootDir, packageDir).split(path.sep).join('/');
  const fromFrontmatter = frontmatter && frontmatter.name;
  const fromManifest = manifest && manifest.name;
  if (fromFrontmatter && String(fromFrontmatter).trim()) return String(fromFrontmatter).trim();
  if (fromManifest && String(fromManifest).trim()) return String(fromManifest).trim();
  return relative === '' ? path.basename(packageDir) : relative;
}

function resolveLimits(options) {
  const maxFileSize = Number.isFinite(options.maxFileSize) ? options.maxFileSize : MAX_FILE_BYTES;
  const maxFiles = Number.isFinite(options.maxFiles) ? options.maxFiles : MAX_TOTAL_FILES;
  const maxTotalBytes = Number.isFinite(options.maxTotalBytes) ? options.maxTotalBytes : MAX_TOTAL_BYTES;
  const maxFilesPerPackage = Number.isFinite(options.maxFilesPerPackage)
    ? options.maxFilesPerPackage
    : MAX_FILES_PER_PACKAGE;
  return { maxFileSize, maxFiles, maxTotalBytes, maxFilesPerPackage };
}

// Loads every skill package found under the target directory and reports what was read.
function loadPackagesDetailed(targetPath, options = {}) {
  const root = path.resolve(targetPath);

  let stat;
  try {
    stat = fs.statSync(root);
  } catch (error) {
    const missing = new Error(`Target path does not exist: ${root}`);
    missing.code = 'TARGET_NOT_FOUND';
    missing.cause = error;
    throw missing;
  }
  if (!stat.isDirectory()) {
    const error = new Error(`Target path is not a directory: ${root}`);
    error.code = 'ENOTDIR';
    throw error;
  }

  const limits = resolveLimits(options);
  const budget = { filesRead: 0, bytesRead: 0 };

  const allDirs = listDirs(root);
  const packageDirs = allDirs.filter(isPackageDir);
  const packageDirSet = new Set(packageDirs);

  const packages = [];
  const skipped = [];

  for (const dir of packageDirs) {
    const skillPath = path.join(dir, 'SKILL.md');
    const manifestPath = path.join(dir, 'package.json');

    const nested = new Set(packageDirSet);
    nested.delete(dir);
    // Nested package directories are audited as their own packages.
    const nestedPackageDirs = new Set(
      [...nested].filter((nestedDir) => nestedDir.startsWith(dir + path.sep))
    );

    const collected = collectFiles(dir, nestedPackageDirs, limits, budget);
    for (const entry of collected.skipped) {
      skipped.push({ ...entry, package: path.relative(root, dir).split(path.sep).join('/') || '.' });
    }

    // A package whose every file was rejected cannot be audited, so it is left out
    // instead of being reported as a clean package.
    if (collected.files.length === 0) continue;

    let frontmatter = null;
    let frontmatterRaw = '';
    let body = null;
    if (fs.existsSync(skillPath)) {
      const skillContent = fs.readFileSync(skillPath, 'utf8');
      const parsed = parseSkillDocument(skillContent);
      if (parsed.frontmatter) {
        frontmatter = parsed.frontmatter.data;
        frontmatterRaw = parsed.frontmatter.raw;
      }
      body = parsed.body;
    }

    const manifest = fs.existsSync(manifestPath) ? readJsonSafe(manifestPath) : null;

    packages.push({
      name: packageNameFor(dir, root, frontmatter, manifest),
      path: dir,
      relativePath: path.relative(root, dir).split(path.sep).join('/') || '.',
      frontmatter,
      frontmatterRaw,
      body,
      manifest,
      files: collected.files
    });
  }

  if (options.sort !== false) {
    packages.sort((a, b) => a.path.localeCompare(b.path));
  }

  return {
    packages,
    stats: {
      target: root,
      packagesFound: packageDirs.length,
      packagesLoaded: packages.length,
      filesRead: budget.filesRead,
      bytesRead: budget.bytesRead,
      skippedFiles: skipped.length,
      skipped
    }
  };
}

// Convenience wrapper that only returns the package list.
function loadPackages(targetPath, options = {}) {
  return loadPackagesDetailed(targetPath, options).packages;
}

module.exports = {
  loadPackages,
  loadPackagesDetailed,
  parseSkillDocument,
  parseFrontmatter,
  parseFrontmatterText,
  parseScalar,
  collectFiles,
  MAX_FILE_BYTES,
  MAX_FILES_PER_PACKAGE,
  MAX_TOTAL_BYTES,
  MAX_TOTAL_FILES,
  SKIP_DIRS
};
