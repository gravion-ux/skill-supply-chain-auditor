// Secret redaction helpers: masks secret-looking values so audit reports never contain a full secret.

'use strict';

// Obvious placeholders must survive redaction untouched, otherwise reports become unreadable noise.
const EXACT_PLACEHOLDERS =
  /^(?:x{3,}|\*{3,}|\.{3,}|placeholder|example|sample|dummy|fake|todo|none|null|nil|undefined|redacted|changeme|change[_-]?me|secret|password|passwd|token|apikey|api[_-]?key)$/i;
const PREFIX_PLACEHOLDERS =
  /^(?:your|my|our|some|any|insert|enter|replace|change|example|sample|dummy|placeholder)[_\w.-]*$/i;

function isPlaceholder(value) {
  if (value === undefined || value === null) return true;
  const v = String(value).trim();
  if (!v) return true;
  if (/^<[^>]*>$/.test(v)) return true;
  if (/^\$\{[^}]*\}$/.test(v)) return true;
  if (/^\{\{[^}]*\}\}$/.test(v)) return true;
  if (/^\$[A-Za-z_][\w]*$/.test(v)) return true;
  if (/example\.com/i.test(v)) return true;
  if (EXACT_PLACEHOLDERS.test(v)) return true;
  if (PREFIX_PLACEHOLDERS.test(v)) return true;
  if (/_here$/i.test(v)) return true;
  return false;
}

// Keeps a short prefix/suffix hint so a reader can correlate the value without learning it.
// Values too short to split safely are masked completely.
function maskValue(value) {
  const s = String(value === undefined || value === null ? '' : value);
  if (!s.length) return s;
  if (s.length < 8) return '…';
  const keep = s.length >= 12 ? 4 : 2;
  return `${s.slice(0, keep)}…${s.slice(-keep)}`;
}

function redact(text) {
  if (text === undefined || text === null) return '';
  let out = String(text);

  // Private key blocks first: the body may itself look like another secret format.
  out = out.replace(
    /-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----[\s\S]*?-----END \1-----/g,
    (_match, kind) => `-----BEGIN ${kind}----- [REDACTED PRIVATE KEY] -----END ${kind}-----`
  );

  out = out.replace(/\bAKIA[0-9A-Z]{16}\b/g, (m) => maskValue(m));
  out = out.replace(/\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, (m) => maskValue(m));
  out = out.replace(/\bgithub_pat_[A-Za-z0-9_]{40,}\b/g, (m) => maskValue(m));
  out = out.replace(/\bxox[baprs]-[A-Za-z0-9]{8,}-[A-Za-z0-9-]{10,}\b/g, (m) => maskValue(m));
  out = out.replace(/\bsk-[A-Za-z0-9_-]{20,}\b/g, (m) => maskValue(m));

  // key = value style secrets (covers AWS secret access keys and generic credentials).
  out = out.replace(
    /\b(password|passwd|passphrase|secret|secrets|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|aws_secret_access_key|client[_-]?secret|auth[_-]?token|token)\b(\s*[:=]\s*)(["']?)([^\s"',;`]{6,})(["']?)/gi,
    (match, key, sep, q1, value, q2) =>
      // Values that were already masked (or are placeholders) are left alone.
      isPlaceholder(value) || value.includes('…') ? match : `${key}${sep}${q1}${maskValue(value)}${q2}`
  );

  return out;
}

module.exports = { redact, maskValue, isPlaceholder };
