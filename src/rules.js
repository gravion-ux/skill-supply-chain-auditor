'use strict';
// Rule catalogue: each entry detects one supply-chain risk in skill packages.

const { isPlaceholder } = require('./redact');

// Returns one descriptor per regex hit so the scanner can locate line/column precisely.
function allMatches(text, re) {
  const out = [];
  if (!text) return out;
  const regex = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
  let match;
  while ((match = regex.exec(text)) !== null) {
    out.push({ index: match.index, length: match[0].length, value: match[0] });
    if (match[0].length === 0) regex.lastIndex += 1;
  }
  return out;
}

function textRule(spec) {
  return {
    ...spec,
    test(text) {
      return allMatches(text, spec.pattern);
    }
  };
}

// Dependency rules inspect parsed manifests rather than raw text.
function manifestRule(spec) {
  return {
    ...spec,
    pattern: null,
    test(text, context) {
      const manifest = context && context.manifest;
      if (!manifest) return [];
      const results = [];
      const sections = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
      const found = [];

      for (const section of sections) {
        const deps = manifest[section];
        if (!deps || typeof deps !== 'object') continue;
        for (const [name, value] of Object.entries(deps)) {
          if (typeof value !== 'string') continue;
          found.push({ section, name, value });
        }
      }

      for (const dep of found) {
        const hit = spec.check(dep, manifest, context);
        if (!hit) continue;
        const index = findIndexInText(text, dep.name, dep.value);
        results.push({
          index: index === -1 ? 0 : index,
          length: dep.name.length,
          value: `${dep.name}@${dep.value}`,
          message: spec.messageFor ? spec.messageFor(dep) : undefined,
          meta: dep
        });
      }

      for (const hit of spec.extraChecks ? spec.extraChecks(manifest, context) : []) {
        const index = findIndexInText(text, hit.needle || '');
        results.push({
          index: index === -1 ? 0 : index,
          length: (hit.needle || '').length,
          value: hit.needle || '',
          message: hit.message,
          meta: hit.meta || {}
        });
      }

      return results;
    }
  };
}

function findIndexInText(text, needle, value) {
  if (!text) return -1;
  if (needle) {
    const quoted = `"${needle}"`;
    const byName = text.indexOf(quoted);
    if (byName !== -1) return byName;
  }
  if (value) {
    const byValue = text.indexOf(`"${value}"`);
    if (byValue !== -1) return byValue;
  }
  return needle ? text.indexOf(needle) : -1;
}

// Frontmatter reaches rules in two shapes: the parsed document ({ data, raw, line }) and the
// flat key/value object. Both are accepted so a rule never depends on the caller's shape.
function frontmatterData(context) {
  const frontmatter = (context && context.frontmatter) || null;
  if (!frontmatter) return null;
  if (frontmatter.data && typeof frontmatter.data === 'object') return frontmatter.data;
  return frontmatter;
}

// A version is "pinned" only when it names one exact release. Ranges such as ^4.17.21 and
// wildcards such as * still float, so they count as unpinned.
const PINNED_EXACT = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
const VERSION_RANGE = /[\^~><=*]|\bx\b|\bX\b|\^\d+\.\d+\.\d+\s+-\s+\d+\.\d+\.\d+$/;

const RULES = [
  // ---------------------------------------------------------------- shell ---
  textRule({
    id: 'SHELL-001',
    category: 'shell',
    severity: 'critical',
    description: 'Remote script downloaded and piped straight into a shell',
    message: 'Downloads and executes a remote script via a pipe-to-shell command',
    remediation: 'Download to a file, verify its checksum or signature, review it, then run it.',
    pattern: /(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b/i
  }),
  textRule({
    id: 'SHELL-002',
    category: 'shell',
    severity: 'critical',
    description: 'Base64-decoded payload piped into a shell',
    message: 'Decodes a base64 payload and pipes it into a shell',
    remediation: 'Remove the encoded payload and execute only readable, reviewable commands.',
    pattern: /base64\s+(?:-d|-D|--decode)\b[^\n|]*\|\s*(?:ba)?sh\b|\|\s*base64\s+(?:-d|-D|--decode)\b[^\n|]*\|\s*(?:ba)?sh\b/i
  }),
  textRule({
    id: 'SHELL-003',
    category: 'shell',
    severity: 'high',
    description: 'eval of a computed string',
    message: 'Uses eval on a computed value, so the executed text is decided at runtime',
    remediation: 'Replace eval with an explicit call to the intended program or function.',
    pattern: /\beval\s*(?:\([^;\n]{1,200}\)|["'`][^"'`\n]{1,200}["'`]|\$\{[^}\n]{1,200}\}|\$[A-Za-z_]\w*)/i
  }),
  textRule({
    id: 'SHELL-004',
    category: 'shell',
    severity: 'critical',
    description: 'Recursive force delete of a root or home path',
    message: 'Recursively force-deletes a root or home directory',
    remediation: 'Scope destructive deletes to a dedicated temporary directory and never target / or $HOME.',
    pattern: /\brm\s+(?:-[a-zA-Z]+\s+)*-{1,2}[a-zA-Z]*(?:rf|fr)[a-zA-Z]*\s+(?:\/|~|\$HOME|\/\*)|\brm\b[^\n]*--no-preserve-root/i
  }),
  textRule({
    id: 'SHELL-005',
    category: 'shell',
    severity: 'medium',
    description: 'World-writable permissions via chmod 777',
    message: 'Grants world-writable permissions with chmod 777',
    remediation: 'Use the narrowest permissions the file needs, such as 755 or 640.',
    pattern: /\bchmod\s+(?:-[a-zA-Z]+\s+)?(?:777|a\+rwx)\b/i
  }),
  textRule({
    id: 'SHELL-006',
    category: 'shell',
    severity: 'critical',
    description: 'Reverse shell or FIFO-based command execution',
    message: 'Contains a reverse-shell or FIFO command-execution pattern',
    remediation: 'Delete the network-shell code; it exists only to hand control to a remote host.',
    pattern: /bash\s+-i\s*>&\s*\/dev\/tcp\/|\/dev\/tcp\/[A-Za-z0-9._-]+\/\d+|\bnc\b[^\n]*\s-[a-z]*e\b|\bmkfifo\b[^\n]*\|\s*(?:ba)?sh\b/i
  }),
  textRule({
    id: 'SHELL-007',
    category: 'shell',
    severity: 'high',
    description: 'Shell history tampering',
    message: 'Clears or deletes shell history to hide executed commands',
    remediation: 'Remove the history manipulation commands.',
    pattern: /\bhistory\s+-c\b|\bunset\s+HISTFILE\b|\brm\b[^\n]*\.bash_history\b/i
  }),
  textRule({
    id: 'SHELL-008',
    category: 'shell',
    severity: 'medium',
    description: 'Privilege escalation with sudo',
    message: 'Runs a privileged command with sudo',
    remediation: 'Run without root privileges or document why elevation is strictly required.',
    pattern: /\bsudo\s+(?:-[a-zA-Z]+\s+)*[a-zA-Z._/-]+/i
  }),
  textRule({
    id: 'SHELL-009',
    category: 'shell',
    severity: 'high',
    description: 'Clone-and-run of an external repository',
    message: 'Clones an external repository and immediately runs its code',
    remediation: 'Clone, inspect the code, pin a commit, and run it only after review.',
    pattern: /\bgit\s+clone\b[^\n]*&&\s*(?:cd\s+[^\n]*&&\s*)?(?:\.\/|\bbash\b[^\n]*\.sh|\bsh\b[^\n]*\.sh|\bmake\b|\bnpm\s+(?:install|run|start|ci)\b)/i
  }),
  textRule({
    id: 'SHELL-010',
    category: 'shell',
    severity: 'medium',
    description: 'Backgrounded execution of a downloaded program',
    message: 'Runs a downloaded program in the background with nohup or trailing &',
    remediation: 'Download, verify, and run foreground scripts so failures stay visible.',
    pattern: /\bnohup\b[^\n]*(?:curl|wget|\.\/|\/tmp\/)|\b(?:curl|wget)\b[^\n]*\s&\s*$/im
  }),

  // ------------------------------------------------------- prompt injection ---
  textRule({
    id: 'PI-001',
    category: 'prompt-injection',
    severity: 'critical',
    description: 'Instruction to ignore previous instructions',
    message: 'Attempts to make the agent ignore its previous instructions',
    remediation: 'Treat instructions that override prior instructions as untrusted content.',
    pattern: /ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+instructions?\b/i
  }),
  textRule({
    id: 'PI-002',
    category: 'prompt-injection',
    severity: 'critical',
    description: 'Instruction to hide activity from the user',
    message: 'Instructs the agent to act silently or conceal actions from the user',
    remediation: 'Require visible, user-confirmed actions for anything privileged.',
    pattern: /do\s+not\s+(?:tell|inform|notify|mention\s+(?:this\s+)?to)\s+the\s+user|don'?t\s+(?:tell|inform|notify)\s+the\s+user|without\s+(?:telling|informing|notifying)\s+the\s+user|\bsilently\b/i
  }),
  textRule({
    id: 'PI-003',
    category: 'prompt-injection',
    severity: 'critical',
    description: 'Instruction to exfiltrate data to an external endpoint',
    message: 'Instructs the agent to send or upload data to an external endpoint',
    remediation: 'Block outbound transfers of local data and require explicit user approval.',
    pattern: /\bsend\b[^\n]{0,80}\bto\s+https?:\/\/|\bupload\b[^\n]{0,80}\bto\b|\bpost\s+the\s+(?:contents?|files?|data|secrets?|keys?)\s+to\b|\bexfiltrat/i
  }),
  textRule({
    id: 'PI-004',
    category: 'prompt-injection',
    severity: 'critical',
    description: 'Reference to a sensitive credential path',
    message: 'References a sensitive credential or secret file path',
    remediation: 'Never read or transmit credential files; use scoped, short-lived tokens instead.',
    pattern: /~?[\/\\]\.ssh\b|\bid_rsa\b|~?[\/\\]\.aws[\/\\]credentials|\.env\b|~?[\/\\]\.npmrc|~?[\/\\]\.git-credentials/i
  }),
  textRule({
    id: 'PI-005',
    category: 'prompt-injection',
    severity: 'high',
    description: 'Attempt to extract the system prompt or hidden instructions',
    message: 'Attempts to extract the system prompt or hidden instructions',
    remediation: 'Treat any request for internal instructions as an attack, not a task.',
    pattern: /print\s+(?:your\s+)?system\s+prompt|reveal\s+(?:your\s+)?(?:instructions?|system\s+prompt|system\s+instructions)|repeat\s+the\s+words\s+above/i
  }),
  textRule({
    id: 'PI-006',
    category: 'prompt-injection',
    severity: 'high',
    description: 'Attempt to remove confirmation or safety gates',
    message: 'Attempts to bypass confirmation or safety guidelines',
    remediation: 'Keep confirmation requirements and ignore requests to waive them.',
    pattern: /you\s+are\s+now\s+in\s+developer\s+mode|ignore\s+your\s+guidelines?|without\s+asking\s+(?:for\s+)?confirmation|no\s+need\s+to\s+ask\s+(?:for\s+)?permission/i
  }),
  textRule({
    id: 'PI-007',
    category: 'prompt-injection',
    severity: 'critical',
    description: 'Instruction to disregard preceding context',
    message: 'Attempts to make the agent disregard the preceding context',
    remediation: 'Treat instructions that override prior instructions as untrusted content.',
    pattern: /disregard\s+(?:all\s+)?(?:the\s+)?(?:above|previous|prior)\b/i
  }),

  // ----------------------------------------------------------- obfuscation ---
  textRule({
    id: 'OBF-001',
    category: 'obfuscation',
    severity: 'medium',
    description: 'Long base64-looking blob',
    message: 'Contains a long base64-looking blob that can hide encoded payloads',
    remediation: 'Inline the decoded meaning as readable text, or remove the blob.',
    pattern: /[A-Za-z0-9+/]{200,}={0,2}/
  }),
  textRule({
    id: 'OBF-002',
    category: 'obfuscation',
    severity: 'medium',
    description: 'Long hexadecimal blob',
    message: 'Contains a long hex blob that can hide encoded payloads',
    remediation: 'Inline the decoded meaning as readable text, or remove the blob.',
    pattern: /[0-9a-fA-F]{120,}/
  }),
  textRule({
    id: 'OBF-003',
    category: 'obfuscation',
    severity: 'high',
    description: 'Zero-width characters',
    message: 'Contains zero-width characters that can hide instructions from reviewers',
    remediation: 'Strip zero-width characters and keep instructions visible in plain text.',
    pattern: /[\u200B-\u200D\uFEFF\u2060]/
  }),
  textRule({
    id: 'OBF-004',
    category: 'obfuscation',
    severity: 'critical',
    description: 'Bidirectional control characters (Trojan Source)',
    message: 'Contains bidirectional control characters that can visually reorder code',
    remediation: 'Remove bidirectional control characters from source and instructions.',
    pattern: /[\u202A-\u202E\u2066-\u2069]/
  }),

  // --------------------------------------------------------------- secrets ---
  textRule({
    id: 'SEC-001',
    category: 'secrets',
    severity: 'critical',
    description: 'Embedded private key block',
    message: 'Contains a PEM private key block',
    remediation: 'Revoke the key, remove it from the package, and load secrets from the environment.',
    pattern: /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/
  }),
  textRule({
    id: 'SEC-002',
    category: 'secrets',
    severity: 'critical',
    description: 'AWS access key id',
    message: 'Contains an AWS access key id',
    remediation: 'Deactivate the key in AWS and load credentials from the environment.',
    pattern: /\bAKIA[0-9A-Z]{16}\b/
  }),
  textRule({
    id: 'SEC-003',
    category: 'secrets',
    severity: 'critical',
    description: 'GitHub token',
    message: 'Contains a GitHub token',
    remediation: 'Revoke the token on GitHub and store it in a secret manager instead.',
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}/
  }),
  textRule({
    id: 'SEC-005',
    category: 'secrets',
    severity: 'critical',
    description: 'Slack token',
    message: 'Contains a Slack token',
    remediation: 'Revoke the Slack token and inject it at runtime instead.',
    // A real Slack token carries a numeric team id and a long secret; "xoxb-not-a-token" does not.
    pattern: /\bxox[baprs]-[A-Za-z0-9]{8,}-[A-Za-z0-9]{10,}\b/
  }),
  textRule({
    id: 'SEC-006',
    category: 'secrets',
    severity: 'high',
    description: 'Generic sk- prefixed API key',
    message: 'Contains a generic sk- prefixed API key',
    remediation: 'Rotate the key and inject it at runtime instead of committing it.',
    pattern: /\bsk-[A-Za-z0-9]{20,}\b/
  }),
  {
    id: 'SEC-004',
    category: 'secrets',
    severity: 'high',
    description: 'Credential assigned to a literal value',
    message: 'Assigns a credential to a literal value instead of reading it from the environment',
    remediation: 'Read the value from an environment variable or secret manager, and rotate the exposed value.',
    pattern: /\b(?:password|passwd|api[_-]?key|apikey|secret|token|access[_-]?key|client[_-]?secret)\b\s*[:=]\s*(["']?)([^\s"',;]{8,})\1/gi,
    test(text) {
      const matches = allMatches(text, this.pattern);
      return matches.filter((match) => {
        const raw = match.value;
        const separator = raw.indexOf('=') !== -1 ? raw.indexOf('=') : raw.indexOf(':');
        const valuePart = separator === -1 ? '' : raw.slice(separator + 1).trim();
        const value = valuePart.replace(/^["']|["']$/g, '');
        if (isPlaceholder(value)) return false;
        // A bare variable reference is not a literal secret.
        if (/^\$\{?[A-Za-z_]\w*\}?$/.test(value)) return false;
        return true;
      });
    }
  },

  // ---------------------------------------------------------- dependencies ---
  manifestRule({
    id: 'DEP-001',
    category: 'dependencies',
    severity: 'high',
    description: 'Dependency version is not pinned to an exact release',
    message: 'Dependency version is not reproducible (not pinned to an exact version)',
    remediation: 'Pin the dependency to an exact version so installs resolve to the same code.',
    check(dep) {
      return !PINNED_EXACT.test(dep.value.trim());
    },
    messageFor(dep) {
      const value = dep.value.trim();
      const kind = VERSION_RANGE.test(value) ? 'uses a floating range' : 'is not pinned';
      return `Dependency "${dep.name}" ${kind} (found "${value}")`;
    }
  }),
  manifestRule({
    id: 'DEP-002',
    category: 'dependencies',
    severity: 'high',
    description: 'Install lifecycle scripts run arbitrary code at install time',
    message: 'Defines an install lifecycle script that executes during npm install',
    remediation: 'Remove install lifecycle scripts, or document and pin exactly what they run.',
    check() {
      return false;
    },
    extraChecks(manifest) {
      const scripts = manifest.scripts || {};
      const hits = [];
      for (const name of ['preinstall', 'install', 'postinstall']) {
        if (typeof scripts[name] === 'string' && scripts[name].trim()) {
          hits.push({
            needle: `"${name}"`,
            message: `Install lifecycle script "${name}" runs "${scripts[name]}" during npm install`,
            meta: { script: name, command: scripts[name] }
          });
        }
      }
      return hits;
    }
  }),
  manifestRule({
    id: 'DEP-003',
    category: 'dependencies',
    severity: 'high',
    description: 'Dependency is fetched from a git or http URL',
    message: 'Dependency is resolved from a git or http URL instead of the registry',
    remediation: 'Publish the dependency to a registry and pin it to an exact version.',
    check(dep) {
      return /^(?:git\+|git:|https?:\/\/)/i.test(dep.value.trim());
    },
    messageFor(dep) {
      return `Dependency "${dep.name}" is fetched from a URL instead of the registry (found "${dep.value.trim()}")`;
    }
  }),

  // -------------------------------------------------------------- manifest ---
  {
    id: 'MAN-001',
    category: 'manifest',
    severity: 'high',
    description: 'allowed-tools grants wildcard tool access',
    message: 'allowed-tools grants wildcard access to every tool',
    remediation: 'List the specific tools the skill needs instead of a wildcard.',
    pattern: null,
    test(text, context) {
      const data = frontmatterData(context);
      if (!data) return [];
      const raw = data['allowed-tools'];
      const candidates = [];
      if (Array.isArray(raw)) candidates.push(...raw.map(String));
      else if (raw !== undefined && raw !== null) candidates.push(String(raw));

      const broad = candidates.filter((value) => value.includes('*'));
      if (broad.length === 0) return [];
      const index = findIndexInText(text, 'allowed-tools');
      return [
        {
          index: index === -1 ? 0 : index,
          length: 'allowed-tools'.length,
          value: `allowed-tools: ${broad.join(', ')}`,
          message: `allowed-tools grants wildcard access to every tool (${broad.join(', ')})`,
          meta: { value: broad.join(', ') }
        }
      ];
    }
  },
  {
    id: 'MAN-002',
    category: 'manifest',
    severity: 'low',
    description: 'Frontmatter is missing a version',
    message: 'Skill frontmatter does not declare a version',
    remediation: 'Add a `version:` field to the frontmatter so the skill can be pinned.',
    pattern: null,
    test(text, context) {
      const data = frontmatterData(context);
      if (!data) return [];
      if (data.version !== undefined && String(data.version).trim() !== '') return [];
      return [{ index: 0, length: 0, value: 'missing version' }];
    }
  },
  {
    id: 'MAN-003',
    category: 'manifest',
    severity: 'medium',
    description: 'Frontmatter is missing a name',
    message: 'Skill frontmatter does not declare a name',
    remediation: 'Add a `name:` field to the frontmatter.',
    pattern: null,
    test(text, context) {
      const data = frontmatterData(context);
      if (!data) return [];
      if (data.name !== undefined && String(data.name).trim() !== '') return [];
      return [{ index: 0, length: 0, value: 'missing name' }];
    }
  },
  {
    id: 'MAN-004',
    category: 'manifest',
    severity: 'low',
    description: 'Frontmatter is missing a description',
    message: 'Skill frontmatter does not declare a description',
    remediation: 'Add a `description:` field so reviewers can understand the skill purpose.',
    pattern: null,
    test(text, context) {
      const data = frontmatterData(context);
      if (!data) return [];
      if (data.description !== undefined && String(data.description).trim() !== '') return [];
      return [{ index: 0, length: 0, value: 'missing description' }];
    }
  }
];

function getRule(id) {
  return RULES.find((rule) => rule.id === id);
}

function ruleCatalogue() {
  return RULES.map((rule) => ({
    id: rule.id,
    category: rule.category,
    severity: rule.severity,
    description: rule.description,
    message: rule.message,
    remediation: rule.remediation
  }));
}

module.exports = {
  RULES,
  getRule,
  ruleCatalogue,
  allMatches,
  findIndexInText,
  frontmatterData
};
