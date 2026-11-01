'use strict';
// Unit tests for secret redaction.

const test = require('node:test');
const assert = require('node:assert/strict');

const { redact, maskValue, isPlaceholder } = require('../src/redact.js');

// Assembled from parts so this file never contains a contiguous Slack token: GitHub's
// push protection rejects any commit whose text matches a live credential pattern.
const SLACK_TOKEN = `xoxb-${'123456789012'}-${'abcdefghijklmnop'}`;

test('redact masks an AWS access key id but keeps a hint', () => {
  const out = redact('key AKIAIOSFODNN7EXAMPLE in file');
  assert.ok(!out.includes('AKIAIOSFODNN7EXAMPLE'));
  assert.ok(out.includes('AKIA'));
  assert.ok(out.includes('\u2026'));
});

test('redact masks a GitHub token', () => {
  const token = `ghp_${'a'.repeat(36)}`;
  const out = redact(`token=${token}`);
  assert.ok(!out.includes(token));
  assert.ok(out.includes('ghp_'));
});

test('redact masks a Slack token', () => {
  const out = redact(`x=${SLACK_TOKEN}`);
  assert.ok(!out.includes(SLACK_TOKEN));
});

test('redact masks a generic sk- API key', () => {
  const key = `sk-${'b'.repeat(25)}`;
  const out = redact(`key: ${key}`);
  assert.ok(!out.includes(key));
});

test('redact replaces a PEM private key block', () => {
  const block = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----';
  const out = redact(block);
  assert.ok(!out.includes('MIIEowIBAAKCAQEA'));
  assert.ok(out.includes('[REDACTED PRIVATE KEY]'));
});

test('redact masks an AWS secret access key assignment', () => {
  const value = 'A'.repeat(40);
  const out = redact(`aws_secret_access_key = "${value}"`);
  assert.ok(!out.includes(value));
  assert.ok(out.includes('aws_secret_access_key'));
});

test('redact masks a generic key = value secret assignment', () => {
  const out = redact('api_key: "abcd1234efgh5678"');
  assert.ok(!out.includes('abcd1234efgh5678'));
  assert.ok(out.includes('api_key'));
});

test('redact leaves obvious placeholders untouched', () => {
  const samples = [
    'api_key = "your_api_key_here"',
    'password: "xxx"',
    'token: "<your-token>"',
    'secret: "changeme"',
    'host = "example.com"',
    'key = "REPLACE_ME"'
  ];
  for (const sample of samples) {
    assert.equal(redact(sample), sample, sample);
  }
});

test('isPlaceholder recognises placeholder values', () => {
  assert.equal(isPlaceholder('your_api_key_here'), true);
  assert.equal(isPlaceholder('xxxxxx'), true);
  assert.equal(isPlaceholder('<token>'), true);
  assert.equal(isPlaceholder('changeme'), true);
  assert.equal(isPlaceholder('s3cretValue'), false);
});

test('maskValue keeps a prefix and suffix hint only', () => {
  const masked = maskValue('abcdefghijklmnop');
  assert.equal(masked, 'abcd\u2026mnop');
  assert.ok(!masked.includes('abcdefghijklmnop'));
});

test('maskValue fully masks short values', () => {
  assert.equal(maskValue('short'), '\u2026');
});

test('redact handles empty and nullish input', () => {
  assert.equal(redact(''), '');
  assert.equal(redact(null), '');
  assert.equal(redact(undefined), '');
});
