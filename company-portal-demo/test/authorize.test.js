import assert from 'node:assert/strict';
import { test } from 'node:test';
import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from 'jose';
import { authorize, parseAllowlist } from '../lib/authorize.js';

const CLIENT = 'portal-test.apps.googleusercontent.com';
const ALLOWED = 'Approved@Example.com, second@example.org';

async function google() {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256' };
  const sign = (claims, { aud = CLIENT, iss = 'https://accounts.google.com', key = privateKey } = {}) =>
    new SignJWT(claims).setProtectedHeader({ alg: 'RS256', kid: 'k1' }).setIssuer(iss).setAudience(aud)
      .setIssuedAt().setExpirationTime('5m').sign(key);
  return { keys: createLocalJWKSet({ keys: [jwk] }), sign };
}

test('allowlist is case-insensitive and ignores blanks', () => {
  assert.deepEqual(parseAllowlist(' A@x.com, ,b@Y.org '), ['a@x.com', 'b@y.org']);
});

test('an approved, verified Google account may download', async () => {
  const g = await google();
  const r = await authorize(await g.sign({ email: 'approved@example.com', email_verified: true }), { clientId: CLIENT, allowed: ALLOWED, keys: g.keys });
  assert.equal(r.ok, true);
  assert.equal(r.email, 'approved@example.com');
});

test('refusals', async () => {
  const g = await google();
  const other = await google();
  const opts = { clientId: CLIENT, allowed: ALLOWED, keys: g.keys };
  const cases = [
    [await g.sign({ email: 'stranger@example.com', email_verified: true }), 403],          // not on the list
    [await g.sign({ email: 'approved@example.com', email_verified: false }), 403],         // unverified email
    [await g.sign({ email: 'approved@example.com', email_verified: true }, { aud: 'other-app' }), 401],  // token for another app
    [await g.sign({ email: 'approved@example.com', email_verified: true }, { iss: 'https://evil.example' }), 401],
    [await other.sign({ email: 'approved@example.com', email_verified: true }), 401],      // not signed by Google's keys
    ['', 400],
  ];
  for (const [credential, status] of cases) {
    assert.equal((await authorize(credential, opts)).status, status);
  }
  assert.equal((await authorize('x', { clientId: CLIENT, allowed: '', keys: g.keys })).status, 503);
});
