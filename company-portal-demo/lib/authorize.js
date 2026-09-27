// Who may download the VPN profile: a Google ID token (from "Sign in with Google" on the page)
// whose signature checks out against Google's published keys, issued for this portal's client ID,
// for a verified email on the allowlist. The same allowlist as network/vpn/.env ALLOWED_EMAILS.
import { createRemoteJWKSet, jwtVerify } from 'jose';

const GOOGLE_KEYS = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'));
const GOOGLE_ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

export function parseAllowlist(value) {
  return String(value || '').split(',').map((e) => e.trim().toLowerCase()).filter(Boolean);
}

export async function authorize(credential, { clientId, allowed, keys = GOOGLE_KEYS }) {
  const allowlist = parseAllowlist(allowed);
  if (!clientId || allowlist.length === 0) return { ok: false, status: 503, error: 'This portal is not configured yet.' };
  if (typeof credential !== 'string' || !credential || credential.length > 8192) {
    return { ok: false, status: 400, error: 'Sign in with Google first.' };
  }
  let payload;
  try {
    ({ payload } = await jwtVerify(credential, keys, { issuer: GOOGLE_ISSUERS, audience: clientId }));
  } catch {
    return { ok: false, status: 401, error: 'Your Google sign-in could not be verified. Please sign in again.' };
  }
  const email = String(payload.email || '').toLowerCase();
  if (payload.email_verified !== true || !allowlist.includes(email)) {
    return { ok: false, status: 403, error: `${email || 'This account'} is not approved for remote access.` };
  }
  return { ok: true, email, name: payload.name || email };
}
