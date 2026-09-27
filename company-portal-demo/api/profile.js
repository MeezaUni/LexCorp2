// POST {credential: <Google ID token>} -> the VPN profile, for approved accounts only.
import { authorize } from '../lib/authorize.js';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Use POST.' });
  }
  const result = await authorize(req.body?.credential, {
    clientId: process.env.GOOGLE_CLIENT_ID,
    allowed: process.env.ALLOWED_EMAILS,
  });
  if (!result.ok) {
    console.log(`profile refused (${result.status})`);
    return res.status(result.status).json({ error: result.error });
  }
  const profile = Buffer.from(process.env.VPN_PROFILE_B64 || '', 'base64').toString('utf8');
  if (!profile.includes('<tls-crypt-v2>')) {
    return res.status(503).json({ error: 'The VPN profile has not been added to this portal yet.' });
  }
  console.log(`profile issued to ${result.email}`);
  res.setHeader('Content-Type', 'application/x-openvpn-profile');
  res.setHeader('Content-Disposition', 'attachment; filename="lexcorp2-remote.ovpn"');
  return res.status(200).send(profile);
}
