// The Google client ID the page's sign-in button uses (a public value).
export default function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  return res.status(200).json({ googleClientId: process.env.GOOGLE_CLIENT_ID || null });
}
