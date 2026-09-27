// Sign in with Google (Google Identity Services), then ask /api/profile for the VPN profile.
// The server checks the Google-signed token and the allowlist; this page only passes it on.
let lastCredential = null;
const $ = (id) => document.getElementById(id);

function showError(message) {
  $('error').textContent = message;
  $('error').hidden = !message;
}

async function download(credential) {
  showError('');
  const res = await fetch('/api/profile', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Download failed (${res.status}).`);
  }
  const url = URL.createObjectURL(await res.blob());
  const a = Object.assign(document.createElement('a'), { href: url, download: 'lexcorp2-remote.ovpn' });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

function emailOf(credential) {
  try {
    const part = credential.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(part)).email || '';
  } catch { return ''; }
}

async function onSignedIn(response) {
  lastCredential = response.credential;
  try {
    await download(lastCredential);
    $('who').textContent = emailOf(lastCredential);
    $('signin').hidden = true;
    $('download').hidden = false;
  } catch (err) {
    showError(err.message);
  }
}

async function start() {
  const status = $('signin-status');
  let clientId = null;
  try {
    clientId = (await (await fetch('/api/config')).json()).googleClientId;
  } catch { /* shown below */ }
  if (!clientId) {
    $('google-button').hidden = true;
    status.textContent = 'Sign-in is not configured on this portal yet.';
    return;
  }
  const waitForGoogle = () => new Promise((resolve, reject) => {
    const t0 = Date.now();
    (function check() {
      if (window.google?.accounts?.id) return resolve();
      if (Date.now() - t0 > 10000) return reject(new Error('Google sign-in did not load. Check your connection or ad blocker.'));
      setTimeout(check, 100);
    })();
  });
  try {
    await waitForGoogle();
  } catch (err) {
    status.textContent = err.message;
    return;
  }
  window.google.accounts.id.initialize({ client_id: clientId, callback: onSignedIn, ux_mode: 'popup' });
  window.google.accounts.id.renderButton($('google-button'), { theme: 'outline', size: 'large', text: 'signin_with', shape: 'rectangular' });
  status.textContent = 'Only approved accounts can download the profile.';
  $('again').addEventListener('click', () => {
    // Google ID tokens last about an hour; after that, sign in again.
    download(lastCredential).catch((err) => {
      showError(err.message);
      $('signin').hidden = false;
      $('download').hidden = true;
    });
  });
}

start();
