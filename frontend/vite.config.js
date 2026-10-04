import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { existsSync, readFileSync } from 'node:fs';

// The app's VPN address (REMOTE_APP_ORIGIN) and the public verify address (PUBLIC_BASE_URL) in
// backend/.env (see network/vpn/README.md) reach this server through the Caddy proxies; Vite
// refuses Host names it hasn't been told about.
function remoteHosts() {
  const file = new URL('../backend/.env', import.meta.url);
  if (!existsSync(file)) return [];
  const lines = readFileSync(file, 'utf8').split(/\r?\n/);
  return ['REMOTE_APP_ORIGIN', 'PUBLIC_BASE_URL'].flatMap((key) => {
    const line = lines.find((l) => l.startsWith(`${key}=`));
    try { return line ? [new URL(line.slice(key.length + 1).trim()).hostname] : []; } catch { return []; }
  }).filter((h) => h !== 'localhost' && h !== '127.0.0.1');
}

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: '0.0.0.0',
    allowedHosts: remoteHosts(),
    // Live reload on its own port, which only this machine reaches. Through the VPN or the public
    // verify address the page never connects to it, so it can't reload the page under the user
    // (a phone drops the connection whenever the browser goes to the background, and Vite reloads
    // the page when it reconnects, which lost half-finished forms such as authenticator setup).
    hmr: { port: 24678 },
    proxy: {
      '/health': { target: 'http://127.0.0.1:8000', changeOrigin: true },
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        // Forward the browser's IP (X-Forwarded-For). The backend trusts this header
        // only from TRUSTED_PROXIES (loopback), and binds sessions to that IP.
        xfwd: true,
      },
    },
  },
  resolve: {
    alias: {
      '@': '/src',
    },
  },
});
