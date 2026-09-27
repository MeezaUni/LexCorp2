import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { existsSync, readFileSync } from 'node:fs';

// The app's VPN address (REMOTE_APP_ORIGIN in backend/.env, see network/vpn/README.md) reaches this
// server through the Caddy proxy; Vite refuses Host names it hasn't been told about.
function remoteHosts() {
  const file = new URL('../backend/.env', import.meta.url);
  if (!existsSync(file)) return [];
  const line = readFileSync(file, 'utf8').split(/\r?\n/).find((l) => l.startsWith('REMOTE_APP_ORIGIN='));
  const origin = line ? line.slice('REMOTE_APP_ORIGIN='.length).trim() : '';
  try { return origin ? [new URL(origin).hostname] : []; } catch { return []; }
}

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: '0.0.0.0',
    allowedHosts: remoteHosts(),
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
