import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: '0.0.0.0',
    proxy: {
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
