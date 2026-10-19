import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:5000',
        changeOrigin: true,
        secure: false,
        configure: (proxy) => {
          proxy.on('error', (err, _req, res) => {
            if (res && res.writeHead && !res.headersSent) {
              res.writeHead(503, {
                'Content-Type': 'application/json',
              });
              res.end(
                JSON.stringify({
                  error:
                    'Backend API is offline at http://127.0.0.1:5000. Start the Express server using "npm run server" or "npm run dev".',
                  code: 'ECONNREFUSED',
                })
              );
            }
          });
        },
      },
    },
  },
});
