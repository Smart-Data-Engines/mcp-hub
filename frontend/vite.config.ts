import { defineConfig } from 'vite';
export default defineConfig({
  base: '/admin/',
  server: {
    proxy: {
      '/admin/api': 'http://127.0.0.1:8000',
      '/credentials': 'http://127.0.0.1:8000',
      '/mcp': 'http://127.0.0.1:8000',
      '/health': 'http://127.0.0.1:8000',
      '/ready': 'http://127.0.0.1:8000',
      '/oauth': 'http://127.0.0.1:8000',
      '/authorize': 'http://127.0.0.1:8000',
      '/token': 'http://127.0.0.1:8000',
    },
  },
  build: {
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          editor: [
            'codemirror',
            '@codemirror/view',
            '@codemirror/lang-python',
            '@codemirror/lang-yaml',
          ],
        },
      },
    },
  },
});
