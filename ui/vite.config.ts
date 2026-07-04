import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Build output goes to dist/ (committed, embedded by ui/embed.go). base "./"
// keeps asset URLs relative so the SPA works regardless of mount path. The dev
// server proxies /api to the Go server so `npm run dev` mirrors production.
export default defineConfig({
  plugins: [react()],
  base: "./",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // No inline scripts in the HTML shell: keeps us compatible with the
    // strict script-src 'self' CSP the Go server sets.
    modulePreload: { polyfill: false },
  },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8080",
    },
  },
});
