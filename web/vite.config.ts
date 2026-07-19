import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

// Dev server proxies /api to the FastAPI backend so the frontend talks to the
// real API with no CORS setup. Prod build emits static assets that FastAPI
// serves directly (see the StaticFiles mount added in Phase 6).
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.API_TARGET || "http://localhost:8001",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
