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
        // 127.0.0.1 (IPv4) not "localhost" — on macOS "localhost" can resolve
        // to IPv6 (::1) first, which uvicorn's default IPv4 bind won't answer,
        // causing ECONNREFUSED ::1:8001.
        target: process.env.API_TARGET || "http://127.0.0.1:8001",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
