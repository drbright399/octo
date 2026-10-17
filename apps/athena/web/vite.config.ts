import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
      "@widgets": fileURLToPath(new URL("../widgets/components", import.meta.url)),
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    // Local dev pair: forward /api/v1/* to the OCTO admin API running
    // on localhost:8001. The backend bootstrap script in
    // scripts/start-dev-backend.sh sets up that port. Vite preserves
    // cookies + the Host header so `credentials: "include"` round-trips
    // session cookies the way the live deployment does behind Cloudflare.
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8001",
        changeOrigin: false,
        secure: false,
      },
    },
  },
  build: {
    target: "es2022",
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: {
          react: ["react", "react-dom"],
        },
      },
    },
  },
});
