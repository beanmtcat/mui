import { defineConfig, type ProxyOptions } from "vite";

const backend: ProxyOptions = {
  target: "http://127.0.0.1:8080",
  configure(proxy) {
    proxy.on("proxyReq", (proxyReq, req) => {
      if (req.headers.host) proxyReq.setHeader("host", req.headers.host);
    });
  },
};

export default defineConfig({
  server: {
    proxy: {
      "/api/": backend,
      "/agent/": backend,
      "/download/": backend,
      "^/s/": backend,
      "/healthz": backend,
    },
  },
  build: {
    // Split the first-load bundle: framework and the QR library load as
    // separate chunks instead of one 300KB blob. Page code stays in main.tsx
    // for now (it shares ~40 pieces of state); per-tab lazy routes are the
    // follow-up once the tab components are extracted.
    rollupOptions: {
      output: {
        // Vite 8 (Rolldown) only accepts the function form of manualChunks.
        manualChunks(id: string) {
          if (/[\\/]node_modules[\\/](react|react-dom|scheduler)[\\/]/.test(id)) return "react";
          if (id.includes("qrcode-generator")) return "qrcode";
          return undefined;
        },
      },
    },
  },
});
