import { defineConfig, type ProxyOptions } from "vite";

const statusBackend: ProxyOptions = {
  target: "http://127.0.0.1:8088",
  configure(proxy) {
    proxy.on("proxyReq", (proxyReq, req) => {
      if (req.headers.host) proxyReq.setHeader("host", req.headers.host);
    });
  },
};

export default defineConfig({
  server: {
    port: 5174,
    proxy: {
      "/api/public/": statusBackend,
      "/healthz": statusBackend,
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    rollupOptions: {
      output: {
        manualChunks(id: string) {
          if (/[\\/]node_modules[\\/](react|react-dom|scheduler)[\\/]/.test(id)) {
            return "react";
          }
          return undefined;
        },
      },
    },
  },
});
