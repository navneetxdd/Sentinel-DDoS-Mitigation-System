import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";

// https://vitejs.dev/config/
export default defineConfig(() => ({
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: [path.resolve(__dirname, "src", "test", "setup.ts")],
    include: ["src/**/*.test.{ts,tsx}"],
  },
  server: {
    // Use localhost on a dedicated dev port to avoid IIS/HTTP.sys collisions.
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          // Recharts + D3 helpers are large; isolate them so dashboard pages
          // don't block on charting code when first loading non-chart routes.
          if (id.includes("recharts") || id.includes("d3-") || id.includes("victory-")) {
            return "charts";
          }
          // Radix UI primitives are shared across many components but change rarely.
          if (id.includes("@radix-ui")) {
            return "radix";
          }
          // React runtime — kept tiny and always cached by the browser.
          if (id.includes("node_modules/react/") || id.includes("node_modules/react-dom/")) {
            return "react";
          }
          // Everything else in node_modules lands in a single stable vendor chunk.
          if (id.includes("node_modules")) {
            return "vendor";
          }
        },
      },
    },
  },
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
}));
