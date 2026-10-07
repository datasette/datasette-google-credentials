import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// Unique across sibling plugins: 5182 is datasette-sidebar's HMR port and
// 5186 is datasette-otel-viewer's. Keep in sync with the Justfile.
const DEV_PORT = 5187;

export default defineConfig({
  server: {
    port: DEV_PORT,
    strictPort: true,
    cors: true,
    hmr: { host: "localhost", port: DEV_PORT, protocol: "ws" },
  },
  plugins: [svelte()],
  build: {
    manifest: "manifest.json",
    outDir: "../datasette_google_credentials",
    // outDir is the Python package itself: never wipe it.
    emptyOutDir: false,
    assetsDir: "static/gen",
    rollupOptions: {
      input: {
        index: "src/pages/index/index.ts",
        admin: "src/pages/admin/index.ts",
      },
    },
  },
});
