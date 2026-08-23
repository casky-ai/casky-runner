import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  // tsconfig.json sets "jsx": "preserve" for Next's own compiler — without
  // overriding the transform's jsx mode here, Vite inherits "preserve" from
  // tsconfig and leaves raw JSX untranspiled, which fails to parse as JS.
  // Vite 8's default oxc-based transform ignores `esbuild.jsx` once both
  // are set, so this must go under `oxc` instead.
  oxc: {
    jsx: "automatic",
  },
  test: {
    environment: "happy-dom",
    globals: true,
    setupFiles: ["./__tests__/setup.tsx"],
    exclude: ["**/node_modules/**", "**/vendor/**/*.test.*"],
  },
  resolve: {
    alias: {
      "@": dirname,
      "@casky/ui-kit": path.resolve(dirname, "./vendor/ui-kit/src/index.ts"),
    },
  },
});
