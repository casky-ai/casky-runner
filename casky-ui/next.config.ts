import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // @casky/ui-kit is vendored as a `file:./vendor/ui-kit` dependency (see
  // vendor/ui-kit/VENDORED.md) — its package.json exports point straight at
  // .ts/.tsx source with no prebuild step, so Next must run its own
  // transform pipeline over it just like first-party app code. Without this,
  // Next treats it as an already-compiled node_modules package and refuses
  // to process the TSX/JSX inside it.
  transpilePackages: ["@casky/ui-kit"],
  // Standalone output — a self-contained server.js + only the node_modules
  // actually traced as used, instead of the full node_modules tree. Keeps
  // the Docker runtime image small and avoids `npm install` at container
  // start (Docker/casky-ui.md's multi-stage build copies .next/standalone).
  output: "standalone",
};

export default nextConfig;
