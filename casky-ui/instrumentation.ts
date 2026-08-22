/**
 * Next.js instrumentation hook — register() runs once when the server
 * process starts (both `next dev` and `next start`), which is the only
 * reliable "on boot" hook available in the App Router without standing up
 * a custom server. Used here to bootstrap the single-admin password (see
 * lib/auth.ts's ensureAdminBootstrap doc comment for the exact rules).
 */
export async function register() {
  // instrumentation.ts also loads for the edge runtime bundle; guard so the
  // Postgres-backed bootstrap logic only ever runs in the Node.js process.
  if (process.env.NEXT_RUNTIME !== "nodejs") return;

  const { ensureAdminBootstrap } = await import("./lib/auth");
  try {
    await ensureAdminBootstrap();
  } catch (err) {
    // Don't crash the whole server on a transient DB hiccup at boot — every
    // page already fails loudly and cleanly if DATABASE_URL/the DB is
    // unreachable (see lib/db.ts), and login will simply fail until the
    // database is reachable and this can run again on the next restart.
    // eslint-disable-next-line no-console
    console.error(
      "[casky-ui] admin bootstrap failed at startup (will not block server start):",
      err instanceof Error ? err.message : err
    );
  }
}
