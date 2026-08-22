import { Nav } from "@/components/nav";

// Every page under this layout queries live Postgres via lib/db.ts (see
// requireDatabaseUrl() there — there's no static/build-time-safe fallback,
// unlike harness.py's JSON-file mode). `next build` has no DATABASE_URL
// (and shouldn't be given one — it would just prerender a stale snapshot of
// whatever the build machine's DB happened to contain), so every route here
// must render per-request, never be statically generated.
export const dynamic = "force-dynamic";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex">
      <Nav />
      <main className="flex-1 min-w-0 px-8 py-8">{children}</main>
    </div>
  );
}
