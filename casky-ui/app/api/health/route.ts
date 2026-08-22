import { NextResponse } from "next/server";

// Intentionally does not touch the database — this is the container
// healthcheck target (see casky-ui/Dockerfile), and it should report "the
// Next.js process is alive" independent of Postgres reachability, which is
// surfaced separately on the Settings page instead.
export async function GET() {
  return NextResponse.json({ ok: true });
}
