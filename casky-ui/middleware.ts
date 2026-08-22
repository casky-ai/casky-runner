import { NextResponse, type NextRequest } from "next/server";
import { SESSION_COOKIE_NAME, verifySessionToken } from "./lib/auth";

// Node.js middleware runtime (stable since Next 15.2) — needed because
// verifySessionToken()/getSetting() ultimately go through `pg`, which is
// not available in the default Edge middleware runtime.
export const runtime = "nodejs";

const PUBLIC_PATHS = ["/login", "/api/health"];

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  if (PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(`${p}/`))) {
    return NextResponse.next();
  }

  const token = request.cookies.get(SESSION_COOKIE_NAME)?.value;
  const valid = token ? await verifySessionToken(token) : false;

  if (!valid) {
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("next", pathname);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    /*
     * Match every route except:
     * - _next/static, _next/image (Next internals)
     * - favicon.ico
     * /login and /api/health are matched but exempted inside the handler
     * above (rather than in this matcher) so they still pass through this
     * same middleware pipeline for consistency/logging if extended later.
     */
    "/((?!_next/static|_next/image|favicon.ico).*)",
  ],
};
