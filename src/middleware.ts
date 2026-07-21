import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

const PUBLIC_PATHS = ["/login", "/register"];

const encoder = new TextEncoder();

async function verifyHmac(signed: string): Promise<boolean> {
  const secret = process.env.AUTH_SECRET;
  if (!secret || secret.length < 32) return false;

  const dot = signed.lastIndexOf(".");
  if (dot === -1) return false;

  const token = signed.slice(0, dot);
  const providedSig = signed.slice(dot + 1);
  if (!token || !providedSig) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const sigBuf = await crypto.subtle.sign("HMAC", key, encoder.encode(token));
  const expectedSig = Array.from(new Uint8Array(sigBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  if (providedSig.length !== expectedSig.length) return false;
  let match = true;
  for (let i = 0; i < expectedSig.length; i++) {
    if (providedSig[i] !== expectedSig[i]) match = false;
  }
  return match;
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  if (
    PUBLIC_PATHS.some((p) => pathname.startsWith(p)) ||
    pathname.startsWith("/_next") ||
    pathname.startsWith("/api") ||
    pathname === "/favicon.ico" ||
    pathname === "/icon.svg"
  ) {
    return NextResponse.next();
  }

  const session = request.cookies.get("ti_session");
  if (!session?.value || !(await verifyHmac(session.value))) {
    const loginUrl = new URL("/login", request.url);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|icon.svg).*)"],
};
