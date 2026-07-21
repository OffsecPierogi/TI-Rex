import { prisma } from "./db";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import bcrypt from "bcryptjs";
import { randomBytes, createHmac } from "crypto";

const SESSION_COOKIE = "ti_session";
const SESSION_MAX_AGE = 30 * 24 * 60 * 60 * 1000; // 30 days
const BCRYPT_ROUNDS = 12;

function getAuthSecret(): string {
  const secret = process.env.AUTH_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("AUTH_SECRET must be set to a random string of at least 32 characters");
  }
  return secret;
}

function signToken(token: string): string {
  const hmac = createHmac("sha256", getAuthSecret());
  hmac.update(token);
  return `${token}.${hmac.digest("hex")}`;
}

function verifySignedToken(signed: string): string | null {
  const dot = signed.lastIndexOf(".");
  if (dot === -1) return null;
  const token = signed.slice(0, dot);
  const sig = signed.slice(dot + 1);
  const hmac = createHmac("sha256", getAuthSecret());
  hmac.update(token);
  const expected = hmac.digest("hex");
  if (sig.length !== expected.length) return null;
  let match = true;
  for (let i = 0; i < sig.length; i++) {
    if (sig[i] !== expected[i]) match = false;
  }
  return match ? token : null;
}

export type Role = "READER" | "EDITOR" | "ADMIN";

export interface SessionUser {
  id: string;
  email: string;
  name: string | null;
  role: Role;
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export async function createSession(userId: string): Promise<void> {
  const token = randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + SESSION_MAX_AGE);

  await prisma.session.create({
    data: { userId, token, expiresAt },
  });

  const cookieStore = await cookies();
  cookieStore.set(SESSION_COOKIE, signToken(token), {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    expires: expiresAt,
  });
}

export async function getSession(): Promise<SessionUser | null> {
  const cookieStore = await cookies();
  const signed = cookieStore.get(SESSION_COOKIE)?.value;
  if (!signed) return null;

  const token = verifySignedToken(signed);
  if (!token) return null;

  const session = await prisma.session.findUnique({
    where: { token },
    include: { user: { select: { id: true, email: true, name: true, role: true } } },
  });

  if (!session || session.expiresAt < new Date()) {
    if (session) {
      await prisma.session.delete({ where: { id: session.id } }).catch(() => {});
    }
    return null;
  }

  return session.user as SessionUser;
}

export async function requireAuth(): Promise<SessionUser> {
  const user = await getSession();
  if (!user) redirect("/login");
  return user;
}

export async function requireRole(minRole: Role): Promise<SessionUser> {
  const user = await requireAuth();
  const hierarchy: Role[] = ["READER", "EDITOR", "ADMIN"];
  const userLevel = hierarchy.indexOf(user.role);
  const requiredLevel = hierarchy.indexOf(minRole);
  if (userLevel < requiredLevel) {
    throw new Error("Insufficient permissions");
  }
  return user;
}

export async function destroySession(): Promise<void> {
  const cookieStore = await cookies();
  const signed = cookieStore.get(SESSION_COOKIE)?.value;
  if (signed) {
    const token = verifySignedToken(signed);
    if (token) {
      await prisma.session.deleteMany({ where: { token } });
    }
  }
  cookieStore.delete(SESSION_COOKIE);
}

export async function cleanExpiredSessions(): Promise<void> {
  await prisma.session.deleteMany({
    where: { expiresAt: { lt: new Date() } },
  });
}
