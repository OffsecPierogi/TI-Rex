"use server";

import { prisma } from "@/lib/db";
import {
  hashPassword,
  verifyPassword,
  createSession,
  destroySession,
  requireRole,
} from "@/lib/auth";
import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PASSWORD_MIN = 8;
const PASSWORD_MAX = 128;
const NAME_MAX = 100;

export async function register(formData: FormData): Promise<{ error?: string }> {
  const email = (formData.get("email") as string)?.trim().toLowerCase();
  const password = formData.get("password") as string;
  const name = (formData.get("name") as string)?.trim();

  if (!email || !EMAIL_RE.test(email)) {
    return { error: "Valid email address is required" };
  }
  if (!password || password.length < PASSWORD_MIN) {
    return { error: `Password must be at least ${PASSWORD_MIN} characters` };
  }
  if (password.length > PASSWORD_MAX) {
    return { error: `Password must be at most ${PASSWORD_MAX} characters` };
  }
  if (name && name.length > NAME_MAX) {
    return { error: `Name must be at most ${NAME_MAX} characters` };
  }

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    return { error: "An account with this email already exists" };
  }

  const userCount = await prisma.user.count();
  const role = userCount === 0 ? "ADMIN" : "READER";

  const hashedPassword = await hashPassword(password);
  const user = await prisma.user.create({
    data: { email, hashedPassword, name: name || null, role },
  });

  await createSession(user.id);
  redirect("/dashboard");
}

export async function login(formData: FormData): Promise<{ error?: string }> {
  const email = (formData.get("email") as string)?.trim().toLowerCase();
  const password = formData.get("password") as string;

  if (!email || !password) {
    return { error: "Email and password are required" };
  }

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    return { error: "Invalid email or password" };
  }

  const valid = await verifyPassword(password, user.hashedPassword);
  if (!valid) {
    return { error: "Invalid email or password" };
  }

  await createSession(user.id);
  redirect("/dashboard");
}

export async function logout(): Promise<void> {
  await destroySession();
  redirect("/login");
}

export async function updateUserRole(
  userId: string,
  role: "READER" | "EDITOR" | "ADMIN"
): Promise<{ error?: string }> {
  const admin = await requireRole("ADMIN");

  if (userId === admin.id) {
    return { error: "Cannot change your own role" };
  }

  const validRoles = ["READER", "EDITOR", "ADMIN"];
  if (!validRoles.includes(role)) {
    return { error: "Invalid role" };
  }

  await prisma.user.update({
    where: { id: userId },
    data: { role },
  });

  revalidatePath("/settings");
  return {};
}

export async function deleteUser(userId: string): Promise<{ error?: string }> {
  const admin = await requireRole("ADMIN");

  if (userId === admin.id) {
    return { error: "Cannot delete your own account" };
  }

  const target = await prisma.user.findUnique({ where: { id: userId } });
  if (!target) {
    return { error: "User not found" };
  }

  await prisma.session.deleteMany({ where: { userId } });
  await prisma.user.delete({ where: { id: userId } });

  revalidatePath("/settings");
  return {};
}

export async function getUsers() {
  await requireRole("ADMIN");
  return prisma.user.findMany({
    select: { id: true, email: true, name: true, role: true, createdAt: true },
    orderBy: { createdAt: "asc" },
  });
}
