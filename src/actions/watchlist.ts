"use server";

import { prisma } from "@/lib/db";
import { requireAuth, requireRole } from "@/lib/auth";
import { validateIOC, IOC_TYPES } from "@/lib/ioc-validation";
import { revalidatePath } from "next/cache";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function verifyOwnership(watchlistId: string, userId: string) {
  const wl = await prisma.watchlist.findUnique({
    where: { id: watchlistId },
    select: { userId: true },
  });
  if (!wl || wl.userId !== userId) {
    throw new Error("Watchlist not found or access denied");
  }
  return wl;
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

/** Get all watchlists for the current user (with item count + unread alerts). */
export async function getWatchlists() {
  const user = await requireAuth();

  const watchlists = await prisma.watchlist.findMany({
    where: { userId: user.id },
    include: {
      _count: {
        select: {
          items: true,
          alerts: true,
        },
      },
    },
    orderBy: { createdAt: "desc" },
  });

  // Get unread counts separately for accuracy
  const unreadCounts = await prisma.watchlistAlert.groupBy({
    by: ["watchlistId"],
    where: {
      watchlist: { userId: user.id },
      read: false,
    },
    _count: true,
  });

  const unreadMap = new Map(unreadCounts.map((u) => [u.watchlistId, u._count]));

  return watchlists.map((wl) => ({
    id: wl.id,
    name: wl.name,
    description: wl.description,
    enabled: wl.enabled,
    createdAt: wl.createdAt,
    itemCount: wl._count.items,
    alertCount: wl._count.alerts,
    unreadAlertCount: unreadMap.get(wl.id) ?? 0,
  }));
}

/** Get single watchlist with all items and recent alerts. Verify ownership. */
export async function getWatchlist(id: string) {
  const user = await requireAuth();

  const wl = await prisma.watchlist.findUnique({
    where: { id },
    include: {
      items: {
        orderBy: { createdAt: "desc" },
      },
      alerts: {
        orderBy: { createdAt: "desc" },
        take: 50,
        include: {
          item: { select: { type: true, value: true } },
        },
      },
    },
  });

  if (!wl || wl.userId !== user.id) {
    throw new Error("Watchlist not found or access denied");
  }

  return wl;
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

/** Create a new watchlist. Requires at least READER role. */
export async function createWatchlist(data: {
  name: string;
  description?: string;
  webhookUrl?: string;
}): Promise<{ id: string }> {
  const user = await requireRole("READER");

  if (!data.name || !data.name.trim()) {
    throw new Error("Watchlist name is required");
  }

  const wl = await prisma.watchlist.create({
    data: {
      name: data.name.trim(),
      description: data.description?.trim() || null,
      webhookUrl: data.webhookUrl?.trim() || null,
      userId: user.id,
    },
  });

  revalidatePath("/watchlist");
  return { id: wl.id };
}

/** Update a watchlist. Verify ownership. */
export async function updateWatchlist(
  id: string,
  data: {
    name?: string;
    description?: string;
    webhookUrl?: string;
    enabled?: boolean;
  }
): Promise<{ success: boolean }> {
  const user = await requireAuth();
  await verifyOwnership(id, user.id);

  const updateData: Record<string, unknown> = {};
  if (data.name !== undefined) {
    if (!data.name.trim()) throw new Error("Name cannot be empty");
    updateData.name = data.name.trim();
  }
  if (data.description !== undefined) updateData.description = data.description.trim() || null;
  if (data.webhookUrl !== undefined) updateData.webhookUrl = data.webhookUrl.trim() || null;
  if (data.enabled !== undefined) updateData.enabled = data.enabled;

  await prisma.watchlist.update({
    where: { id },
    data: updateData,
  });

  revalidatePath(`/watchlist/${id}`);
  revalidatePath("/watchlist");
  return { success: true };
}

/** Delete a watchlist. Verify ownership. */
export async function deleteWatchlist(id: string): Promise<{ success: boolean }> {
  const user = await requireAuth();
  await verifyOwnership(id, user.id);

  await prisma.watchlist.delete({ where: { id } });

  revalidatePath("/watchlist");
  return { success: true };
}

/** Add an IOC item to a watchlist. Validates type and format. */
export async function addWatchlistItem(
  watchlistId: string,
  data: { type: string; value: string; description?: string }
): Promise<{ success: boolean; error?: string }> {
  const user = await requireAuth();
  await verifyOwnership(watchlistId, user.id);

  // Validate type
  if (!IOC_TYPES.includes(data.type as typeof IOC_TYPES[number])) {
    return { success: false, error: `Invalid IOC type: ${data.type}` };
  }

  // Validate and normalize value
  const validation = validateIOC(data.type, data.value);
  if (!validation.valid) {
    return { success: false, error: validation.error };
  }

  try {
    await prisma.watchlistItem.create({
      data: {
        watchlistId,
        type: data.type,
        value: validation.normalized,
        description: data.description?.trim() || null,
      },
    });
  } catch (err: unknown) {
    // Handle unique constraint violation
    if (
      err instanceof Error &&
      err.message.includes("Unique constraint")
    ) {
      return { success: false, error: "This indicator is already in the watchlist" };
    }
    throw err;
  }

  revalidatePath(`/watchlist/${watchlistId}`);
  revalidatePath("/watchlist");
  return { success: true };
}

/** Remove an item from a watchlist. Verify ownership through the watchlist. */
export async function removeWatchlistItem(itemId: string): Promise<{ success: boolean }> {
  const user = await requireAuth();

  const item = await prisma.watchlistItem.findUnique({
    where: { id: itemId },
    include: { watchlist: { select: { userId: true, id: true } } },
  });

  if (!item || item.watchlist.userId !== user.id) {
    throw new Error("Item not found or access denied");
  }

  await prisma.watchlistItem.delete({ where: { id: itemId } });

  revalidatePath(`/watchlist/${item.watchlistId}`);
  revalidatePath("/watchlist");
  return { success: true };
}

/** Get paginated alerts for a watchlist. Verify ownership. */
export async function getWatchlistAlerts(
  watchlistId: string,
  opts?: { unreadOnly?: boolean; page?: number }
) {
  const user = await requireAuth();
  await verifyOwnership(watchlistId, user.id);

  const page = opts?.page ?? 1;
  const take = 50;
  const skip = (page - 1) * take;

  const where: Record<string, unknown> = { watchlistId };
  if (opts?.unreadOnly) where.read = false;

  const [alerts, total] = await Promise.all([
    prisma.watchlistAlert.findMany({
      where: where as never,
      include: {
        item: { select: { type: true, value: true } },
      },
      orderBy: { createdAt: "desc" },
      skip,
      take,
    }),
    prisma.watchlistAlert.count({ where: where as never }),
  ]);

  return {
    alerts,
    total,
    pages: Math.ceil(total / take),
    page,
  };
}

/** Mark a single alert as read. */
export async function markAlertRead(alertId: string): Promise<{ success: boolean }> {
  const user = await requireAuth();

  const alert = await prisma.watchlistAlert.findUnique({
    where: { id: alertId },
    include: { watchlist: { select: { userId: true, id: true } } },
  });

  if (!alert || alert.watchlist.userId !== user.id) {
    throw new Error("Alert not found or access denied");
  }

  await prisma.watchlistAlert.update({
    where: { id: alertId },
    data: { read: true },
  });

  revalidatePath(`/watchlist/${alert.watchlistId}`);
  revalidatePath("/watchlist");
  return { success: true };
}

/** Mark all alerts in a watchlist as read. */
export async function markAllAlertsRead(watchlistId: string): Promise<{ success: boolean }> {
  const user = await requireAuth();
  await verifyOwnership(watchlistId, user.id);

  await prisma.watchlistAlert.updateMany({
    where: { watchlistId, read: false },
    data: { read: true },
  });

  revalidatePath(`/watchlist/${watchlistId}`);
  revalidatePath("/watchlist");
  return { success: true };
}

/** Get total unread alert count for the current user (for sidebar badge). */
export async function getAlertCount(): Promise<number> {
  const user = await requireAuth();

  const count = await prisma.watchlistAlert.count({
    where: {
      watchlist: { userId: user.id },
      read: false,
    },
  });

  return count;
}
