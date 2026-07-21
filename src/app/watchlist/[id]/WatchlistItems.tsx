"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { removeWatchlistItem } from "@/actions/watchlist";
import { Trash2, Shield } from "lucide-react";

const TYPE_STYLES: Record<string, { bg: string; text: string; label: string }> = {
  ip: { bg: "bg-red-900/50", text: "text-red-400", label: "IP" },
  domain: { bg: "bg-blue-900/50", text: "text-blue-400", label: "Domain" },
  "hash-md5": { bg: "bg-purple-900/50", text: "text-purple-400", label: "MD5" },
  "hash-sha1": { bg: "bg-purple-900/50", text: "text-purple-400", label: "SHA-1" },
  "hash-sha256": { bg: "bg-purple-900/50", text: "text-purple-400", label: "SHA-256" },
  url: { bg: "bg-cyan-900/50", text: "text-cyan-400", label: "URL" },
  email: { bg: "bg-amber-900/50", text: "text-amber-400", label: "Email" },
  cve: { bg: "bg-orange-900/50", text: "text-orange-400", label: "CVE" },
};

interface WatchlistItemData {
  id: string;
  type: string;
  value: string;
  description: string | null;
  createdAt: Date;
}

export function WatchlistItems({ items }: { items: WatchlistItemData[] }) {
  const router = useRouter();
  const [deletingId, setDeletingId] = useState<string | null>(null);

  async function handleDelete(itemId: string) {
    if (deletingId) return;
    setDeletingId(itemId);

    try {
      await removeWatchlistItem(itemId);
      router.refresh();
    } catch (err) {
      console.error("Failed to remove item:", err);
    } finally {
      setDeletingId(null);
    }
  }

  return (
    <div className="card">
      <h2 className="text-sm font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-3">
        Watched Indicators ({items.length})
      </h2>

      {items.length === 0 ? (
        <div className="text-center py-8">
          <Shield className="w-8 h-8 text-[var(--text-secondary)] mx-auto mb-2 opacity-50" />
          <p className="text-sm text-[var(--text-secondary)]">
            No indicators added yet. Use the form above to add IOCs to watch.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {items.map((item) => {
            const style = TYPE_STYLES[item.type] ?? {
              bg: "bg-zinc-800",
              text: "text-zinc-400",
              label: item.type,
            };

            return (
              <div
                key={item.id}
                className="flex items-center gap-3 p-2 rounded-lg bg-[var(--bg-secondary)] hover:bg-[var(--bg-tertiary)] transition-colors"
              >
                <span className={`badge ${style.bg} ${style.text} shrink-0`}>
                  {style.label}
                </span>
                <code className="text-sm text-[var(--accent)] font-mono break-all flex-1 min-w-0">
                  {item.value}
                </code>
                {item.description && (
                  <span className="text-xs text-[var(--text-secondary)] truncate max-w-[200px]">
                    {item.description}
                  </span>
                )}
                <button
                  onClick={() => handleDelete(item.id)}
                  disabled={deletingId === item.id}
                  className="p-1.5 rounded hover:bg-red-900/30 text-[var(--text-secondary)] hover:text-red-400 transition-colors shrink-0 disabled:opacity-50"
                  title="Remove indicator"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
