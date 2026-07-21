"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { markAlertRead, markAllAlertsRead } from "@/actions/watchlist";
import { Bell, CheckCheck, Circle } from "lucide-react";

const TYPE_STYLES: Record<string, { text: string; label: string }> = {
  ip: { text: "text-red-400", label: "IP" },
  domain: { text: "text-blue-400", label: "Domain" },
  "hash-md5": { text: "text-purple-400", label: "MD5" },
  "hash-sha1": { text: "text-purple-400", label: "SHA-1" },
  "hash-sha256": { text: "text-purple-400", label: "SHA-256" },
  url: { text: "text-cyan-400", label: "URL" },
  email: { text: "text-amber-400", label: "Email" },
  cve: { text: "text-orange-400", label: "CVE" },
};

interface AlertData {
  id: string;
  matchSource: string;
  matchDetail: string | null;
  read: boolean;
  createdAt: Date;
  item: {
    type: string;
    value: string;
  };
}

export function WatchlistAlerts({
  alerts,
  watchlistId,
}: {
  alerts: AlertData[];
  watchlistId: string;
}) {
  const router = useRouter();
  const [markingAll, setMarkingAll] = useState(false);
  const [markingId, setMarkingId] = useState<string | null>(null);

  const unreadCount = alerts.filter((a) => !a.read).length;

  async function handleMarkAllRead() {
    if (markingAll) return;
    setMarkingAll(true);
    try {
      await markAllAlertsRead(watchlistId);
      router.refresh();
    } catch (err) {
      console.error("Failed to mark all read:", err);
    } finally {
      setMarkingAll(false);
    }
  }

  async function handleMarkRead(alertId: string) {
    if (markingId) return;
    setMarkingId(alertId);
    try {
      await markAlertRead(alertId);
      router.refresh();
    } catch (err) {
      console.error("Failed to mark alert read:", err);
    } finally {
      setMarkingId(null);
    }
  }

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-[var(--text-secondary)]">
          Recent Alerts ({alerts.length})
        </h2>
        {unreadCount > 0 && (
          <button
            onClick={handleMarkAllRead}
            disabled={markingAll}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--bg-tertiary)] text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors disabled:opacity-50"
          >
            <CheckCheck className="w-3.5 h-3.5" />
            {markingAll ? "Marking..." : `Mark All Read (${unreadCount})`}
          </button>
        )}
      </div>

      {alerts.length === 0 ? (
        <div className="text-center py-8">
          <Bell className="w-8 h-8 text-[var(--text-secondary)] mx-auto mb-2 opacity-50" />
          <p className="text-sm text-[var(--text-secondary)]">
            No alerts yet. Alerts appear when watched indicators match ingested threat intel.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {alerts.map((alert) => {
            const typeStyle = TYPE_STYLES[alert.item.type] ?? {
              text: "text-zinc-400",
              label: alert.item.type,
            };

            return (
              <div
                key={alert.id}
                className={`flex items-start gap-3 p-3 rounded-lg transition-colors ${
                  alert.read
                    ? "bg-[var(--bg-secondary)] opacity-60"
                    : "bg-[var(--bg-secondary)] border-l-2 border-red-500"
                }`}
              >
                {/* Unread indicator */}
                <div className="mt-1 shrink-0">
                  {alert.read ? (
                    <Circle className="w-2.5 h-2.5 text-[var(--text-secondary)] opacity-30" />
                  ) : (
                    <button
                      onClick={() => handleMarkRead(alert.id)}
                      disabled={markingId === alert.id}
                      title="Mark as read"
                      className="hover:scale-125 transition-transform"
                    >
                      <Circle className="w-2.5 h-2.5 text-red-400 fill-red-400" />
                    </button>
                  )}
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`text-xs font-medium ${typeStyle.text}`}>
                      {typeStyle.label}
                    </span>
                    <code className="text-xs text-[var(--accent)] font-mono break-all">
                      {alert.item.value}
                    </code>
                  </div>
                  <p className="text-xs text-[var(--text-secondary)] mt-1">
                    Source: <span className="text-[var(--text-primary)]">{alert.matchSource}</span>
                  </p>
                  {alert.matchDetail && (
                    <p className="text-xs text-[var(--text-secondary)] mt-0.5 break-all">
                      {alert.matchDetail}
                    </p>
                  )}
                </div>

                <span className="text-[10px] text-[var(--text-secondary)] shrink-0 mt-0.5">
                  {new Date(alert.createdAt).toLocaleString()}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
