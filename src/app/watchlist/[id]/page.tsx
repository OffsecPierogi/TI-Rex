import { getWatchlist } from "@/actions/watchlist";
import { notFound } from "next/navigation";
import Link from "next/link";
import { Eye, ArrowLeft } from "lucide-react";
import { AddItemForm } from "./AddItemForm";
import { WatchlistItems } from "./WatchlistItems";
import { WatchlistAlerts } from "./WatchlistAlerts";
import { WatchlistSettings } from "./WatchlistSettings";

export default async function WatchlistDetailPage(props: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await props.params;

  let wl;
  try {
    wl = await getWatchlist(id);
  } catch {
    notFound();
  }

  const unreadCount = wl.alerts.filter((a) => !a.read).length;

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <Link
            href="/watchlist"
            className="inline-flex items-center gap-1 text-xs text-[var(--text-secondary)] hover:text-[var(--accent)] mb-2"
          >
            <ArrowLeft className="w-3 h-3" />
            All Watchlists
          </Link>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Eye className="w-6 h-6 text-[var(--accent)]" />
            {wl.name}
          </h1>
          {wl.description && (
            <p className="text-sm text-[var(--text-secondary)] mt-1">{wl.description}</p>
          )}
        </div>
        <div className="flex items-center gap-2">
          {wl.enabled ? (
            <span className="text-xs px-2 py-1 rounded-full bg-emerald-900/30 text-emerald-400 font-medium">
              Active
            </span>
          ) : (
            <span className="text-xs px-2 py-1 rounded-full bg-zinc-800 text-zinc-400 font-medium">
              Paused
            </span>
          )}
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 gap-4">
        <div className="stat-card">
          <div className="stat-value">{wl.items.length}</div>
          <div className="text-xs text-[var(--text-secondary)]">Watched Indicators</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{wl.alerts.length}</div>
          <div className="text-xs text-[var(--text-secondary)]">Total Alerts</div>
        </div>
        <div className="stat-card">
          <div className={`stat-value ${unreadCount > 0 ? "text-red-400" : ""}`}>{unreadCount}</div>
          <div className="text-xs text-[var(--text-secondary)]">Unread Alerts</div>
        </div>
      </div>

      {/* Add Item Form */}
      <AddItemForm watchlistId={wl.id} />

      {/* Watched Items */}
      <WatchlistItems items={wl.items} />

      {/* Recent Alerts */}
      <WatchlistAlerts alerts={wl.alerts} watchlistId={wl.id} />

      {/* Settings */}
      <WatchlistSettings watchlist={wl} />
    </div>
  );
}
