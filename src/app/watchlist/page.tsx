import { getWatchlists } from "@/actions/watchlist";
import Link from "next/link";
import { Eye, Plus, Bell, BellOff } from "lucide-react";

export default async function WatchlistPage() {
  const watchlists = await getWatchlists();

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Eye className="w-6 h-6 text-[var(--accent)]" />
            IOC Watchlist
          </h1>
          <p className="text-sm text-[var(--text-secondary)]">
            Monitor indicators of compromise and get alerted on matches
          </p>
        </div>
        <Link
          href="/watchlist/new"
          className="flex items-center gap-2 px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm font-medium hover:opacity-90 transition-opacity"
        >
          <Plus className="w-4 h-4" />
          Create Watchlist
        </Link>
      </div>

      {watchlists.length === 0 ? (
        <div className="card text-center py-16">
          <Eye className="w-12 h-12 text-[var(--text-secondary)] mx-auto mb-4 opacity-50" />
          <h2 className="text-lg font-semibold mb-2">No Watchlists Yet</h2>
          <p className="text-sm text-[var(--text-secondary)] mb-6 max-w-md mx-auto">
            Create a watchlist to monitor specific IPs, domains, hashes, and other
            indicators. You will be alerted when they appear in ingested threat intel.
          </p>
          <Link
            href="/watchlist/new"
            className="inline-flex items-center gap-2 px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm font-medium hover:opacity-90 transition-opacity"
          >
            <Plus className="w-4 h-4" />
            Create Your First Watchlist
          </Link>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {watchlists.map((wl) => (
            <Link
              key={wl.id}
              href={`/watchlist/${wl.id}`}
              className="card hover:border-[var(--accent)] transition-colors group"
            >
              <div className="flex items-start justify-between mb-2">
                <h3 className="font-semibold text-[var(--text-primary)] group-hover:text-[var(--accent)] transition-colors">
                  {wl.name}
                </h3>
                <div className="flex items-center gap-2">
                  {wl.unreadAlertCount > 0 && (
                    <span className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-red-900/50 text-red-400 text-xs font-medium">
                      <Bell className="w-3 h-3" />
                      {wl.unreadAlertCount}
                    </span>
                  )}
                  {wl.enabled ? (
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-900/30 text-emerald-400 font-medium">
                      Active
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-zinc-800 text-zinc-400 font-medium">
                      <BellOff className="w-3 h-3" />
                      Paused
                    </span>
                  )}
                </div>
              </div>

              {wl.description && (
                <p className="text-xs text-[var(--text-secondary)] mb-3 line-clamp-2">
                  {wl.description}
                </p>
              )}

              <div className="flex items-center gap-4 text-xs text-[var(--text-secondary)]">
                <span>{wl.itemCount} indicator{wl.itemCount !== 1 ? "s" : ""}</span>
                <span>{wl.alertCount} alert{wl.alertCount !== 1 ? "s" : ""}</span>
                <span className="ml-auto">
                  {new Date(wl.createdAt).toLocaleDateString()}
                </span>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
