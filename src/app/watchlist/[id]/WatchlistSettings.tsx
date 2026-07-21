"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { updateWatchlist, deleteWatchlist } from "@/actions/watchlist";
import { Settings, Trash2, Save } from "lucide-react";

interface WatchlistData {
  id: string;
  name: string;
  description: string | null;
  webhookUrl: string | null;
  enabled: boolean;
}

export function WatchlistSettings({ watchlist }: { watchlist: WatchlistData }) {
  const router = useRouter();
  const [name, setName] = useState(watchlist.name);
  const [description, setDescription] = useState(watchlist.description ?? "");
  const [webhookUrl, setWebhookUrl] = useState(watchlist.webhookUrl ?? "");
  const [enabled, setEnabled] = useState(watchlist.enabled);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) {
      setError("Name is required");
      return;
    }
    setError("");
    setMessage("");
    setSaving(true);

    try {
      await updateWatchlist(watchlist.id, {
        name: name.trim(),
        description: description.trim() || undefined,
        webhookUrl: webhookUrl.trim() || undefined,
        enabled,
      });
      setMessage("Settings saved");
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save");
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete() {
    setDeleting(true);
    try {
      await deleteWatchlist(watchlist.id);
      router.push("/watchlist");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete");
      setDeleting(false);
      setShowDeleteConfirm(false);
    }
  }

  return (
    <div className="card">
      <h2 className="text-sm font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-3 flex items-center gap-2">
        <Settings className="w-4 h-4" />
        Settings
      </h2>

      <form onSubmit={handleSave} className="space-y-4">
        {error && (
          <div className="px-3 py-2 rounded bg-red-900/30 border border-red-800 text-red-400 text-sm">
            {error}
          </div>
        )}
        {message && (
          <div className="px-3 py-2 rounded bg-emerald-900/30 border border-emerald-800 text-emerald-400 text-sm">
            {message}
          </div>
        )}

        <div>
          <label htmlFor="settings-name" className="block text-sm font-medium mb-1">
            Name
          </label>
          <input
            id="settings-name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full"
            required
          />
        </div>

        <div>
          <label htmlFor="settings-description" className="block text-sm font-medium mb-1">
            Description
          </label>
          <textarea
            id="settings-description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className="w-full"
            rows={2}
          />
        </div>

        <div>
          <label htmlFor="settings-webhook" className="block text-sm font-medium mb-1">
            Webhook URL
          </label>
          <input
            id="settings-webhook"
            type="url"
            value={webhookUrl}
            onChange={(e) => setWebhookUrl(e.target.value)}
            placeholder="https://hooks.slack.com/services/..."
            className="w-full"
          />
        </div>

        <div className="flex items-center gap-3">
          <label className="relative inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="sr-only peer"
            />
            <div className="w-9 h-5 bg-zinc-700 rounded-full peer peer-checked:bg-emerald-600 peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all" />
          </label>
          <span className="text-sm">
            {enabled ? "Watchlist active — matching enabled" : "Watchlist paused — matching disabled"}
          </span>
        </div>

        <div className="flex items-center justify-between pt-2 border-t border-[var(--border)]">
          <button
            type="submit"
            disabled={saving}
            className="flex items-center gap-1.5 px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm font-medium hover:opacity-90 transition-opacity disabled:opacity-50"
          >
            <Save className="w-4 h-4" />
            {saving ? "Saving..." : "Save Settings"}
          </button>

          {showDeleteConfirm ? (
            <div className="flex items-center gap-2">
              <span className="text-xs text-red-400">Delete this watchlist?</span>
              <button
                type="button"
                onClick={handleDelete}
                disabled={deleting}
                className="px-3 py-1.5 bg-red-900/50 text-red-400 rounded-lg text-xs font-medium hover:bg-red-900/80 transition-colors disabled:opacity-50"
              >
                {deleting ? "Deleting..." : "Yes, Delete"}
              </button>
              <button
                type="button"
                onClick={() => setShowDeleteConfirm(false)}
                className="px-3 py-1.5 bg-[var(--bg-tertiary)] text-[var(--text-secondary)] rounded-lg text-xs hover:text-[var(--text-primary)] transition-colors"
              >
                Cancel
              </button>
            </div>
          ) : (
            <button
              type="button"
              onClick={() => setShowDeleteConfirm(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-[var(--text-secondary)] hover:text-red-400 transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Delete Watchlist
            </button>
          )}
        </div>
      </form>
    </div>
  );
}
