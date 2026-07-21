"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { createWatchlist } from "@/actions/watchlist";
import { Eye } from "lucide-react";

export default function NewWatchlistPage() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [webhookUrl, setWebhookUrl] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) {
      setError("Name is required");
      return;
    }
    setError("");
    setSubmitting(true);

    try {
      const result = await createWatchlist({
        name: name.trim(),
        description: description.trim() || undefined,
        webhookUrl: webhookUrl.trim() || undefined,
      });
      router.push(`/watchlist/${result.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create watchlist");
      setSubmitting(false);
    }
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Eye className="w-6 h-6 text-[var(--accent)]" />
          Create Watchlist
        </h1>
        <p className="text-sm text-[var(--text-secondary)]">
          Set up a new watchlist to monitor IOCs for matches in threat intel feeds
        </p>
      </div>

      <form onSubmit={handleSubmit} className="card space-y-4">
        {error && (
          <div className="px-3 py-2 rounded bg-red-900/30 border border-red-800 text-red-400 text-sm">
            {error}
          </div>
        )}

        <div>
          <label htmlFor="name" className="block text-sm font-medium mb-1">
            Name <span className="text-red-400">*</span>
          </label>
          <input
            id="name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. APT29 Infrastructure Watch"
            className="w-full"
            required
          />
        </div>

        <div>
          <label htmlFor="description" className="block text-sm font-medium mb-1">
            Description
          </label>
          <textarea
            id="description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Optional description of what this watchlist monitors..."
            className="w-full"
            rows={3}
          />
        </div>

        <div>
          <label htmlFor="webhook" className="block text-sm font-medium mb-1">
            Webhook URL
          </label>
          <input
            id="webhook"
            type="url"
            value={webhookUrl}
            onChange={(e) => setWebhookUrl(e.target.value)}
            placeholder="https://hooks.slack.com/services/..."
            className="w-full"
          />
          <p className="text-[10px] text-[var(--text-secondary)] mt-1">
            Optional. Receives a JSON POST when a watched indicator is matched.
          </p>
        </div>

        <div className="flex items-center gap-3 pt-2">
          <button
            type="submit"
            disabled={submitting}
            className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm font-medium hover:opacity-90 transition-opacity disabled:opacity-50"
          >
            {submitting ? "Creating..." : "Create Watchlist"}
          </button>
          <button
            type="button"
            onClick={() => router.push("/watchlist")}
            className="px-4 py-2 bg-[var(--bg-tertiary)] text-[var(--text-secondary)] rounded-lg text-sm hover:text-[var(--text-primary)] transition-colors"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}
