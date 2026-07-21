"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { addWatchlistItem } from "@/actions/watchlist";
import { Plus } from "lucide-react";

const IOC_TYPE_OPTIONS = [
  { value: "ip", label: "IP Address" },
  { value: "domain", label: "Domain" },
  { value: "hash-md5", label: "Hash (MD5)" },
  { value: "hash-sha1", label: "Hash (SHA-1)" },
  { value: "hash-sha256", label: "Hash (SHA-256)" },
  { value: "url", label: "URL" },
  { value: "email", label: "Email" },
  { value: "cve", label: "CVE" },
];

export function AddItemForm({ watchlistId }: { watchlistId: string }) {
  const router = useRouter();
  const [type, setType] = useState("ip");
  const [value, setValue] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!value.trim()) {
      setError("Value is required");
      return;
    }
    setError("");
    setSubmitting(true);

    try {
      const result = await addWatchlistItem(watchlistId, {
        type,
        value: value.trim(),
        description: description.trim() || undefined,
      });

      if (!result.success) {
        setError(result.error ?? "Failed to add item");
        setSubmitting(false);
        return;
      }

      setValue("");
      setDescription("");
      setError("");
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add item");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="card">
      <h2 className="text-sm font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-3">
        Add Indicator
      </h2>

      <form onSubmit={handleSubmit} className="space-y-3">
        {error && (
          <div className="px-3 py-2 rounded bg-red-900/30 border border-red-800 text-red-400 text-sm">
            {error}
          </div>
        )}

        <div className="flex gap-3 flex-wrap">
          <select
            value={type}
            onChange={(e) => setType(e.target.value)}
            className="w-44"
          >
            {IOC_TYPE_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>

          <input
            type="text"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={
              type === "ip"
                ? "192.168.1.1"
                : type === "domain"
                  ? "malicious-domain.com"
                  : type === "hash-md5"
                    ? "d41d8cd98f00b204e9800998ecf8427e"
                    : type === "cve"
                      ? "CVE-2024-12345"
                      : "indicator value"
            }
            className="flex-1 min-w-[200px]"
            required
          />

          <input
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Description (optional)"
            className="flex-1 min-w-[150px]"
          />

          <button
            type="submit"
            disabled={submitting}
            className="flex items-center gap-1.5 px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm font-medium hover:opacity-90 transition-opacity disabled:opacity-50 shrink-0"
          >
            <Plus className="w-4 h-4" />
            {submitting ? "Adding..." : "Add"}
          </button>
        </div>
      </form>
    </div>
  );
}
