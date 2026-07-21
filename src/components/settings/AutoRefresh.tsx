"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { setAutoRefreshConfig } from "@/actions/settings";

interface AutoRefreshProps {
  initialHours: number;
  initialLastUpdate: string | null;
}

const INTERVAL_OPTIONS = [
  { label: "Disabled", value: 0 },
  { label: "Every 6 hours", value: 6 },
  { label: "Every 12 hours", value: 12 },
  { label: "Every 24 hours", value: 24 },
  { label: "Every 48 hours", value: 48 },
  { label: "Weekly", value: 168 },
];

function formatTimeRemaining(ms: number): string {
  if (ms <= 0) return "now";
  const totalMinutes = Math.ceil(ms / 60_000);
  if (totalMinutes < 60) return `${totalMinutes}m`;
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  if (hours >= 24) {
    const days = Math.floor(hours / 24);
    const remHours = hours % 24;
    if (remHours === 0) return `${days}d`;
    return `${days}d ${remHours}h`;
  }
  if (minutes === 0) return `${hours}h`;
  return `${hours}h ${minutes}m`;
}

export function AutoRefresh({ initialHours, initialLastUpdate }: AutoRefreshProps) {
  const [selectedHours, setSelectedHours] = useState(initialHours);
  const [savedHours, setSavedHours] = useState(initialHours);
  const [lastUpdate, setLastUpdate] = useState<string | null>(initialLastUpdate);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [refreshStatus, setRefreshStatus] = useState<"idle" | "success" | "error">("idle");
  const [timeRemaining, setTimeRemaining] = useState<string>("");
  const inFlightRef = useRef(false);

  const hasChanges = selectedHours !== savedHours;

  const computeTimeRemaining = useCallback(() => {
    if (savedHours === 0 || !lastUpdate) {
      setTimeRemaining("");
      return;
    }
    const lastMs = new Date(lastUpdate).getTime();
    const nextMs = lastMs + savedHours * 3600_000;
    const remaining = nextMs - Date.now();
    setTimeRemaining(formatTimeRemaining(remaining));
  }, [savedHours, lastUpdate]);

  // Update countdown every 30 seconds
  useEffect(() => {
    computeTimeRemaining();
    const id = setInterval(computeTimeRemaining, 30_000);
    return () => clearInterval(id);
  }, [computeTimeRemaining]);

  // Polling: check every 60s if it's time to refresh
  useEffect(() => {
    if (savedHours === 0) return;

    const checkAndRefresh = async () => {
      if (inFlightRef.current) return;

      // Determine if a refresh is due
      const shouldRefresh = !lastUpdate || (() => {
        const lastMs = new Date(lastUpdate).getTime();
        const nextMs = lastMs + savedHours * 3600_000;
        return Date.now() >= nextMs;
      })();

      if (!shouldRefresh) return;

      inFlightRef.current = true;
      setRefreshing(true);
      setRefreshStatus("idle");
      try {
        const res = await fetch("/api/update", { method: "POST" });
        const data = await res.json();
        if (res.ok && data.status === "success") {
          setRefreshStatus("success");
        } else {
          setRefreshStatus("error");
        }
      } catch {
        setRefreshStatus("error");
      } finally {
        // Always update the timestamp so we don't retry every 60s on failure.
        // On error, the next attempt will wait for the full interval to elapse.
        setLastUpdate(new Date().toISOString());
        setRefreshing(false);
        inFlightRef.current = false;
      }
    };

    // Check once on mount
    checkAndRefresh();

    const id = setInterval(checkAndRefresh, 60_000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [savedHours, lastUpdate]);

  async function handleSave() {
    setSaving(true);
    setSaved(false);
    try {
      await setAutoRefreshConfig(selectedHours);
      setSavedHours(selectedHours);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } finally {
      setSaving(false);
    }
  }

  const currentOption = INTERVAL_OPTIONS.find((o) => o.value === savedHours);
  const statusLabel = savedHours === 0
    ? "Auto-refresh disabled"
    : `Auto-refresh enabled (${currentOption?.label.toLowerCase() ?? `every ${savedHours}h`})`;

  return (
    <div className="space-y-4">
      {/* Status line */}
      <div className="flex items-center gap-2">
        <span
          className="inline-block w-2 h-2 rounded-full"
          style={{
            backgroundColor: savedHours === 0 ? "var(--text-secondary)" : "var(--accent)",
          }}
        />
        <span className="text-sm text-[var(--text-secondary)]">{statusLabel}</span>
        {savedHours > 0 && timeRemaining && !refreshing && (
          <span className="text-xs text-[var(--text-secondary)] ml-auto">
            Next refresh in {timeRemaining}
          </span>
        )}
        {refreshing && (
          <span className="text-xs text-[var(--text-secondary)] ml-auto flex items-center gap-1.5">
            <svg
              className="animate-spin"
              width="12"
              height="12"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M21 12a9 9 0 1 1-6.219-8.56" />
            </svg>
            Refreshing...
          </span>
        )}
      </div>

      {/* Controls */}
      <div className="flex items-center gap-3">
        <select
          value={selectedHours}
          onChange={(e) => setSelectedHours(Number(e.target.value))}
          className="px-3 py-2 rounded-lg text-sm border"
          style={{
            background: "var(--bg-tertiary)",
            borderColor: "var(--border)",
            color: "var(--text-primary)",
          }}
        >
          {INTERVAL_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>

        <button
          onClick={handleSave}
          disabled={!hasChanges || saving}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors border disabled:opacity-40 disabled:cursor-not-allowed"
          style={{
            background: hasChanges && !saving ? "var(--accent)" : "var(--bg-tertiary)",
            borderColor: hasChanges && !saving ? "var(--accent)" : "var(--border)",
            color: hasChanges && !saving ? "#fff" : "var(--text-secondary)",
          }}
        >
          {saving ? "Saving..." : "Save"}
        </button>

        {saved && (
          <span className="text-xs text-green-400">Saved</span>
        )}
      </div>

      {/* Last update info */}
      {lastUpdate && (
        <p className="text-xs text-[var(--text-secondary)]">
          Last successful update: {new Date(lastUpdate).toLocaleString()}
        </p>
      )}
      {!lastUpdate && savedHours > 0 && (
        <p className="text-xs text-[var(--text-secondary)]">
          No previous update recorded. Auto-refresh will trigger immediately.
        </p>
      )}

      {/* Auto-refresh result feedback */}
      {refreshStatus === "success" && (
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-green-900/30 border border-green-800/50 text-green-400 text-sm">
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
            <polyline points="22 4 12 14.01 9 11.01" />
          </svg>
          Auto-refresh completed successfully. Reload the page to see new stats.
        </div>
      )}

      {refreshStatus === "error" && (
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-red-900/30 border border-red-800/50 text-red-400 text-sm">
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <circle cx="12" cy="12" r="10" />
            <line x1="15" y1="9" x2="9" y2="15" />
            <line x1="9" y1="9" x2="15" y2="15" />
          </svg>
          Auto-refresh failed. The next attempt will retry automatically.
        </div>
      )}
    </div>
  );
}
