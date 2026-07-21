"use client";

import { useState } from "react";
import { setIocRetentionDays, pruneStaleIocs } from "@/actions/settings";

interface IocRetentionProps {
  initialDays: number;
  lastPruned: string | null;
  lastPrunedCount: number;
  currentIocCount: number;
}

const RETENTION_OPTIONS = [
  { label: "30 days", value: 30 },
  { label: "60 days", value: 60 },
  { label: "90 days (default)", value: 90 },
  { label: "180 days", value: 180 },
  { label: "1 year", value: 365 },
  { label: "No limit", value: 0 },
];

export function IocRetention({ initialDays, lastPruned, lastPrunedCount, currentIocCount }: IocRetentionProps) {
  const [selectedDays, setSelectedDays] = useState(initialDays);
  const [savedDays, setSavedDays] = useState(initialDays);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [pruning, setPruning] = useState(false);
  const [pruneResult, setPruneResult] = useState<{ deleted: number } | null>(null);

  const hasChanges = selectedDays !== savedDays;

  async function handleSave() {
    setSaving(true);
    setSaved(false);
    try {
      await setIocRetentionDays(selectedDays);
      setSavedDays(selectedDays);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } finally {
      setSaving(false);
    }
  }

  async function handlePrune() {
    setPruning(true);
    setPruneResult(null);
    try {
      const result = await pruneStaleIocs();
      setPruneResult(result);
    } finally {
      setPruning(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <span
          className="inline-block w-2 h-2 rounded-full"
          style={{
            backgroundColor: savedDays === 0 ? "var(--text-secondary)" : "var(--accent)",
          }}
        />
        <span className="text-sm text-[var(--text-secondary)]">
          {savedDays === 0
            ? "IOC retention: unlimited (no auto-pruning)"
            : `IOC retention: ${savedDays} days`}
        </span>
        <span className="text-xs text-[var(--text-secondary)] ml-auto">
          {currentIocCount.toLocaleString()} IOCs in database
        </span>
      </div>

      <div className="flex items-center gap-3">
        <select
          value={selectedDays}
          onChange={(e) => setSelectedDays(Number(e.target.value))}
          className="px-3 py-2 rounded-lg text-sm border"
          style={{
            background: "var(--bg-tertiary)",
            borderColor: "var(--border)",
            color: "var(--text-primary)",
          }}
        >
          {RETENTION_OPTIONS.map((opt) => (
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

        {saved && <span className="text-xs text-green-400">Saved</span>}

        <button
          onClick={handlePrune}
          disabled={pruning || savedDays === 0}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors border disabled:opacity-40 disabled:cursor-not-allowed ml-auto"
          style={{
            background: "var(--bg-tertiary)",
            borderColor: "var(--border)",
            color: "var(--text-secondary)",
          }}
        >
          {pruning ? "Pruning..." : "Prune Now"}
        </button>
      </div>

      {lastPruned && !pruneResult && (
        <p className="text-xs text-[var(--text-secondary)]">
          Last pruned: {new Date(lastPruned).toLocaleString()} — removed {lastPrunedCount.toLocaleString()} stale IOCs
        </p>
      )}

      {pruneResult && (
        <div className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm ${
          pruneResult.deleted > 0
            ? "bg-green-900/30 border border-green-800/50 text-green-400"
            : "bg-zinc-800/50 border border-zinc-700/50 text-zinc-400"
        }`}>
          {pruneResult.deleted > 0
            ? `Pruned ${pruneResult.deleted.toLocaleString()} stale IOCs (advisory-linked IOCs preserved)`
            : "No stale IOCs to prune"}
        </div>
      )}

      <p className="text-xs text-[var(--text-secondary)]">
        IOCs linked to CISA KEV advisories are never pruned. Pruning runs automatically at the end of each update cycle.
      </p>
    </div>
  );
}
