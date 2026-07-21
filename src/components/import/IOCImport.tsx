"use client";

import { useState } from "react";
import { importIOCs } from "@/actions/import";

interface ParsedIOC {
  value: string;
  type: string;
}

const IOC_PATTERNS: [string, RegExp][] = [
  ["sha256", /^[A-Fa-f0-9]{64}$/],
  ["md5", /^[A-Fa-f0-9]{32}$/],
  ["url", /^https?:\/\//i],
  ["email", /^[^\s@]+@[^\s@]+\.[^\s@]+$/],
  ["ipv4", /^(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?$/],
  ["domain", /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/],
];

function detectIOCType(value: string): string {
  for (const [type, pattern] of IOC_PATTERNS) {
    if (pattern.test(value)) return type;
  }
  return "unknown";
}

const IOC_TYPE_LABELS: Record<string, string> = {
  ipv4: "IPv4", domain: "Domain", sha256: "SHA-256", md5: "MD5",
  url: "URL", email: "Email", unknown: "Unknown",
};

const IOC_TYPE_STYLES: Record<string, string> = {
  ipv4: "bg-red-900/50 text-red-400",
  domain: "bg-blue-900/50 text-blue-400",
  sha256: "bg-purple-900/50 text-purple-400",
  md5: "bg-purple-900/50 text-purple-400",
  url: "bg-cyan-900/50 text-cyan-400",
  email: "bg-amber-900/50 text-amber-400",
  unknown: "bg-zinc-800 text-zinc-400",
};

export function IOCImport() {
  const [open, setOpen] = useState(false);
  const [rawText, setRawText] = useState("");
  const [source, setSource] = useState("");
  const [description, setDescription] = useState("");
  const [parsed, setParsed] = useState<ParsedIOC[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<{
    ok: boolean; inserted?: number; skipped?: number; error?: string;
  } | null>(null);

  function handleParse() {
    const lines = rawText.split(/\n/).map((l) => l.trim()).filter((l) => l.length > 0 && !l.startsWith("#"));
    setParsed(lines.map((value) => ({ value, type: detectIOCType(value) })));
    setResult(null);
  }

  async function handleImport() {
    if (!parsed.length || !source.trim()) return;
    setSubmitting(true);
    setResult(null);
    try {
      const res = await importIOCs(
        parsed.map((p) => ({ type: p.type, value: p.value, source: source.trim(), description: description.trim() || undefined }))
      );
      setResult(res);
      if (res.ok) { setRawText(""); setParsed([]); }
    } catch {
      setResult({ ok: false, error: "Unexpected error" });
    } finally {
      setSubmitting(false);
    }
  }

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm font-medium hover:opacity-90 transition-opacity"
      >
        + Import IOCs
      </button>
    );
  }

  return (
    <div className="card space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Import IOCs</h2>
        <button onClick={() => { setOpen(false); setResult(null); setParsed([]); }} className="text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)]">Close</button>
      </div>
      <p className="text-xs text-[var(--text-secondary)]">
        One indicator per line. Supported: IPv4, domain, SHA-256, MD5, URL, email. Lines starting with # are ignored.
      </p>
      <textarea
        value={rawText}
        onChange={(e) => setRawText(e.target.value)}
        placeholder={"192.168.1.1\nexample.com\nhttps://evil.example/payload\na1b2c3d4e5f6..."}
        rows={6}
        className="w-full bg-[var(--bg-tertiary)] border border-[var(--border)] rounded-lg p-3 text-sm font-mono text-[var(--text-primary)] resize-y focus:outline-none focus:border-[var(--accent)]"
      />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="block text-xs text-[var(--text-secondary)] mb-1">Source *</label>
          <input type="text" value={source} onChange={(e) => setSource(e.target.value)} placeholder="e.g. Internal hunt, CISA advisory" className="w-full" />
        </div>
        <div>
          <label className="block text-xs text-[var(--text-secondary)] mb-1">Description</label>
          <input type="text" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Optional description" className="w-full" />
        </div>
      </div>
      <button onClick={handleParse} disabled={!rawText.trim()} className="px-4 py-2 bg-[var(--bg-tertiary)] border border-[var(--border)] rounded-lg text-sm text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--accent)] transition-colors disabled:opacity-40 disabled:cursor-not-allowed">
        Parse and Preview
      </button>

      {parsed.length > 0 && (
        <div className="space-y-3 border-t border-[var(--border)] pt-4">
          <p className="text-sm font-medium">{parsed.length} indicator{parsed.length !== 1 ? "s" : ""} detected</p>
          <div className="overflow-x-auto max-h-48 overflow-y-auto">
            <table className="w-full text-sm">
              <thead><tr className="text-left text-[var(--text-secondary)] text-xs"><th className="pb-2 pr-4">Type</th><th className="pb-2">Value</th></tr></thead>
              <tbody>
                {parsed.map((ioc, i) => (
                  <tr key={i} className="table-row">
                    <td className="py-1.5 pr-4"><span className={`badge ${IOC_TYPE_STYLES[ioc.type] ?? IOC_TYPE_STYLES.unknown}`}>{IOC_TYPE_LABELS[ioc.type] ?? ioc.type}</span></td>
                    <td className="py-1.5 font-mono text-xs break-all">{ioc.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {parsed.some((p) => p.type === "unknown") && (
            <p className="text-xs text-amber-400">Some indicators could not be auto-classified.</p>
          )}
          <div className="flex items-center gap-4">
            <button onClick={handleImport} disabled={submitting || !source.trim()} className="px-5 py-2 bg-[var(--accent)] text-white rounded-lg text-sm font-medium hover:opacity-90 transition-opacity disabled:opacity-40 disabled:cursor-not-allowed">
              {submitting ? "Importing..." : "Import IOCs"}
            </button>
            {!source.trim() && <span className="text-xs text-amber-400">Source field is required</span>}
          </div>
        </div>
      )}

      {result && (
        <div className={`px-3 py-2 rounded-lg text-sm ${result.ok ? "bg-green-900/30 border border-green-800/50 text-green-400" : "bg-red-900/30 border border-red-800/50 text-red-400"}`}>
          {result.ok ? `Imported ${result.inserted} IOCs (${result.skipped} duplicates skipped)` : `Import failed: ${result.error}`}
        </div>
      )}
    </div>
  );
}
