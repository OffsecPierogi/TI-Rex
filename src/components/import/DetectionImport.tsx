"use client";

import { useState } from "react";
import { importDetectionRule } from "@/actions/import";

const DETECTION_FORMATS = [
  { value: "sigma", label: "Sigma" },
  { value: "kql", label: "KQL" },
  { value: "splunk", label: "SPL / Splunk" },
  { value: "snort", label: "Snort" },
  { value: "yara", label: "YARA" },
];

const SEVERITY_OPTIONS = ["low", "medium", "high", "critical"];

export function DetectionImport({ categories }: { categories: string[] }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [format, setFormat] = useState("");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("");
  const [category, setCategory] = useState("");
  const [techniqueId, setTechniqueId] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; id?: string; warning?: string; error?: string } | null>(null);

  async function handleImport() {
    setSubmitting(true); setResult(null);
    try {
      const res = await importDetectionRule({ name, description, format, query, severity, category, techniqueExternalId: techniqueId.trim() || undefined });
      setResult(res);
      if (res.ok) { setName(""); setDescription(""); setFormat(""); setQuery(""); setSeverity(""); setCategory(""); setTechniqueId(""); }
    } catch { setResult({ ok: false, error: "Unexpected error" }); }
    finally { setSubmitting(false); }
  }

  if (!open) {
    return (
      <button onClick={() => setOpen(true)} className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm font-medium hover:opacity-90 transition-opacity">
        + Import Detection Rule
      </button>
    );
  }

  return (
    <div className="card space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Import Detection Rule</h2>
        <button onClick={() => { setOpen(false); setResult(null); }} className="text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)]">Close</button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="block text-xs text-[var(--text-secondary)] mb-1">Rule Name *</label>
          <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Detect Mimikatz Credential Dump" className="w-full" />
        </div>
        <div>
          <label className="block text-xs text-[var(--text-secondary)] mb-1">Format *</label>
          <select value={format} onChange={(e) => setFormat(e.target.value)} className="w-full">
            <option value="">-- Select format --</option>
            {DETECTION_FORMATS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
          </select>
        </div>
      </div>

      <div>
        <label className="block text-xs text-[var(--text-secondary)] mb-1">Description</label>
        <input type="text" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="What does this rule detect?" className="w-full" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div>
          <label className="block text-xs text-[var(--text-secondary)] mb-1">Severity</label>
          <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="w-full">
            <option value="">-- Select severity --</option>
            {SEVERITY_OPTIONS.map((s) => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs text-[var(--text-secondary)] mb-1">Category</label>
          <select value={category} onChange={(e) => setCategory(e.target.value)} className="w-full">
            <option value="">-- Select category --</option>
            {categories.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs text-[var(--text-secondary)] mb-1">ATT&CK Technique ID</label>
          <input type="text" value={techniqueId} onChange={(e) => setTechniqueId(e.target.value)} placeholder="e.g. T1003.001" className="w-full" />
        </div>
      </div>

      <div>
        <label className="block text-xs text-[var(--text-secondary)] mb-1">Rule / Query Content *</label>
        <textarea value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Paste your detection rule or query here..." rows={12} className="w-full bg-[var(--bg-tertiary)] border border-[var(--border)] rounded-lg p-3 text-sm font-mono text-[var(--text-primary)] resize-y focus:outline-none focus:border-[var(--accent)]" />
      </div>

      <button onClick={handleImport} disabled={submitting || !name.trim() || !format || !query.trim()} className="px-5 py-2 bg-[var(--accent)] text-white rounded-lg text-sm font-medium hover:opacity-90 transition-opacity disabled:opacity-40 disabled:cursor-not-allowed">
        {submitting ? "Importing..." : "Import Detection Rule"}
      </button>

      {result && (
        <div className={`px-3 py-2 rounded-lg text-sm ${result.ok ? "bg-green-900/30 border border-green-800/50 text-green-400" : "bg-red-900/30 border border-red-800/50 text-red-400"}`}>
          {result.ok ? (
            <>Detection rule imported successfully{result.warning && <span className="block text-xs text-amber-400 mt-1">{result.warning}</span>}</>
          ) : `Import failed: ${result.error}`}
        </div>
      )}
    </div>
  );
}
