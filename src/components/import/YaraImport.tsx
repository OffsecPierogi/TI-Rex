"use client";

import { useState, useCallback } from "react";
import { importYaraRule, searchTechniques, searchMalware } from "@/actions/import";

interface TechniqueOption { id: string; externalId: string; name: string; }
interface MalwareOption { id: string; name: string; }

const YARA_CATEGORIES = [
  { value: "ransomware", label: "Ransomware" },
  { value: "rat", label: "RAT" },
  { value: "stealer", label: "Stealer" },
  { value: "apt-tool", label: "APT Tool" },
  { value: "packer", label: "Packer" },
  { value: "webshell", label: "Webshell" },
];

const SEVERITY_OPTIONS = ["low", "medium", "high", "critical"];

function useDebounce<T extends unknown[]>(fn: (...args: T) => void, ms: number) {
  const [timer, setTimer] = useState<ReturnType<typeof setTimeout> | null>(null);
  return useCallback(
    (...args: T) => {
      if (timer) clearTimeout(timer);
      setTimer(setTimeout(() => fn(...args), ms));
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [fn, ms, timer]
  );
}

export function YaraImport() {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [content, setContent] = useState("");
  const [category, setCategory] = useState("");
  const [severity, setSeverity] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; id?: string; error?: string } | null>(null);

  const [malwareQuery, setMalwareQuery] = useState("");
  const [malwareResults, setMalwareResults] = useState<MalwareOption[]>([]);
  const [selectedMalware, setSelectedMalware] = useState<MalwareOption | null>(null);
  const [techQuery, setTechQuery] = useState("");
  const [techResults, setTechResults] = useState<TechniqueOption[]>([]);
  const [selectedTech, setSelectedTech] = useState<TechniqueOption | null>(null);

  const debouncedMalwareSearch = useDebounce(async (q: string) => {
    if (q.length < 2) { setMalwareResults([]); return; }
    setMalwareResults(await searchMalware(q));
  }, 300);

  const debouncedTechSearch = useDebounce(async (q: string) => {
    if (q.length < 2) { setTechResults([]); return; }
    setTechResults(await searchTechniques(q));
  }, 300);

  async function handleImport() {
    setSubmitting(true); setResult(null);
    try {
      const res = await importYaraRule({ name, content, category, severity, malwareId: selectedMalware?.id, techniqueId: selectedTech?.id });
      setResult(res);
      if (res.ok) { setName(""); setContent(""); setCategory(""); setSeverity(""); setSelectedMalware(null); setSelectedTech(null); setMalwareQuery(""); setTechQuery(""); }
    } catch { setResult({ ok: false, error: "Unexpected error" }); }
    finally { setSubmitting(false); }
  }

  if (!open) {
    return (
      <button onClick={() => setOpen(true)} className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm font-medium hover:opacity-90 transition-opacity">
        + Import YARA Rule
      </button>
    );
  }

  return (
    <div className="card space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Import YARA Rule</h2>
        <button onClick={() => { setOpen(false); setResult(null); }} className="text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)]">Close</button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="block text-xs text-[var(--text-secondary)] mb-1">Rule Name *</label>
          <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. APT29_Backdoor_SunBurst" className="w-full" />
        </div>
        <div>
          <label className="block text-xs text-[var(--text-secondary)] mb-1">Category</label>
          <select value={category} onChange={(e) => setCategory(e.target.value)} className="w-full">
            <option value="">-- Select category --</option>
            {YARA_CATEGORIES.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
          </select>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div>
          <label className="block text-xs text-[var(--text-secondary)] mb-1">Severity</label>
          <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="w-full">
            <option value="">-- Select severity --</option>
            {SEVERITY_OPTIONS.map((s) => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
          </select>
        </div>
        <div className="relative">
          <label className="block text-xs text-[var(--text-secondary)] mb-1">Malware Family</label>
          {selectedMalware ? (
            <div className="flex items-center gap-2">
              <span className="badge bg-red-900/20 text-red-400">{selectedMalware.name}</span>
              <button onClick={() => { setSelectedMalware(null); setMalwareQuery(""); }} className="text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)]">Clear</button>
            </div>
          ) : (
            <>
              <input type="text" value={malwareQuery} onChange={(e) => { setMalwareQuery(e.target.value); debouncedMalwareSearch(e.target.value); }} placeholder="Search malware..." className="w-full" />
              {malwareResults.length > 0 && (
                <div className="absolute z-20 top-full left-0 right-0 mt-1 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-lg max-h-48 overflow-y-auto shadow-lg">
                  {malwareResults.map((m) => (
                    <button key={m.id} onClick={() => { setSelectedMalware(m); setMalwareResults([]); setMalwareQuery(""); }} className="block w-full text-left px-3 py-2 text-sm hover:bg-[var(--bg-tertiary)] transition-colors">{m.name}</button>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
        <div className="relative">
          <label className="block text-xs text-[var(--text-secondary)] mb-1">ATT&CK Technique</label>
          {selectedTech ? (
            <div className="flex items-center gap-2">
              <span className="badge bg-blue-900/20 text-blue-400">{selectedTech.externalId} -- {selectedTech.name}</span>
              <button onClick={() => { setSelectedTech(null); setTechQuery(""); }} className="text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)]">Clear</button>
            </div>
          ) : (
            <>
              <input type="text" value={techQuery} onChange={(e) => { setTechQuery(e.target.value); debouncedTechSearch(e.target.value); }} placeholder="Search e.g. T1055" className="w-full" />
              {techResults.length > 0 && (
                <div className="absolute z-20 top-full left-0 right-0 mt-1 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-lg max-h-48 overflow-y-auto shadow-lg">
                  {techResults.map((t) => (
                    <button key={t.id} onClick={() => { setSelectedTech(t); setTechResults([]); setTechQuery(""); }} className="block w-full text-left px-3 py-2 text-sm hover:bg-[var(--bg-tertiary)] transition-colors">
                      <span className="text-[var(--accent)]">{t.externalId}</span> {t.name}
                    </button>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      </div>

      <div>
        <label className="block text-xs text-[var(--text-secondary)] mb-1">Rule Content *</label>
        <textarea value={content} onChange={(e) => setContent(e.target.value)} placeholder={"rule Example {\n  strings:\n    $s1 = \"malware\"\n  condition:\n    $s1\n}"} rows={12} className="w-full bg-[var(--bg-tertiary)] border border-[var(--border)] rounded-lg p-3 text-sm font-mono text-[var(--text-primary)] resize-y focus:outline-none focus:border-[var(--accent)]" />
      </div>

      <button onClick={handleImport} disabled={submitting || !name.trim() || !content.trim()} className="px-5 py-2 bg-[var(--accent)] text-white rounded-lg text-sm font-medium hover:opacity-90 transition-opacity disabled:opacity-40 disabled:cursor-not-allowed">
        {submitting ? "Importing..." : "Import YARA Rule"}
      </button>

      {result && (
        <div className={`px-3 py-2 rounded-lg text-sm ${result.ok ? "bg-green-900/30 border border-green-800/50 text-green-400" : "bg-red-900/30 border border-red-800/50 text-red-400"}`}>
          {result.ok ? "YARA rule imported successfully" : `Import failed: ${result.error}`}
        </div>
      )}
    </div>
  );
}
