"use client";

import { analyzeSample } from "@/actions/sandbox";
import { useState, useTransition } from "react";

interface AnalysisResult {
  id: string;
  indicator: string;
  indicatorType: string;
  source: string;
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  score: number;
  verdict: string | null;
  malwareFamily: string | null;
  tags: string | null;
  fileType: string | null;
  fileSize: number | null;
  fileName: string | null;
  sha256: string | null;
  md5: string | null;
  sha1: string | null;
  ssdeep: string | null;
  firstSeen: Date | null;
  lastSeen: Date | null;
  techniques: string | null;
  fetchedAt: Date;
}

function scoreColor(score: number) {
  if (score === 0) return "text-green-400";
  if (score <= 5) return "text-yellow-400";
  if (score <= 15) return "text-orange-400";
  return "text-red-400";
}

function scoreBg(score: number) {
  if (score === 0) return "bg-green-900/30";
  if (score <= 5) return "bg-yellow-900/30";
  if (score <= 15) return "bg-orange-900/30";
  return "bg-red-900/30";
}

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function SandboxSearch({ initialQuery, initialIocId }: { initialQuery?: string; initialIocId?: string }) {
  const [query, setQuery] = useState(initialQuery ?? "");
  const [results, setResults] = useState<AnalysisResult[]>([]);
  const [errors, setErrors] = useState<string[]>([]);
  const [isPending, startTransition] = useTransition();
  const [searched, setSearched] = useState(false);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!query.trim()) return;
    startTransition(async () => {
      const res = await analyzeSample(query.trim(), initialIocId ?? undefined);
      setResults(res.results as AnalysisResult[]);
      setErrors(res.errors);
      setSearched(true);
    });
  }

  return (
    <div className="space-y-6">
      <form onSubmit={handleSubmit} className="flex gap-3">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Enter SHA-256, MD5, IP address, or domain..."
          className="flex-1"
        />
        <button
          type="submit"
          disabled={isPending || !query.trim()}
          className="px-6 py-2 bg-[var(--accent)] text-white rounded-lg text-sm disabled:opacity-50 flex items-center gap-2"
        >
          {isPending ? (
            <>
              <span className="inline-block w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Analyzing...
            </>
          ) : (
            "Analyze"
          )}
        </button>
      </form>

      {errors.length > 0 && (
        <div className="space-y-2">
          {errors.map((err, i) => (
            <div key={i} className="p-3 rounded-lg bg-red-900/20 border border-red-900/50 text-sm text-red-400">
              {err}
            </div>
          ))}
        </div>
      )}

      {results.length > 0 && (
        <div className="space-y-4">
          {results.map((r) => {
            const tags: string[] = r.tags ? JSON.parse(r.tags) : [];
            const techniques: string[] = r.techniques ? JSON.parse(r.techniques) : [];
            const total = r.malicious + r.suspicious + r.harmless + r.undetected;

            return (
              <div key={r.id} className="card">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <span className={`badge ${
                      r.source === "virustotal" ? "bg-blue-900/30 text-blue-400" : "bg-green-900/30 text-green-400"
                    }`}>
                      {r.source === "virustotal" ? "VirusTotal" : "Hybrid Analysis"}
                    </span>
                    <span className="text-xs text-[var(--text-secondary)]">
                      {r.indicatorType.toUpperCase()}
                    </span>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className={`badge ${scoreBg(r.score)} ${scoreColor(r.score)} text-lg font-bold`}>
                      {r.score}
                    </div>
                    {r.verdict && (
                      <span className={`badge ${
                        r.verdict.includes("malicious") || r.verdict.includes("trojan") ? "bg-red-900/30 text-red-400" :
                        r.verdict.includes("suspicious") ? "bg-yellow-900/30 text-yellow-400" :
                        "bg-zinc-800 text-zinc-400"
                      }`}>
                        {r.verdict}
                      </span>
                    )}
                  </div>
                </div>

                {total > 0 && (
                  <div className="mb-3">
                    <div className="flex items-center gap-2 text-xs mb-1">
                      <span className="text-red-400">{r.malicious} malicious</span>
                      <span className="text-[var(--text-secondary)]">|</span>
                      <span className="text-yellow-400">{r.suspicious} suspicious</span>
                      <span className="text-[var(--text-secondary)]">|</span>
                      <span className="text-green-400">{r.harmless} harmless</span>
                      <span className="text-[var(--text-secondary)]">|</span>
                      <span className="text-zinc-400">{r.undetected} undetected</span>
                    </div>
                    <div className="w-full h-2 rounded-full bg-[var(--bg-tertiary)] flex overflow-hidden">
                      {r.malicious > 0 && <div className="h-full bg-red-500" style={{ width: `${(r.malicious / total) * 100}%` }} />}
                      {r.suspicious > 0 && <div className="h-full bg-yellow-500" style={{ width: `${(r.suspicious / total) * 100}%` }} />}
                      {r.harmless > 0 && <div className="h-full bg-green-500" style={{ width: `${(r.harmless / total) * 100}%` }} />}
                    </div>
                  </div>
                )}

                <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-xs mb-3">
                  {r.malwareFamily && (
                    <div><span className="text-[var(--text-secondary)]">Family:</span> <span className="text-red-400 font-medium">{r.malwareFamily}</span></div>
                  )}
                  {r.fileName && (
                    <div><span className="text-[var(--text-secondary)]">File:</span> <span className="font-mono">{r.fileName}</span></div>
                  )}
                  {r.fileType && (
                    <div><span className="text-[var(--text-secondary)]">Type:</span> {r.fileType}</div>
                  )}
                  {r.fileSize && (
                    <div><span className="text-[var(--text-secondary)]">Size:</span> {formatBytes(r.fileSize)}</div>
                  )}
                  {r.sha256 && (
                    <div className="col-span-2"><span className="text-[var(--text-secondary)]">SHA-256:</span> <code className="font-mono text-[10px] break-all">{r.sha256}</code></div>
                  )}
                  {r.md5 && (
                    <div><span className="text-[var(--text-secondary)]">MD5:</span> <code className="font-mono text-[10px]">{r.md5}</code></div>
                  )}
                  {r.firstSeen && (
                    <div><span className="text-[var(--text-secondary)]">First seen:</span> {new Date(r.firstSeen).toLocaleDateString()}</div>
                  )}
                  {r.lastSeen && (
                    <div><span className="text-[var(--text-secondary)]">Last seen:</span> {new Date(r.lastSeen).toLocaleDateString()}</div>
                  )}
                </div>

                {techniques.length > 0 && (
                  <div className="flex gap-1.5 flex-wrap mb-2">
                    <span className="text-[10px] text-[var(--text-secondary)]">MITRE:</span>
                    {techniques.map((t) => (
                      <span key={t} className="badge bg-[var(--accent)]/20 text-[var(--accent)] text-[10px] font-mono">{t}</span>
                    ))}
                  </div>
                )}

                {tags.length > 0 && (
                  <div className="flex gap-1.5 flex-wrap">
                    {tags.slice(0, 15).map((t) => (
                      <span key={t} className="badge bg-zinc-800 text-zinc-400 text-[10px]">{t}</span>
                    ))}
                    {tags.length > 15 && <span className="text-[10px] text-[var(--text-secondary)]">+{tags.length - 15}</span>}
                  </div>
                )}

                <div className="text-[10px] text-[var(--text-secondary)] mt-2">
                  Fetched: {new Date(r.fetchedAt).toLocaleString()}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {searched && results.length === 0 && errors.length === 0 && (
        <div className="card text-center py-8">
          <p className="text-[var(--text-secondary)]">No results found for this indicator.</p>
        </div>
      )}
    </div>
  );
}
