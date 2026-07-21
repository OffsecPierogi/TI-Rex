"use client";

import { useState } from "react";
import { enrichIOC, type EnrichmentResult } from "@/actions/enrichment";
import Link from "next/link";

export function EnrichButton({ indicator, iocId }: { indicator: string; iocId: string }) {
  const [result, setResult] = useState<EnrichmentResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState(false);

  async function handleEnrich() {
    if (result) { setExpanded(!expanded); return; }
    setLoading(true);
    try {
      const data = await enrichIOC(indicator, iocId);
      setResult(data);
      setExpanded(true);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <button
        onClick={handleEnrich}
        disabled={loading}
        className="badge bg-emerald-900/30 text-emerald-400 hover:bg-emerald-900/50 shrink-0 text-[10px] disabled:opacity-50 cursor-pointer"
      >
        {loading ? "Enriching..." : result ? (expanded ? "Hide" : "Show") : "Enrich"}
      </button>

      {expanded && result && (
        <div className="mt-3 p-3 bg-[var(--bg-tertiary)] rounded-lg space-y-3 text-xs">
          {result.errors.length > 0 && (
            <div className="text-yellow-400">
              {result.errors.map((e, i) => <p key={i}>{e}</p>)}
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {/* VirusTotal */}
            <div className="p-2.5 bg-[var(--bg-secondary)] rounded-lg">
              <p className="font-semibold text-[var(--text-primary)] mb-1.5">VirusTotal</p>
              {result.vt ? (
                <div className="space-y-1">
                  <div className="flex justify-between">
                    <span className="text-[var(--text-secondary)]">Score</span>
                    <span className={result.vt.malicious > 5 ? "text-red-400 font-bold" : result.vt.malicious > 0 ? "text-yellow-400" : "text-green-400"}>
                      {result.vt.malicious}/{result.vt.total}
                    </span>
                  </div>
                  {result.vt.verdict && (
                    <div className="flex justify-between">
                      <span className="text-[var(--text-secondary)]">Verdict</span>
                      <span className="text-red-400">{result.vt.verdict}</span>
                    </div>
                  )}
                  {result.vt.malwareFamily && (
                    <div className="flex justify-between">
                      <span className="text-[var(--text-secondary)]">Family</span>
                      <span className="text-purple-400">{result.vt.malwareFamily}</span>
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-[var(--text-secondary)]">No data / API key not set</p>
              )}
            </div>

            {/* AbuseIPDB */}
            <div className="p-2.5 bg-[var(--bg-secondary)] rounded-lg">
              <p className="font-semibold text-[var(--text-primary)] mb-1.5">AbuseIPDB</p>
              {result.abuseipdb ? (
                <div className="space-y-1">
                  <div className="flex justify-between">
                    <span className="text-[var(--text-secondary)]">Confidence</span>
                    <span className={result.abuseipdb.abuseConfidenceScore > 50 ? "text-red-400 font-bold" : result.abuseipdb.abuseConfidenceScore > 0 ? "text-yellow-400" : "text-green-400"}>
                      {result.abuseipdb.abuseConfidenceScore}%
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[var(--text-secondary)]">Reports</span>
                    <span>{result.abuseipdb.totalReports} ({result.abuseipdb.numDistinctUsers} users)</span>
                  </div>
                  {result.abuseipdb.isp && (
                    <div className="flex justify-between">
                      <span className="text-[var(--text-secondary)]">ISP</span>
                      <span className="text-right truncate ml-2">{result.abuseipdb.isp}</span>
                    </div>
                  )}
                  {result.abuseipdb.countryCode && (
                    <div className="flex justify-between">
                      <span className="text-[var(--text-secondary)]">Country</span>
                      <span>{result.abuseipdb.countryCode}</span>
                    </div>
                  )}
                  {result.abuseipdb.usageType && (
                    <div className="flex justify-between">
                      <span className="text-[var(--text-secondary)]">Usage</span>
                      <span className="text-right truncate ml-2">{result.abuseipdb.usageType}</span>
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-[var(--text-secondary)]">
                  {result.type === "ip" ? "No data / API key not set" : "IP addresses only"}
                </p>
              )}
            </div>

            {/* Shodan */}
            <div className="p-2.5 bg-[var(--bg-secondary)] rounded-lg">
              <p className="font-semibold text-[var(--text-primary)] mb-1.5">Shodan</p>
              {result.shodan ? (
                <div className="space-y-1">
                  {result.shodan.org && (
                    <div className="flex justify-between">
                      <span className="text-[var(--text-secondary)]">Org</span>
                      <span className="text-right truncate ml-2">{result.shodan.org}</span>
                    </div>
                  )}
                  {result.shodan.os && (
                    <div className="flex justify-between">
                      <span className="text-[var(--text-secondary)]">OS</span>
                      <span>{result.shodan.os}</span>
                    </div>
                  )}
                  {result.shodan.ports.length > 0 && (
                    <div>
                      <span className="text-[var(--text-secondary)]">Ports</span>
                      <div className="flex gap-1 flex-wrap mt-0.5">
                        {result.shodan.ports.slice(0, 12).map((p) => (
                          <span key={p} className="badge bg-zinc-800 text-zinc-400">{p}</span>
                        ))}
                        {result.shodan.ports.length > 12 && (
                          <span className="text-[var(--text-secondary)]">+{result.shodan.ports.length - 12}</span>
                        )}
                      </div>
                    </div>
                  )}
                  {result.shodan.vulns.length > 0 && (
                    <div>
                      <span className="text-[var(--text-secondary)]">Vulns</span>
                      <div className="flex gap-1 flex-wrap mt-0.5">
                        {result.shodan.vulns.slice(0, 6).map((v) => (
                          <span key={v} className="badge bg-red-900/50 text-red-400">{v}</span>
                        ))}
                        {result.shodan.vulns.length > 6 && (
                          <span className="text-[var(--text-secondary)]">+{result.shodan.vulns.length - 6}</span>
                        )}
                      </div>
                    </div>
                  )}
                  {result.shodan.services.length > 0 && (
                    <div>
                      <span className="text-[var(--text-secondary)]">Services</span>
                      <div className="mt-0.5 space-y-0.5">
                        {result.shodan.services.slice(0, 5).map((s, i) => (
                          <div key={i} className="text-[10px]">
                            <span className="text-[var(--accent)]">{s.port}/{s.transport}</span>
                            {s.product && <span className="ml-1">{s.product} {s.version ?? ""}</span>}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-[var(--text-secondary)]">
                  {result.type === "ip" ? "No data / API key not set" : "IP addresses only"}
                </p>
              )}
            </div>
          </div>

          {(result.linkedMalware.length > 0 || result.linkedActors.length > 0) && (
            <div className="pt-2 border-t border-[var(--border)]">
              <p className="font-semibold text-[var(--text-primary)] mb-1">Linked Intelligence</p>
              <div className="flex gap-2 flex-wrap">
                {result.linkedMalware.map((m) => (
                  <Link key={m.id} href={`/malware/${m.id}`}>
                    <span className="badge bg-purple-900/30 text-purple-400 hover:bg-purple-900/50 cursor-pointer">{m.name}</span>
                  </Link>
                ))}
                {result.linkedActors.map((a) => (
                  <Link key={a.id} href={`/actors/${a.id}`}>
                    <span className="badge bg-red-900/30 text-red-400 hover:bg-red-900/50 cursor-pointer">{a.name}</span>
                  </Link>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
