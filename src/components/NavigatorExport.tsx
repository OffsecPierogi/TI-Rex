"use client";

export function NavigatorExportButton({
  type,
  id,
  label,
}: {
  type: "actor" | "malware" | "category";
  id: string;
  label?: string;
}) {
  const href = `/api/navigator?type=${type}&id=${encodeURIComponent(id)}`;

  return (
    <a
      href={href}
      download
      className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--border)] transition-colors border border-[var(--border)]"
    >
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
        <polyline points="7 10 12 15 17 10" />
        <line x1="12" y1="15" x2="12" y2="3" />
      </svg>
      {label ?? "Export ATT&CK Navigator Layer"}
    </a>
  );
}
