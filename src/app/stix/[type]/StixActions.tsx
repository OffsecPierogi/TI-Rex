"use client";

import { useState } from "react";

export function StixActions({
  jsonData,
  filename,
}: {
  jsonData: string;
  filename: string;
}) {
  const [copied, setCopied] = useState(false);

  function handleDownload() {
    const blob = new Blob([jsonData], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  function handleCopy() {
    navigator.clipboard.writeText(jsonData).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <div className="flex gap-3">
      <button
        onClick={handleDownload}
        className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm font-medium hover:opacity-90 transition-opacity"
      >
        Download JSON
      </button>
      <button
        onClick={handleCopy}
        className="px-4 py-2 bg-[var(--bg-tertiary)] border border-[var(--border)] text-[var(--text-primary)] rounded-lg text-sm font-medium hover:bg-[var(--bg-secondary)] transition-colors"
      >
        {copied ? "Copied!" : "Copy JSON"}
      </button>
    </div>
  );
}
