"use client";

import { useState } from "react";

export function CopySigmaButton({ yaml }: { yaml: string }) {
  const [copied, setCopied] = useState(false);

  function handleClick() {
    navigator.clipboard.writeText(yaml).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <button
      onClick={handleClick}
      className="px-3 py-1 text-xs bg-[var(--bg-tertiary)] hover:bg-[var(--accent)] text-[var(--text-secondary)] hover:text-white rounded transition-colors"
    >
      {copied ? "Copied!" : "Copy Sigma Rule"}
    </button>
  );
}
