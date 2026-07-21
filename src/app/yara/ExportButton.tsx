"use client";

import { useState } from "react";
import { exportYaraRules } from "@/actions/yara";

export function ExportButton({ category, filename, content: directContent }: { category?: string; filename: string; content?: string }) {
  const [loading, setLoading] = useState(false);

  async function handleExport() {
    setLoading(true);
    try {
      const content = directContent ?? await exportYaraRules({ category });
      const blob = new Blob([content], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setLoading(false);
    }
  }

  return (
    <button
      onClick={handleExport}
      disabled={loading}
      className="px-4 py-2 text-sm rounded-lg bg-[var(--accent)] text-white hover:opacity-90 transition-opacity disabled:opacity-50"
    >
      {loading ? "Exporting..." : "Export .yar"}
    </button>
  );
}
