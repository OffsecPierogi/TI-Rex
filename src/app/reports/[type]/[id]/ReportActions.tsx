"use client";

export function ReportActions({
  jsonData,
  markdownData,
  reportTitle,
}: {
  jsonData: string;
  markdownData?: string;
  reportTitle: string;
}) {
  const slug = reportTitle.replace(/[^a-z0-9]+/gi, "-").toLowerCase();

  function handlePrint() {
    window.print();
  }

  function handleDownloadJson() {
    const blob = new Blob([jsonData], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${slug}-report.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function handleDownloadMarkdown() {
    if (!markdownData) return;
    const blob = new Blob([markdownData], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${slug}-report.md`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function handleCopy() {
    navigator.clipboard.writeText(jsonData).catch(() => {});
  }

  return (
    <div className="flex gap-3 no-print">
      <button
        onClick={handlePrint}
        className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm font-medium hover:opacity-90 transition-opacity"
      >
        Print / Save PDF
      </button>
      <button
        onClick={handleDownloadJson}
        className="px-4 py-2 bg-[var(--bg-tertiary)] border border-[var(--border)] text-[var(--text-primary)] rounded-lg text-sm font-medium hover:bg-[var(--bg-secondary)] transition-colors"
      >
        Download JSON
      </button>
      {markdownData && (
        <button
          onClick={handleDownloadMarkdown}
          className="px-4 py-2 bg-[var(--bg-tertiary)] border border-[var(--border)] text-[var(--text-primary)] rounded-lg text-sm font-medium hover:bg-[var(--bg-secondary)] transition-colors"
        >
          Download MD
        </button>
      )}
      <button
        onClick={handleCopy}
        className="px-4 py-2 bg-[var(--bg-tertiary)] border border-[var(--border)] text-[var(--text-primary)] rounded-lg text-sm font-medium hover:bg-[var(--bg-secondary)] transition-colors"
      >
        Copy JSON
      </button>
    </div>
  );
}
