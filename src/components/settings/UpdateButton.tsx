"use client";

import { useState } from "react";

type Status = "idle" | "running" | "success" | "error";

export function UpdateButton() {
  const [status, setStatus] = useState<Status>("idle");
  const [errorMessage, setErrorMessage] = useState("");

  async function handleClick() {
    setStatus("running");
    setErrorMessage("");

    try {
      const res = await fetch("/api/update", { method: "POST" });
      const data = await res.json();

      if (res.ok && data.status === "success") {
        setStatus("success");
      } else {
        setStatus("error");
        setErrorMessage(data.message ?? "Unknown error");
      }
    } catch (err) {
      setStatus("error");
      setErrorMessage(String(err));
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-3">
        <button
          onClick={handleClick}
          disabled={status === "running"}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors border disabled:opacity-60 disabled:cursor-not-allowed"
          style={{
            background:
              status === "running"
                ? "var(--bg-tertiary)"
                : "var(--accent)",
            borderColor:
              status === "running"
                ? "var(--border)"
                : "var(--accent)",
            color: status === "running" ? "var(--text-secondary)" : "#fff",
          }}
        >
          {status === "running" ? (
            <svg
              className="animate-spin"
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M21 12a9 9 0 1 1-6.219-8.56" />
            </svg>
          ) : (
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <polyline points="23 4 23 10 17 10" />
              <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
            </svg>
          )}
          {status === "running" ? "Updating..." : "Refresh Data"}
        </button>

        {status === "running" && (
          <span className="text-xs text-[var(--text-secondary)]">
            This may take 2-5 minutes. Please wait...
          </span>
        )}
      </div>

      {status === "success" && (
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-green-900/30 border border-green-800/50 text-green-400 text-sm">
          <svg
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
            <polyline points="22 4 12 14.01 9 11.01" />
          </svg>
          Update completed successfully. Reload the page to see new stats.
        </div>
      )}

      {status === "error" && (
        <div className="flex items-start gap-2 px-3 py-2 rounded-lg bg-red-900/30 border border-red-800/50 text-red-400 text-sm">
          <svg
            className="mt-0.5 shrink-0"
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <circle cx="12" cy="12" r="10" />
            <line x1="15" y1="9" x2="9" y2="15" />
            <line x1="9" y1="9" x2="15" y2="15" />
          </svg>
          <span>
            Update failed.{" "}
            {errorMessage && (
              <span className="text-red-400/70">{errorMessage}</span>
            )}
          </span>
        </div>
      )}
    </div>
  );
}
