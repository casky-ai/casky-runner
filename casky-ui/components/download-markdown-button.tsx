"use client";

// Same dependency-free client-side Blob download pattern already used
// successfully in claude-skills-security/apps/web's reports download
// button — just the .md path (no PDF/print-window service here, per spec).
export function DownloadMarkdownButton({
  filename,
  markdown,
}: {
  filename: string;
  markdown: string;
}) {
  function download() {
    const blob = new Blob([markdown], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <button
      onClick={download}
      className="rounded-lg bg-white/[0.06] hover:bg-white/[0.1] px-3 py-1.5 text-xs text-white/80 transition-colors"
    >
      Download .md
    </button>
  );
}
