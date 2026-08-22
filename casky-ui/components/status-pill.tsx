const STATUS_CLASSES: Record<string, string> = {
  draft: "bg-slate-100 text-slate-700",
  planned: "bg-blue-100 text-blue-700",
  running: "bg-blue-100 text-blue-700",
  in_progress: "bg-blue-100 text-blue-700",
  completed: "bg-green-100 text-green-700",
  done: "bg-green-100 text-green-700",
  resolved: "bg-green-100 text-green-700",
  failed: "bg-red-100 text-red-700",
  open: "bg-orange-100 text-orange-700",
  accepted: "bg-slate-100 text-slate-700",
};

export function StatusPill({ status }: { status: string | null | undefined }) {
  const key = (status ?? "").toLowerCase();
  const cls = STATUS_CLASSES[key] ?? "bg-slate-100 text-slate-700";
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${cls}`}>
      {status || "unknown"}
    </span>
  );
}
