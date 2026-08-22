"use client";

import { useRef } from "react";
import { updateFindingRemediationAction, updateFindingStatusAction } from "@/lib/actions";
import type { FindingStatus } from "@/lib/types";

const STATUSES: FindingStatus[] = ["open", "in_progress", "resolved", "accepted"];

export function FindingStatusForm({ id, status }: { id: string; status: FindingStatus }) {
  const formRef = useRef<HTMLFormElement>(null);
  return (
    <form ref={formRef} action={updateFindingStatusAction}>
      <input type="hidden" name="id" value={id} />
      <select
        name="status"
        defaultValue={status}
        onChange={() => formRef.current?.requestSubmit()}
        className="text-xs rounded-md bg-white/[0.06] border border-white/10 px-2 py-1 text-white/80 outline-none"
      >
        {STATUSES.map((s) => (
          <option key={s} value={s} className="bg-[#101826]">
            {s}
          </option>
        ))}
      </select>
    </form>
  );
}

export function FindingRemediationForm({
  id,
  remediation,
}: {
  id: string;
  remediation: string | null;
}) {
  return (
    <form action={updateFindingRemediationAction} className="w-full flex flex-col gap-2">
      <input type="hidden" name="id" value={id} />
      <textarea
        name="remediation"
        defaultValue={remediation ?? ""}
        rows={3}
        placeholder="Add or edit remediation guidance…"
        className="w-full text-xs rounded-lg bg-white/[0.04] border border-white/10 px-3 py-2 text-white/80 outline-none focus:border-white/30"
      />
      <button
        type="submit"
        className="self-end text-xs rounded-md bg-white/[0.08] hover:bg-white/[0.14] px-3 py-1.5 text-white/80 transition-colors"
      >
        Save remediation
      </button>
    </form>
  );
}
