"use client";

import { useActionState } from "react";
import { loginAction } from "@/lib/actions";

export function LoginForm({ nextPath }: { nextPath: string }) {
  const [state, formAction, pending] = useActionState(loginAction, { error: null });

  return (
    <form action={formAction} className="w-full max-w-sm space-y-4">
      <input type="hidden" name="next" value={nextPath} />
      <div>
        <label htmlFor="password" className="block text-xs text-white/45 mb-1">
          Admin password
        </label>
        <input
          id="password"
          name="password"
          type="password"
          required
          autoFocus
          className="w-full rounded-lg bg-white/[0.04] border border-white/[0.1] px-3 py-2 text-sm text-[#EAF2FF] outline-none focus:border-white/30"
        />
      </div>
      {state.error && <p className="text-sm text-red-400">{state.error}</p>}
      <button
        type="submit"
        disabled={pending}
        className="w-full rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-sm font-medium py-2 transition-colors"
      >
        {pending ? "Signing in…" : "Sign in"}
      </button>
    </form>
  );
}
