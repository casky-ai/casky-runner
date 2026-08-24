"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import {
  ADMIN_PASSWORD_HASH_KEY,
  SESSION_COOKIE_NAME,
  SESSION_TTL_SECONDS,
  createSessionToken,
  shouldUseSecureCookie,
  verifyPassword,
} from "./auth";
import { getSetting, setSetting, updateFindingStatus, updateFindingRemediation } from "./db";
import type { FindingStatus } from "./types";

export async function loginAction(
  _prevState: { error: string | null },
  formData: FormData
): Promise<{ error: string | null }> {
  const password = String(formData.get("password") ?? "");
  const nextPath = String(formData.get("next") ?? "/");

  const storedHash = await getSetting<string>(ADMIN_PASSWORD_HASH_KEY);
  if (!storedHash) {
    return {
      error:
        "No admin password is configured yet. Check `docker compose logs ui` for the " +
        "generated password, or set CASKY_UI_ADMIN_PASSWORD and restart.",
    };
  }

  const ok = await verifyPassword(password, storedHash);
  if (!ok) {
    return { error: "Incorrect password." };
  }

  const token = await createSessionToken();
  const cookieStore = await cookies();
  cookieStore.set(SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    secure: shouldUseSecureCookie(),
    sameSite: "lax",
    path: "/",
    maxAge: SESSION_TTL_SECONDS,
  });

  redirect(nextPath && nextPath.startsWith("/") ? nextPath : "/");
}

export async function logoutAction(): Promise<void> {
  const cookieStore = await cookies();
  cookieStore.delete(SESSION_COOKIE_NAME);
  redirect("/login");
}

// ── The two narrow write paths named in the spec, besides Settings ───────
// Form-data-based (rather than positional-args-based) so they can be bound
// directly to <form action={...}> without a client component wrapper, and
// so Next's built-in server-action CSRF (same-origin) check applies as-is.

const VALID_FINDING_STATUSES: FindingStatus[] = ["open", "in_progress", "resolved", "accepted"];

export async function updateFindingStatusAction(formData: FormData): Promise<void> {
  const id = String(formData.get("id") ?? "");
  const status = String(formData.get("status") ?? "");
  if (!id || !VALID_FINDING_STATUSES.includes(status as FindingStatus)) return;
  await updateFindingStatus(id, status as FindingStatus);
  revalidatePath("/findings");
  revalidatePath("/remediation");
  revalidatePath("/investigations", "layout");
}

export async function updateFindingRemediationAction(formData: FormData): Promise<void> {
  const id = String(formData.get("id") ?? "");
  const remediation = String(formData.get("remediation") ?? "");
  if (!id) return;
  await updateFindingRemediation(id, remediation);
  revalidatePath("/findings");
  revalidatePath("/remediation");
  revalidatePath("/investigations", "layout");
}

// ── Settings writes ────────────────────────────────────────────────────

export async function saveSettingsAction(formData: FormData): Promise<void> {
  const keys = ["default_agent", "default_model", "fallback_model", "skills_repository", "tools"];
  for (const key of keys) {
    const raw = formData.get(key);
    if (raw === null) continue;
    const value = key === "tools" ? String(raw).split(",").map((s) => s.trim()).filter(Boolean) : String(raw);
    await setSetting(key, value);
  }
  revalidatePath("/settings");
}
