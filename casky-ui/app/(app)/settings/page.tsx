import { getSetting, pingDatabase } from "@/lib/db";
import { saveSettingsAction } from "@/lib/actions";

function maskDatabaseUrl(url: string | undefined): string {
  if (!url) return "(not set)";
  try {
    const u = new URL(url);
    if (u.password) u.password = "••••••";
    return u.toString();
  } catch {
    return "(unparseable DATABASE_URL)";
  }
}

export default async function SettingsPage() {
  const [defaultAgent, defaultModel, fallbackModel, skillsRepository, tools, dbOk] =
    await Promise.all([
      getSetting<string>("default_agent", ""),
      getSetting<string>("default_model", ""),
      getSetting<string>("fallback_model", ""),
      getSetting<string>("skills_repository", ""),
      getSetting<string[]>("tools", []),
      pingDatabase(),
    ]);

  return (
    <div className="max-w-2xl space-y-8">
      <div>
        <h1 className="text-lg font-semibold text-[#EAF2FF]">Settings</h1>
        <p className="text-sm text-white/45 mt-1">
          Runtime configuration read/written to the <code className="font-mono">runtime_settings</code> table.
        </p>
      </div>

      <form action={saveSettingsAction} className="space-y-5">
        <Field label="Default agent" name="default_agent" defaultValue={defaultAgent ?? ""} placeholder="claude" />
        <Field label="Default model" name="default_model" defaultValue={defaultModel ?? ""} placeholder="claude-opus-4-6" />
        <Field label="Fallback model" name="fallback_model" defaultValue={fallbackModel ?? ""} placeholder="claude-sonnet-4-6" />
        <Field
          label="Skills repository"
          name="skills_repository"
          defaultValue={skillsRepository ?? ""}
          placeholder="/opt/skills-library"
        />
        <Field
          label="Tools (comma-separated)"
          name="tools"
          defaultValue={(tools ?? []).join(", ")}
          placeholder="nmap, nuclei, zap"
        />
        <button
          type="submit"
          className="rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium px-4 py-2 transition-colors"
        >
          Save settings
        </button>
      </form>

      <div className="pt-6 border-t border-white/[0.08]">
        <h2 className="text-sm font-semibold text-white/60 mb-2">Database</h2>
        <p className="text-xs text-white/35 mb-2">
          Read-only — set via the <code className="font-mono">DATABASE_URL</code> environment
          variable and requires a restart to change (editing it here would create a
          bootstrapping contradiction, since this page itself depends on the database).
        </p>
        <div className="rounded-lg bg-white/[0.03] border border-white/[0.07] px-3 py-2 flex items-center justify-between gap-3">
          <span className="font-mono text-xs text-white/70 truncate">
            {maskDatabaseUrl(process.env.DATABASE_URL)}
          </span>
          <span
            className={`text-xs px-2 py-0.5 rounded-full shrink-0 ${
              dbOk ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"
            }`}
          >
            {dbOk ? "connected" : "unreachable"}
          </span>
        </div>
      </div>
    </div>
  );
}

function Field({
  label,
  name,
  defaultValue,
  placeholder,
}: {
  label: string;
  name: string;
  defaultValue: string;
  placeholder?: string;
}) {
  return (
    <div>
      <label htmlFor={name} className="block text-xs text-white/45 mb-1">
        {label}
      </label>
      <input
        id={name}
        name={name}
        defaultValue={defaultValue}
        placeholder={placeholder}
        className="w-full rounded-lg bg-white/[0.04] border border-white/[0.1] px-3 py-2 text-sm text-[#EAF2FF] outline-none focus:border-white/30"
      />
    </div>
  );
}
