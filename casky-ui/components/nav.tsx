import Link from "next/link";
import { logoutAction } from "@/lib/actions";

const NAV_ITEMS = [
  { href: "/", label: "Dashboard" },
  { href: "/investigations", label: "Investigations" },
  { href: "/findings", label: "Findings" },
  { href: "/remediation", label: "Remediation" },
  { href: "/reports", label: "Reports" },
  { href: "/settings", label: "Settings" },
];

export function Nav() {
  return (
    <nav className="w-56 shrink-0 border-r border-white/[0.08] px-4 py-6 flex flex-col justify-between min-h-screen">
      <div>
        <div className="px-2 mb-6">
          <span className="text-sm font-semibold text-[#EAF2FF]">Casky Box</span>
        </div>
        <ul className="space-y-1">
          {NAV_ITEMS.map((item) => (
            <li key={item.href}>
              <Link
                href={item.href}
                className="block rounded-lg px-3 py-2 text-sm text-white/65 hover:bg-white/[0.05] hover:text-white transition-colors"
              >
                {item.label}
              </Link>
            </li>
          ))}
        </ul>
      </div>
      <form action={logoutAction}>
        <button
          type="submit"
          className="w-full text-left rounded-lg px-3 py-2 text-sm text-white/40 hover:bg-white/[0.05] hover:text-white/70 transition-colors"
        >
          Sign out
        </button>
      </form>
    </nav>
  );
}
