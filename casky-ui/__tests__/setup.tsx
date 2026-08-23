import "@testing-library/jest-dom/vitest";
import React from "react";
import { vi } from "vitest";

// next/link's App Router implementation reaches for router context that
// isn't present when a Server Component page is invoked directly in a unit
// test (see the smoke tests in this directory) — swap it for a plain
// anchor so pages render without a full Next app-router harness.
vi.mock("next/link", () => ({
  default: ({
    href,
    children,
    ...props
  }: React.AnchorHTMLAttributes<HTMLAnchorElement> & { children?: React.ReactNode }) =>
    React.createElement("a", { href, ...props }, children),
}));
