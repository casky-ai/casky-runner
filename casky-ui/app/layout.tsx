import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Casky Box",
  description: "Browse investigations, findings, remediation, and reports.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
