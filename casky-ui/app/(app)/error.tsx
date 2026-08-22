"use client";

export default function AppError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="max-w-lg mx-auto mt-16 text-center">
      <h1 className="text-lg font-semibold text-[#EAF2FF] mb-2">Something went wrong</h1>
      <p className="text-sm text-white/55 mb-1">
        {error.message.includes("DATABASE_URL") || error.name === "DatabaseUnavailable"
          ? "casky-ui could not reach its database."
          : "An unexpected error occurred loading this page."}
      </p>
      <p className="text-xs text-white/35 mb-6 font-mono break-words">{error.message}</p>
      <button
        onClick={() => reset()}
        className="rounded-lg bg-white/[0.06] hover:bg-white/[0.1] px-4 py-2 text-sm text-white/80 transition-colors"
      >
        Try again
      </button>
    </div>
  );
}
