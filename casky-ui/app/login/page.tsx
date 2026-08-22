import { LoginForm } from "./login-form";

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string }>;
}) {
  const { next } = await searchParams;
  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-4">
      <div className="mb-8 text-center">
        <h1 className="text-xl font-semibold text-[#EAF2FF]">Casky Box</h1>
        <p className="text-sm text-white/45 mt-1">Sign in to browse investigations</p>
      </div>
      <LoginForm nextPath={next && next.startsWith("/") ? next : "/"} />
    </div>
  );
}
