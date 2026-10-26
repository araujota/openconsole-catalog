"use client";

export default function CatalogError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <main className="grid min-h-screen place-items-center bg-[#090b10] px-6 text-zinc-100">
      <section role="alert" className="w-full max-w-lg rounded-2xl border border-red-300/20 bg-red-300/5 p-8 text-center">
        <span className="mx-auto grid size-11 place-items-center rounded-lg bg-red-300 text-sm font-black text-black">!</span>
        <h1 className="mt-5 text-2xl font-semibold">The catalog could not load</h1>
        <p className="mt-3 text-sm leading-6 text-zinc-400">{error.message || "The service returned an unexpected error."}</p>
        {error.digest && <p className="mt-3 font-mono text-[10px] text-zinc-400">Reference {error.digest}</p>}
        <button onClick={reset} className="mt-6 rounded-lg bg-white px-5 py-2.5 text-sm font-medium text-black focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-lime-300">Try again</button>
      </section>
    </main>
  );
}
