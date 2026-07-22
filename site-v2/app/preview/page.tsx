import type { Metadata } from "next";
import { ArrowRight, CircleAlert } from "lucide-react";
import { redirect } from "next/navigation";

import { CoquicLogo } from "@/components/coquic-logo";
import { Button } from "@/components/ui/button";
import { previewPassword, previewReturnPath } from "@/lib/preview-access";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "V2 preview",
  description: "Access the CoQUIC V2 work-in-progress preview.",
  robots: { index: false, follow: false },
};

interface PreviewPageProps {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}

export default async function PreviewPage({ searchParams }: PreviewPageProps) {
  if (!previewPassword()) redirect("/");

  const query = await searchParams;
  const next = previewReturnPath(query.next);
  const invalid = query.error === "invalid";

  return (
    <main className="grid min-h-screen place-items-center px-4 py-12 sm:px-8">
      <div className="w-full max-w-xl">
        <header className="flex items-center gap-3 border-b border-line pb-6">
          <CoquicLogo className="size-10 shrink-0" />
          <div>
            <p className="text-sm font-medium text-ink">CoQUIC Observatory</p>
            <p className="mt-1 text-xs text-muted">V2 compatibility preview</p>
          </div>
        </header>

        <section className="py-8 sm:py-12" aria-labelledby="preview-title">
          <p className="flex items-center gap-2 text-sm font-medium text-warning">
            <CircleAlert aria-hidden="true" size={16} strokeWidth={1.8} />
            Preview in progress
          </p>
          <h1
            id="preview-title"
            className="mt-4 text-3xl font-medium leading-tight text-ink sm:text-4xl"
          >
            CoQUIC V2 is under construction
          </h1>
          <p className="mt-5 max-w-lg text-base leading-7 text-muted">
            This is a working compatibility preview. Routes, evidence adapters,
            and interaction details are still being verified before public
            release.
          </p>

          <form className="mt-8 max-w-md" method="post" action="/api/preview-access">
            <input type="hidden" name="next" value={next} />
            <label
              htmlFor="preview-password"
              className="block text-xs font-medium text-muted"
            >
              Shared preview password
            </label>
            <input
              id="preview-password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              aria-describedby={invalid ? "preview-error preview-note" : "preview-note"}
              className="mt-2 h-11 w-full rounded-control border border-line-strong bg-transparent px-3 text-base text-ink outline-none transition-colors duration-fast focus:border-accent focus:outline-2 focus:outline-offset-2 focus:outline-ring"
            />
            {invalid ? (
              <p id="preview-error" role="alert" className="mt-3 text-sm text-negative">
                That preview password did not match.
              </p>
            ) : null}
            <Button className="mt-5" type="submit" size="lg">
              Enter preview
              <ArrowRight aria-hidden="true" />
            </Button>
          </form>
        </section>

        <footer className="border-t border-line pt-6">
          <p id="preview-note" className="max-w-lg text-xs leading-5 text-muted">
            The shared password is a preview notice, not an account or security
            boundary. Access lasts for seven days in this browser.
          </p>
        </footer>
      </div>
    </main>
  );
}
