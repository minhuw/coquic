import { ArrowRight } from "lucide-react";
import Link from "next/link";
import dailySummary from "@/examples/steward-daily-summary.json";
import growthSummary from "@/examples/steward-growth-summary.json";
import { Button } from "@/components/ui/button";
import { CoquicLogo } from "@/components/coquic-logo";
import { DailyStewardReport } from "@/components/daily-steward-report";
import { SiteHeader } from "@/components/site-header";
import { getGitHubStars } from "@/lib/github";

const routeGroups = [
  {
    title: "Measure",
    description:
      "Inspect dated evidence without reducing it to a maturity claim.",
    links: [
      {
        href: "/performance",
        label: "Performance",
        detail: "LAN throughput, latency, and history",
      },
      {
        href: "/interop",
        label: "Interop",
        detail: "Directional peer and testcase outcomes",
      },
      {
        href: "/coverage",
        label: "Coverage",
        detail: "LLVM source coverage evidence",
      },
      {
        href: "/duvet",
        label: "RFC traceability",
        detail: "Requirements mapped to implementation",
      },
    ],
  },
  {
    title: "Experiment",
    description:
      "Ask protocol questions and manipulate QUIC behavior directly.",
    links: [
      {
        href: "/workbench",
        label: "Workbench",
        detail: "Run an in-browser protocol simulation",
      },
      {
        href: "/qa",
        label: "Ask",
        detail: "Compare direct and RFC-grounded answers",
      },
      {
        href: "/docs",
        label: "Documentation",
        detail: "Use CoQUIC APIs and language bindings",
      },
    ],
  },
  {
    title: "Follow",
    description: "Study the work, decisions, and public development record.",
    links: [
      {
        href: "/steward",
        label: "Steward",
        detail: "Observe repository automation",
      },
      {
        href: "/transcript",
        label: "Dataset",
        detail: "Search public development transcripts",
      },
      {
        href: "/blog",
        label: "Journal",
        detail: "Read project notes and research articles",
      },
    ],
  },
];

export default async function HomePage() {
  const githubStars = await getGitHubStars();

  return (
    <>
      <SiteHeader githubStars={githubStars} />
      <main id="content">
        <div className="mx-auto max-w-shell px-4 sm:px-8 lg:px-12">
          <header className="grid gap-12 py-12 sm:py-16 lg:grid-cols-[minmax(0,0.8fr)_minmax(34rem,1.2fr)] lg:items-center lg:gap-16 lg:py-20">
            <div className="max-w-xl">
              <CoquicLogo className="size-20 sm:size-24" />
              <h1 className="mt-8 text-display-compact font-medium text-ink sm:text-display">
                CoQUIC
              </h1>
              <p className="mt-5 max-w-lg text-2xl font-medium leading-tight text-ink">
                An AI-built transport stack, measured in public.
              </p>
              <p className="mt-5 max-w-lg text-base leading-7 text-muted">
                An experimental open-source QUIC and HTTP/3 implementation
                exploring how far Codex can build a full-featured transport
                stack under minimal direction.
              </p>
              <div className="mt-8 flex flex-wrap items-center gap-4">
                <Button asChild>
                  <Link href="/docs">Explore the implementation</Link>
                </Button>
                <Button asChild variant="outline">
                  <a
                    href="https://github.com/minhuw/coquic"
                    target="_blank"
                    rel="noreferrer"
                  >
                    View source
                  </a>
                </Button>
              </div>
            </div>

            <DailyStewardReport
              summary={{
                ranges: growthSummary.data.ranges,
                live: dailySummary.data.live,
              }}
            />
          </header>

          <section
            aria-labelledby="observatory-title"
            className="border-t border-line py-20 sm:py-24"
          >
            <div className="grid gap-8 border-b border-line pb-8 lg:grid-cols-[minmax(0,0.7fr)_minmax(0,1.3fr)]">
              <h2
                id="observatory-title"
                className="text-2xl font-semibold leading-tight text-ink"
              >
                From packet behavior to project history
              </h2>
              <p className="max-w-2xl text-base leading-7 text-muted lg:justify-self-end">
                Measure transport behavior, run protocol experiments, and follow
                the implementation through source, revisions, and public
                development sessions.
              </p>
            </div>

            <div className="grid lg:grid-cols-3">
              {routeGroups.map((group) => (
                <div
                  key={group.title}
                  className="border-b border-line py-8 lg:border-b-0 lg:border-r lg:px-8 lg:first:pl-0 lg:last:border-r-0 lg:last:pr-0"
                >
                  <h3 className="text-xl font-semibold text-ink">
                    {group.title}
                  </h3>
                  <p className="mt-3 min-h-12 max-w-sm text-sm leading-6 text-muted">
                    {group.description}
                  </p>
                  <ul className="mt-8 border-t border-line">
                    {group.links.map((link) => (
                      <li key={link.href} className="border-b border-line">
                        <Link
                          href={link.href}
                          className="group flex min-h-20 items-center justify-between gap-4 py-4 text-ink no-underline"
                        >
                          <span className="min-w-0">
                            <span className="block text-sm font-semibold">
                              {link.label}
                            </span>
                            <span className="mt-1 block text-xs leading-5 text-muted">
                              {link.detail}
                            </span>
                          </span>
                          <ArrowRight
                            aria-hidden="true"
                            size={16}
                            strokeWidth={1.8}
                            className="shrink-0 text-muted transition-transform group-hover:translate-x-1 group-hover:text-accent motion-reduce:transition-none"
                          />
                        </Link>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </section>
        </div>
      </main>

      <footer className="border-t border-line">
        <div className="mx-auto flex max-w-shell flex-col gap-3 px-4 py-8 text-xs text-muted sm:flex-row sm:items-center sm:justify-between sm:px-8 lg:px-12">
          <p>
            CoQUIC is experimental research software, not a production-readiness
            claim.
          </p>
          <div className="flex gap-5">
            <a
              href="https://github.com/minhuw/coquic"
              className="text-inherit hover:text-ink"
            >
              GitHub
            </a>
            <a
              href="mailto:minhuw@gmail.com"
              className="text-inherit hover:text-ink"
            >
              Contact
            </a>
            <a
              href="https://github.com/minhuw/coquic/blob/main/LICENSE"
              className="text-inherit hover:text-ink"
            >
              License
            </a>
          </div>
        </div>
      </footer>
    </>
  );
}
