"use client";

import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { ChevronDown, Menu, Star, X } from "lucide-react";
import Link from "next/link";
import {
  type FocusEvent,
  type KeyboardEvent as ReactKeyboardEvent,
  type MouseEvent,
  useEffect,
  useRef,
  useState,
} from "react";
import { CoquicLogo } from "@/components/coquic-logo";
import { GitHubMark } from "@/components/github-mark";
import { Button } from "@/components/ui/button";

const directLinks = [
  { href: "/steward", label: "Steward" },
  { href: "/docs", label: "Documentation" },
  { href: "/blog", label: "Journal" },
];

const navigationGroups = [
  {
    label: "Evidence",
    links: [
      { href: "/performance", label: "Performance" },
      { href: "/interop", label: "Interop" },
      { href: "/coverage", label: "Coverage" },
      { href: "/duvet", label: "RFC traceability" },
      { href: "/transcript", label: "Dataset" },
    ],
  },
  {
    label: "Tools",
    links: [
      { href: "/workbench", label: "Workbench" },
      { href: "/qa", label: "Ask" },
    ],
  },
];

interface SiteHeaderProps {
  githubStars: number | null;
}

function openDisclosure(event: MouseEvent<HTMLDetailsElement>) {
  event.currentTarget.open = true;
}

function closeDisclosure(event: MouseEvent<HTMLDetailsElement>) {
  event.currentTarget.open = false;
}

function openFocusedDisclosure(event: FocusEvent<HTMLDetailsElement>) {
  event.currentTarget.open = true;
}

function closeBlurredDisclosure(event: FocusEvent<HTMLDetailsElement>) {
  if (
    event.relatedTarget instanceof Node &&
    event.currentTarget.contains(event.relatedTarget)
  ) {
    return;
  }

  event.currentTarget.open = false;
}

function closeDisclosureOnEscape(
  event: ReactKeyboardEvent<HTMLDetailsElement>,
) {
  if (event.key !== "Escape") return;

  event.currentTarget.open = false;
  event.currentTarget.querySelector("summary")?.focus();
}

function keepHoveredDisclosureOpen(event: MouseEvent<HTMLElement>) {
  const disclosure = event.currentTarget.parentElement;
  if (
    disclosure instanceof HTMLDetailsElement &&
    disclosure.open &&
    window.matchMedia("(hover: hover)").matches
  ) {
    event.preventDefault();
  }
}

export function SiteHeader({ githubStars }: SiteHeaderProps) {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const firstLinkRef = useRef<HTMLAnchorElement>(null);
  const reducedMotion = useReducedMotion();

  useEffect(() => {
    if (!open) return;

    firstLinkRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      setOpen(false);
      triggerRef.current?.focus();
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open]);

  const closeMenu = () => setOpen(false);

  return (
    <header className="sticky top-0 z-40 h-16 border-b border-line bg-canvas">
      <a
        href="#content"
        className="absolute left-4 top-2 z-50 -translate-y-20 bg-ink px-4 py-2 text-sm font-medium text-canvas focus:translate-y-0"
      >
        Skip to content
      </a>
      <div className="mx-auto flex h-full max-w-shell items-center gap-8 px-4 sm:px-8 lg:px-12">
        <Link
          href="/"
          className="flex shrink-0 items-center gap-2.5 text-wordmark font-semibold text-ink no-underline"
        >
          <CoquicLogo className="size-7" />
          <span>CoQUIC</span>
        </Link>

        <nav
          aria-label="Primary"
          className="hidden h-full flex-1 items-center gap-7 nav:flex"
        >
          {directLinks.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className="flex h-full items-center border-b-2 border-transparent text-sm font-medium text-muted no-underline transition-colors hover:text-ink"
            >
              {link.label}
            </Link>
          ))}
          <div className="ml-auto flex h-full items-center gap-7">
            {navigationGroups.map((group) => (
              <details
                key={group.label}
                name="primary-navigation"
                className="group relative flex h-full items-center"
                onMouseEnter={openDisclosure}
                onMouseLeave={closeDisclosure}
                onFocus={openFocusedDisclosure}
                onBlur={closeBlurredDisclosure}
                onKeyDown={closeDisclosureOnEscape}
              >
                <summary
                  className="flex h-full cursor-pointer list-none items-center gap-1 border-b-2 border-transparent text-sm font-medium text-muted transition-colors hover:text-ink [&::-webkit-details-marker]:hidden"
                  onClick={keepHoveredDisclosureOpen}
                >
                  {group.label}
                  <ChevronDown
                    aria-hidden="true"
                    size={14}
                    strokeWidth={1.8}
                    className="transition-transform group-open:rotate-180 motion-reduce:transition-none"
                  />
                </summary>
                <div className="absolute left-0 top-[calc(100%-1px)] w-56 rounded-layer border border-line bg-surface p-2 shadow-temporary">
                  {group.links.map((link) => (
                    <Link
                      key={link.href}
                      href={link.href}
                      className="block rounded-control px-3 py-2.5 text-sm font-medium text-ink no-underline hover:bg-accent-soft hover:text-accent"
                    >
                      {link.label}
                    </Link>
                  ))}
                </div>
              </details>
            ))}
            <a
              href="https://github.com/minhuw/coquic"
              target="_blank"
              rel="noreferrer"
              className="group flex items-center gap-2.5 text-ink no-underline"
              aria-label={`minhuw/coquic on GitHub, ${githubStars === null ? "star count unavailable" : `${githubStars.toLocaleString("en-US")} ${githubStars === 1 ? "star" : "stars"}`}`}
            >
              <GitHubMark className="size-8 shrink-0 text-muted transition-colors group-hover:text-ink" />
              <span>
                <span className="block text-[15px] font-medium leading-[18px] text-ink">
                  minhuw/coquic
                </span>
                <span className="flex items-center gap-1 text-sm leading-4 text-muted">
                  <Star aria-hidden="true" size={15} strokeWidth={1.7} />
                  {githubStars === null
                    ? "Unavailable"
                    : githubStars.toLocaleString("en-US")}
                </span>
              </span>
            </a>
          </div>
        </nav>

        <Button
          ref={triggerRef}
          type="button"
          variant="ghost"
          size="icon"
          className="ml-auto nav:hidden"
          aria-label={open ? "Close navigation" : "Open navigation"}
          aria-expanded={open}
          aria-controls="mobile-navigation"
          onClick={() => setOpen((value) => !value)}
        >
          {open ? <X aria-hidden="true" /> : <Menu aria-hidden="true" />}
        </Button>
      </div>

      <AnimatePresence>
        {open ? (
          <>
            <motion.button
              type="button"
              aria-label="Close navigation"
              className="fixed inset-x-0 bottom-0 top-16 z-40 bg-ink/20 nav:hidden"
              initial={reducedMotion ? false : { opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.16 }}
              onClick={closeMenu}
            />
            <motion.nav
              id="mobile-navigation"
              aria-label="Mobile"
              className="fixed bottom-0 right-0 top-16 z-50 w-[min(22.5rem,100%)] overflow-y-auto border-l border-line bg-surface px-6 py-8 nav:hidden"
              initial={reducedMotion ? false : { opacity: 0, x: 24 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 24 }}
              transition={{ duration: 0.16, ease: "easeOut" }}
            >
              {directLinks.map((link, index) => (
                <Link
                  key={link.href}
                  ref={index === 0 ? firstLinkRef : undefined}
                  href={link.href}
                  onClick={closeMenu}
                  className="flex min-h-11 items-center border-b border-line text-base font-medium text-ink no-underline"
                >
                  {link.label}
                </Link>
              ))}
              {navigationGroups.map((group) => (
                <div key={group.label} className="mt-7">
                  <p className="mb-2 text-xs font-medium text-muted">
                    {group.label}
                  </p>
                  <div className="border-t border-line">
                    {group.links.map((link) => (
                      <Link
                        key={link.href}
                        href={link.href}
                        onClick={closeMenu}
                        className="flex min-h-11 items-center border-b border-line text-base font-medium text-ink no-underline"
                      >
                        {link.label}
                      </Link>
                    ))}
                  </div>
                </div>
              ))}
              <a
                href="https://github.com/minhuw/coquic"
                target="_blank"
                rel="noreferrer"
                className="mt-8 flex min-h-11 items-center gap-2.5 border-t border-line pt-5 text-ink no-underline"
              >
                <GitHubMark className="size-8 shrink-0 text-muted" />
                <span>
                  <span className="block text-[15px] font-medium leading-[18px]">
                    minhuw/coquic
                  </span>
                  <span className="flex items-center gap-1 text-sm leading-4 text-muted">
                    <Star aria-hidden="true" size={15} strokeWidth={1.7} />
                    {githubStars === null
                      ? "Star count unavailable"
                      : githubStars.toLocaleString("en-US")}
                  </span>
                </span>
              </a>
            </motion.nav>
          </>
        ) : null}
      </AnimatePresence>
    </header>
  );
}
