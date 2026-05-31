import Image from 'next/image';
import Link from 'next/link';

import { DemoNav, demoViews } from '@/components/demo-nav';

export default function Home() {
  return (
    <main className="coquic-page flex min-h-screen flex-col">
      <meta name="coquic-demo-marker" content="coquic-wasm-demo-v1" />
      <meta name="coquic-home-marker" content="coquic-demo-home-v1" />
      <DemoNav active="home" />

      <section className="grid flex-1 place-items-center content-center py-16 text-center sm:py-20 lg:py-24" aria-label="coquic slogan">
        <Image className="h-auto w-[clamp(72px,12vw,116px)]" src="/coquic-logo.svg" width={116} height={116} alt="CoQUIC logo" priority />
        <h1 className="mx-auto mt-5 w-full max-w-[920px] text-[44px] font-normal leading-none text-[var(--ink)] sm:text-[64px] lg:text-[104px]">
          <span className="bg-[linear-gradient(110deg,#161616_0%,#393939_48%,#0f62fe_100%)] bg-clip-text text-transparent">Co</span>
          <span className="bg-[linear-gradient(110deg,#002d9c_0%,#0f62fe_48%,#78a9ff_100%)] bg-clip-text text-transparent">QUIC</span>
          <span className="bg-[linear-gradient(90deg,var(--ink)_0%,#393939_58%,var(--primary)_100%)] bg-clip-text text-transparent">
            , from Prompt to Packet.
          </span>
        </h1>
        <div className="mt-8 flex w-full max-w-[660px] flex-wrap items-center justify-center gap-2.5 sm:mt-9" aria-label="Feature links">
          {demoViews.slice(0, 3).map((view) => (
            <Link
              key={view.href}
              className="inline-flex min-h-11 min-w-[148px] items-center justify-center rounded-[var(--radius)] border border-[var(--line-strong)] bg-[var(--surface)] px-5 text-sm font-semibold text-[var(--ink)] no-underline transition-colors duration-200 hover:border-[var(--primary)] hover:bg-[var(--primary)] hover:text-white focus-visible:border-[var(--primary)] focus-visible:bg-[var(--primary)] focus-visible:text-white max-sm:w-full"
              href={view.href}
            >
              {view.label}
            </Link>
          ))}
        </div>
      </section>

      <footer className="text-center font-mono text-xs font-medium text-[var(--muted)]">Hosted by CoQUIC</footer>
    </main>
  );
}
