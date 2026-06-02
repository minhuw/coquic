import { DemoNav } from '@/components/demo-nav';
import { CoquicLogoIcon } from '@/components/icons';

export default function Home() {
  return (
    <main className="coquic-page flex min-h-screen flex-col">
      <meta name="coquic-demo-marker" content="coquic-wasm-demo-v1" />
      <meta name="coquic-home-marker" content="coquic-demo-home-v1" />
      <DemoNav active="home" />

      <section className="grid flex-1 place-items-center content-center py-16 text-center sm:py-20 lg:py-24" aria-label="coquic slogan">
        <CoquicLogoIcon className="h-auto w-[clamp(72px,12vw,116px)] text-[var(--ink)]" />
        <h1 className="mx-auto mt-5 w-full max-w-[920px] text-[44px] font-normal leading-none text-[var(--ink)] sm:text-[64px] lg:text-[104px]">
          <span className="bg-[linear-gradient(110deg,var(--ink)_0%,var(--soft)_48%,var(--primary)_100%)] bg-clip-text text-transparent">Co</span>
          <span className="bg-[linear-gradient(110deg,#002d9c_0%,#0f62fe_48%,#78a9ff_100%)] bg-clip-text text-transparent">QUIC</span>
          <span className="bg-[linear-gradient(90deg,var(--ink)_0%,var(--soft)_58%,var(--primary)_100%)] bg-clip-text text-transparent">
            , from Prompt to Packet.
          </span>
        </h1>
      </section>

      <footer className="text-center font-mono text-xs font-medium text-[var(--muted)]">Hosted by CoQUIC</footer>
    </main>
  );
}
