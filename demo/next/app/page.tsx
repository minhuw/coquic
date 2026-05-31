import Link from 'next/link';

const views = [
  { href: '/workbench', label: 'Workbench' },
  { href: '/performance', label: 'Performance' },
  { href: '/interop', label: 'Interop' },
  { href: '/coverage', label: 'Coverage' },
];

export default function Home() {
  return (
    <main className="home-page">
      <meta name="coquic-demo-marker" content="coquic-wasm-demo-v1" />
      <meta name="coquic-home-marker" content="coquic-demo-home-v1" />
      <nav className="top-nav" aria-label="Demo views">
        <Link className="top-nav-home" href="/" aria-label="Home" aria-current="page">
          <img src="/coquic-logo.svg" alt="" aria-hidden="true" />
        </Link>
        <span className="top-nav-links">
          {views.map((view) => (
            <Link key={view.href} href={view.href}>
              {view.label}
            </Link>
          ))}
          <a
            className="repo-link"
            href="https://github.com/minhuw/coquic"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="CoQUIC on GitHub"
          >
            <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
              <path d="M12 .5C5.73.5.96 5.27.96 11.54c0 4.88 3.17 9.01 7.57 10.46.55.1.75-.24.75-.53v-1.87c-3.08.67-3.73-1.33-3.73-1.33-.5-1.28-1.23-1.62-1.23-1.62-1.01-.69.08-.68.08-.68 1.11.08 1.7 1.14 1.7 1.14.99 1.69 2.59 1.2 3.22.92.1-.72.39-1.2.7-1.48-2.46-.28-5.04-1.23-5.04-5.48 0-1.21.43-2.2 1.14-2.98-.11-.28-.49-1.41.11-2.94 0 0 .93-.3 3.04 1.14.88-.24 1.83-.37 2.77-.37s1.89.13 2.77.37c2.11-1.44 3.04-1.14 3.04-1.14.6 1.53.22 2.66.11 2.94.71.78 1.14 1.77 1.14 2.98 0 4.26-2.59 5.19-5.05 5.47.4.34.75 1.01.75 2.04v3.02c0 .29.2.64.76.53 4.39-1.45 7.56-5.58 7.56-10.46C23.04 5.27 18.27.5 12 .5Z" />
            </svg>
          </a>
        </span>
      </nav>

      <section className="slogan-hero" aria-label="coquic slogan">
        <img className="slogan-logo" src="/coquic-logo.svg" alt="CoQUIC logo" />
        <h1>
          <span className="codex-word">Co</span>
          <span className="quic-word">QUIC</span>
          <span className="slogan-rest">, from Prompt to Packet.</span>
        </h1>
        <div className="home-actions" aria-label="Feature links">
          {views.map((view) => (
            <Link key={view.href} className="home-action" href={view.href}>
              {view.label}
            </Link>
          ))}
        </div>
      </section>
    </main>
  );
}
