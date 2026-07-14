import Link from 'next/link';
import { Mail } from 'lucide-react';

import { CoquicLogoIcon, GitHubIcon } from './icons';

const contactHref = 'https://www.minhuw.dev';
const githubHref = 'https://github.com/minhuw/coquic';
const licenseHref = `${githubHref}/blob/main/LICENSE`;

export function ProjectFooter() {
  return (
    <footer className="project-footer">
      <div className="project-footer-inner">
        <Link className="project-footer-brand" href="/" aria-label="CoQUIC home">
          <CoquicLogoIcon aria-hidden="true" />
          <span>CoQUIC</span>
        </Link>
        <p>Open-source QUIC implementation from prompt to packet.</p>
        <nav className="project-footer-links" aria-label="Project links">
          <a href={githubHref} target="_blank" rel="noopener noreferrer">
            <GitHubIcon />
            <span>GitHub</span>
          </a>
          <a href={contactHref} target="_blank" rel="noopener noreferrer">
            <Mail aria-hidden="true" />
            <span>Contact</span>
          </a>
          <a href={licenseHref} target="_blank" rel="noopener noreferrer">
            <span>License</span>
          </a>
        </nav>
      </div>
    </footer>
  );
}
