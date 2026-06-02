import type { SVGProps } from 'react';

export function CoquicLogoIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 512 512" role="img" aria-label="CoQUIC" focusable="false" {...props}>
      <defs>
        <mask id="coquic-logo-cutouts" maskUnits="userSpaceOnUse">
          <rect width="512" height="512" fill="#fff" />
          <circle cx="256" cy="253" r="96" fill="#000" />
          <rect x="82" y="245" width="352" height="20" fill="#000" />
          <rect x="-59" y="296" width="89" height="128" rx="15" transform="skewX(45)" fill="#000" />
        </mask>
      </defs>
      <circle cx="256" cy="253" r="171" fill="currentColor" mask="url(#coquic-logo-cutouts)" />
      <rect fill="#0F62FE" x="-47" y="307" width="65" height="101" rx="9" transform="skewX(45)" />
    </svg>
  );
}

export function GitHubIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false" {...props}>
      <path
        fill="currentColor"
        d="M12 .5C5.73.5.96 5.27.96 11.54c0 4.88 3.17 9.01 7.57 10.46.55.1.75-.24.75-.53v-1.87c-3.08.67-3.73-1.33-3.73-1.33-.5-1.28-1.23-1.62-1.23-1.62-1.01-.69.08-.68.08-.68 1.11.08 1.7 1.14 1.7 1.14.99 1.69 2.59 1.2 3.22.92.1-.72.39-1.2.7-1.48-2.46-.28-5.04-1.23-5.04-5.48 0-1.21.43-2.2 1.14-2.98-.11-.28-.49-1.41.11-2.94 0 0 .93-.3 3.04 1.14.88-.24 1.83-.37 2.77-.37s1.89.13 2.77.37c2.11-1.44 3.04-1.14 3.04-1.14.6 1.53.22 2.66.11 2.94.71.78 1.14 1.77 1.14 2.98 0 4.26-2.59 5.19-5.05 5.47.4.34.75 1.01.75 2.04v3.02c0 .29.2.64.76.53 4.39-1.45 7.56-5.58 7.56-10.46C23.04 5.27 18.27.5 12 .5Z"
      />
    </svg>
  );
}

export function HomepageIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false" {...props}>
      <path
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="2"
        d="M10 13a5 5 0 0 0 7.07 0l2.12-2.12a5 5 0 0 0-7.07-7.07l-1.22 1.22"
      />
      <path
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="2"
        d="M14 11a5 5 0 0 0-7.07 0L4.81 13.12a5 5 0 0 0 7.07 7.07l1.22-1.22"
      />
    </svg>
  );
}
