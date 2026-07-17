import styles from './artwork.module.css';

export type HomeArtworkVariant =
  | 'performance'
  | 'interop'
  | 'coverage'
  | 'duvet'
  | 'workbench'
  | 'api'
  | 'ask'
  | 'dataset';

type HomeArtworkRole = 'chart' | 'protocol' | 'status';

const artworkRoles: Record<HomeArtworkVariant, HomeArtworkRole> = {
  performance: 'chart',
  interop: 'protocol',
  coverage: 'status',
  duvet: 'status',
  workbench: 'protocol',
  api: 'protocol',
  ask: 'protocol',
  dataset: 'status',
};

export function HomeArtwork({ variant }: { variant: HomeArtworkVariant }) {
  return (
    <span className={styles.art} data-home-art={variant} data-home-art-role={artworkRoles[variant]} aria-hidden="true">
      <svg viewBox="0 0 160 160" focusable="false">
        <rect className={styles.surface} width="160" height="160" />
        <path className={styles.frame} d="M12 28V12h16M132 12h16v16M12 132v16h16M132 148h16v-16" />
        <ArtworkScene variant={variant} />
      </svg>
    </span>
  );
}

function ArtworkScene({ variant }: { variant: HomeArtworkVariant }) {
  switch (variant) {
    case 'performance':
      return (
        <>
          <path className={styles.grid} d="M26 34h112M26 62h112M26 90h112M26 118h112M50 26v108M78 26v108M106 26v108M134 26v108" />
          <path className={styles.muted} d="M32 124V106h16v18M58 124V88h16v36M84 124V98h16v26M110 124V66h16v58" />
          <polyline className={styles.accent} points="30,112 54,100 78,104 102,78 126,56 142,62" />
          <g className={styles.solid}>
            <circle cx="30" cy="112" r="3" /><circle cx="54" cy="100" r="3" /><circle cx="78" cy="104" r="3" />
            <circle cx="102" cy="78" r="3" /><circle cx="126" cy="56" r="3" />
          </g>
        </>
      );
    case 'interop':
      return (
        <>
          <path className={styles.grid} d="M80 80 80 28M80 80l44-28M80 80l44 28M80 80v52M80 80l-44 28M80 80 36 52" />
          <path className={styles.accent} d="M80 28v52l44-28M36 108l44-28 44 28M80 132V80" />
          <g className={styles.paper}>
            <rect x="69" y="20" width="22" height="16" /><rect x="116" y="44" width="22" height="16" />
            <rect x="116" y="100" width="22" height="16" /><rect x="69" y="124" width="22" height="16" />
            <rect x="22" y="100" width="22" height="16" /><rect x="22" y="44" width="22" height="16" />
          </g>
          <circle className={styles.fill} cx="80" cy="80" r="18" />
          <circle className={styles.solid} cx="80" cy="80" r="4" />
        </>
      );
    case 'coverage':
      return (
        <>
          <g className={styles.paper}>
            <rect x="24" y="24" width="24" height="24" /><rect x="56" y="24" width="24" height="24" />
            <rect x="88" y="24" width="24" height="24" /><rect x="120" y="24" width="16" height="24" />
            <rect x="24" y="56" width="24" height="24" /><rect x="56" y="56" width="24" height="24" />
            <rect x="88" y="56" width="24" height="24" /><rect x="120" y="56" width="16" height="24" />
            <rect x="24" y="88" width="24" height="24" /><rect x="56" y="88" width="24" height="24" />
            <rect x="88" y="88" width="24" height="24" /><rect x="120" y="88" width="16" height="24" />
            <rect x="24" y="120" width="24" height="16" /><rect x="56" y="120" width="24" height="16" />
            <rect x="88" y="120" width="24" height="16" /><rect x="120" y="120" width="16" height="16" />
          </g>
          <g className={styles.fill}>
            <rect x="24" y="24" width="24" height="24" /><rect x="56" y="24" width="24" height="24" />
            <rect x="120" y="24" width="16" height="24" /><rect x="24" y="56" width="24" height="24" />
            <rect x="88" y="56" width="24" height="24" /><rect x="120" y="56" width="16" height="24" />
            <rect x="24" y="88" width="24" height="24" /><rect x="56" y="88" width="24" height="24" />
            <rect x="88" y="88" width="24" height="24" /><rect x="56" y="120" width="24" height="16" />
            <rect x="88" y="120" width="24" height="16" /><rect x="120" y="120" width="16" height="16" />
          </g>
          <path className={styles.accent} d="m92 34 7 7 13-17M60 98l7 7 13-17" />
        </>
      );
    case 'duvet':
      return (
        <>
          <path className={styles.paper} d="M22 22h68l16 16v98H22zM90 22v16h16" />
          <path className={styles.muted} d="M38 50h48M38 64h54M38 78h42M38 92h50M38 106h34" />
          <path className={styles.grid} d="M78 64h32l14-18M84 86h28l12-2M72 108h38l14 18" />
          <g className={styles.fill}>
            <circle cx="110" cy="64" r="5" /><circle cx="112" cy="86" r="5" /><circle cx="110" cy="108" r="5" />
          </g>
          <g className={styles.paper}>
            <rect x="120" y="34" width="22" height="22" /><rect x="120" y="73" width="22" height="22" /><rect x="120" y="112" width="22" height="22" />
          </g>
          <path className={styles.accent} d="m125 45 5 5 9-12M125 84l5 5 9-12M125 123l5 5 9-12" />
        </>
      );
    case 'workbench':
      return (
        <>
          <circle className={styles.paper} cx="28" cy="80" r="13" />
          <circle className={styles.paper} cx="132" cy="80" r="13" />
          <path className={styles.grid} d="M42 44h76M42 80h76M42 116h76" />
          <path className={styles.muted} d="M40 80h16l10-20 12 40 14-58 14 76 12-38h4" />
          <path className={styles.accent} d="M42 44h30l12 12h34M42 116h30l12-12h34" />
          <g className={styles.fill}>
            <rect x="64" y="36" width="18" height="14" /><rect x="90" y="73" width="18" height="14" /><rect x="76" y="109" width="18" height="14" />
          </g>
          <circle className={styles.solid} cx="28" cy="80" r="4" />
          <circle className={styles.solid} cx="132" cy="80" r="4" />
        </>
      );
    case 'api':
      return (
        <>
          <path className={styles.muted} d="M48 24H30v38L18 80l12 18v38h18M112 24h18v38l12 18-12 18v38h-18" />
          <path className={styles.grid} d="M48 44h28M48 62h20M84 44h28M92 62h20M48 98h20M48 116h28M92 98h20M84 116h28" />
          <circle className={styles.paper} cx="80" cy="80" r="29" />
          <path className={styles.accent} d="M63 74a18 18 0 0 1 31-7l5 6M97 86a18 18 0 0 1-31 7l-5-6" />
          <path className={styles.accent} d="m97 63 2 10-10-2M63 97l-2-10 10 2" />
          <circle className={styles.fill} cx="80" cy="80" r="6" />
        </>
      );
    case 'ask':
      return (
        <>
          <path className={styles.paper} d="M20 24h96v48H58L40 88V72H20z" />
          <path className={styles.muted} d="M34 40h64M34 54h42" />
          <path className={styles.paper} d="M44 94h96v42H122v14l-18-14H44z" />
          <path className={styles.muted} d="M60 108h62M60 122h48" />
          <path className={styles.grid} d="M116 50h18v44M110 72h24M96 94l18-22" />
          <circle className={styles.fill} cx="134" cy="72" r="5" />
          <path className={styles.accent} d="M76 34c11 0 17 6 17 14 0 7-5 10-11 13v5M82 74h.1" />
        </>
      );
    case 'dataset':
      return (
        <>
          <g className={styles.paper}>
            <rect x="20" y="28" width="82" height="22" /><rect x="20" y="60" width="82" height="22" /><rect x="20" y="92" width="82" height="22" /><rect x="20" y="124" width="82" height="14" />
          </g>
          <path className={styles.muted} d="M32 39h56M32 71h42M32 103h58M32 131h46" />
          <path className={styles.paper} d="M112 36c0-7 7-12 15-12s15 5 15 12v88c0 7-7 12-15 12s-15-5-15-12z" />
          <path className={styles.muted} d="M112 36c0 7 7 12 15 12s15-5 15-12M112 80c0 7 7 12 15 12s15-5 15-12M112 124c0 7 7 12 15 12s15-5 15-12" />
          <path className={styles.accent} d="M102 39h10M102 71h10M102 103h10M102 131h10" />
          <g className={styles.solid}>
            <circle cx="108" cy="39" r="3" /><circle cx="108" cy="71" r="3" /><circle cx="108" cy="103" r="3" /><circle cx="108" cy="131" r="3" />
          </g>
        </>
      );
  }
}
