import nextConfig from 'eslint-config-next/core-web-vitals';
import typescriptConfig from 'eslint-config-next/typescript';

const config = [
  ...nextConfig,
  ...typescriptConfig,
  {
    name: 'coquic/ignores',
    ignores: [
      '.next/**',
      'out/**',
      'build/**',
      'coverage/**',
      'src/generated/**',
    ],
  },
  {
    name: 'coquic/unused-convention',
    files: ['**/*.{ts,tsx,mts,cts}'],
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          args: 'all',
          argsIgnorePattern: '^_',
          caughtErrors: 'all',
          caughtErrorsIgnorePattern: '^_',
          destructuredArrayIgnorePattern: '^_',
          varsIgnorePattern: '^_',
        },
      ],
    },
  },
  {
    name: 'coquic/effect-synchronization',
    files: [
      'app/transcript/transcript-dataset.tsx',
      'src/components/duvet-report-frame.tsx',
      'src/components/site-search-dialog.tsx',
      'src/components/steward/dashboard.tsx',
      'src/components/steward/data.ts',
      'src/components/steward/task-detail.tsx',
      'src/components/theme-toggle.tsx',
    ],
    rules: {
      // These existing data-fetching hooks synchronize state as inputs change.
      'react-hooks/set-state-in-effect': 'off',
    },
  },
  {
    name: 'coquic/existing-dependencies',
    files: ['app/transcript/transcript-dataset.tsx'],
    rules: {
      // The search effect intentionally captures its stable URL replacement helper.
      'react-hooks/exhaustive-deps': 'off',
    },
  },
  {
    name: 'coquic/render-derived-values',
    files: [
      'src/components/docs/markdown.tsx',
      'src/components/steward/dashboard.tsx',
      'src/components/steward/shared.tsx',
    ],
    rules: {
      // These values are intentionally derived from parsed content or an external clock.
      'react-hooks/immutability': 'off',
      'react-hooks/purity': 'off',
    },
  },
  {
    name: 'coquic/dynamic-components',
    files: ['src/components/site-search-dialog.tsx'],
    rules: {
      // Lucide icons are selected by data and intentionally rendered dynamically.
      'react-hooks/static-components': 'off',
    },
  },
  {
    name: 'coquic/mdx-components',
    files: ['src/components/blog/blog-post-content.tsx'],
    rules: {
      // useMDXComponents is a server-side resolver, not a React hook.
      'react-hooks/rules-of-hooks': 'off',
    },
  },
  {
    name: 'coquic/external-image',
    files: ['app/qa/qa-client.tsx'],
    rules: {
      // The QA transcript receives an external image URL that cannot use next/image.
      '@next/next/no-img-element': 'off',
    },
  },
];

export default config;
