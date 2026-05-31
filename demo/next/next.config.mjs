import { PHASE_DEVELOPMENT_SERVER } from 'next/constants.js';

/** @type {import('next').NextConfig} */
const baseConfig = {
  trailingSlash: false,
};

const devProxyConfig = {
  experimental: {
    proxyTimeout: 120_000,
  },
};

const nextConfig = (phase) => {
  if (phase !== PHASE_DEVELOPMENT_SERVER) {
    return {
      ...baseConfig,
      output: 'export',
    };
  }

  return {
    ...baseConfig,
    ...devProxyConfig,
    async rewrites() {
      return [
        {
          source: '/rag-api/:path*',
          destination: 'http://127.0.0.1:8787/:path*',
        },
      ];
    },
  };
};

export default nextConfig;
