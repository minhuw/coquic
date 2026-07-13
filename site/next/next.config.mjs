import createMDX from '@next/mdx';

const withMDX = createMDX({
  extension: /\.mdx$/,
  options: {
    remarkPlugins: ['remark-gfm'],
  },
});

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  pageExtensions: ['ts', 'tsx', 'js', 'jsx', 'mdx'],
  trailingSlash: false,
  async headers() {
    return [
      {
        source: '/steward/data/:path*',
        headers: [
          { key: 'Cache-Control', value: 'no-store' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
        ],
      },
    ];
  },
};

export default withMDX(nextConfig);
