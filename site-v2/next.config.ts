import path from 'node:path';
import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  output: 'standalone',
  allowedDevOrigins: ['127.0.0.1', '100.78.225.3'],
  turbopack: {
    root: path.resolve(__dirname, '..'),
  },
};

export default nextConfig;
