/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      {
        source: '/v1/:path*',
        destination: process.env.NEBULA_INTERNAL_API_PROXY ?? 'http://127.0.0.1:8080/v1/:path*'
      }
    ];
  }
};

module.exports = nextConfig;
