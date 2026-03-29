/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',   // generates frontend/out/ for FastAPI to serve
  trailingSlash: true, // /dashboard → /dashboard/index.html
};

module.exports = nextConfig;
