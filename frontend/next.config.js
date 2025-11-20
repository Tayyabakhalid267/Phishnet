/** @type {import('next').NextConfig} */
const nextConfig = {
  images: {
    domains: ['ui-avatars.com', 'images.unsplash.com'],
  },
  env: {
    CUSTOM_KEY: 'phishnet-ai',
  },
  webpack: (config) => {
    // Handle Three.js files
    config.externals = config.externals || [];
    config.externals.push({
      canvas: 'canvas',
    });
    return config;
  },
}

module.exports = nextConfig