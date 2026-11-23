/** @type {import("next").NextConfig} */
// The app is served under /sentinelops (https://<domain>/sentinelops) both locally and on the server,
// so URLs are identical everywhere. Override with NEXT_PUBLIC_BASE_PATH if ever needed.
const nextConfig = {
  reactStrictMode: true,
  basePath: process.env.NEXT_PUBLIC_BASE_PATH ?? "/sentinelops",
};
module.exports = nextConfig;
