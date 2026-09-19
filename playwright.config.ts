import { defineConfig } from '@playwright/test'

/**
 * Page-level smoke tests against the built site (dist/). `npm run build`
 * first; `vite preview` then serves the static output — no Worker, so the
 * share API and the links directory are out of scope here (unit tests cover
 * the core; these prove the pages wire it up).
 */
export default defineConfig({
  testDir: 'e2e',
  timeout: 30_000,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: 'http://localhost:4173',
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'npx vite preview --port 4173 --strictPort',
    url: 'http://localhost:4173/',
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
})
