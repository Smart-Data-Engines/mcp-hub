import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: 'tests',
  timeout: 120_000,
  expect: { timeout: 15000 },
  workers: 1,
  use: {
    baseURL: process.env.MCP_HUB_UI_URL || 'http://localhost:8000',
    viewport: { width: 1440, height: 1000 },
    headless: true,
    actionTimeout: 15000,
    launchOptions: {
      executablePath:
        process.env.CHROME_EXECUTABLE || (process.env.CI ? undefined : '/opt/google/chrome/chrome'),
      args: ['--no-sandbox'],
    },
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
  reporter: [['list']],
});
