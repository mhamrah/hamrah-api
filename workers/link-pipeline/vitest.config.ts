import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: true,
    environment: 'miniflare',
    environmentOptions: {
      bindings: {
        DB: 'TEST_DB',
        AI: 'TEST_AI',
        LINK_PIPELINE: 'TEST_WORKFLOW'
      },
      compatibilityDate: '2025-07-18',
      compatibilityFlags: ['nodejs_compat']
    },
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/**',
        'dist/**',
        '**/*.d.ts',
        'vitest.config.ts'
      ]
    }
  }
})
