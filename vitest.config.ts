import {defineConfig} from 'vitest/config';

export default defineConfig({
  test: {
    include: ['packages/*/test/**/*.test.ts'],
    // BBS and RDF canonicalization in pure JS take 100-200 ms per operation.
    testTimeout: 60_000
  }
});
