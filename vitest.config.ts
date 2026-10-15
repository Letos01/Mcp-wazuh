import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    exclude: ["tests/e2e/**"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/index.ts"],
      thresholds: {
        "src/security/**": { statements: 80, branches: 75, functions: 80, lines: 80 },
        "src/tools/**": { statements: 80, branches: 70, functions: 80, lines: 80 },
      },
    },
  },
});
