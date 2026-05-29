import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    globals: false,
    include: ["tests/**/*.test.ts"],
    reporters: "default",
    // Run each test file in its own child process rather than a worker thread.
    // Some tests exercise modules backed by native N-API addons (notably the
    // Prisma query engine, a Rust binary); tearing those down across vitest's
    // default worker-thread pool intermittently aborts the run with a
    // "thread caused non-unwinding panic" (seen flaking the CI test gate).
    // Process isolation tears the addon down with the process and avoids it.
    pool: "forks",
  },
});
