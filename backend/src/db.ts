import { PrismaClient } from "@prisma/client";

/**
 * Singleton Prisma client. Import this instead of `new PrismaClient()` so tests
 * and services share the same pool and graceful shutdown hook.
 */
export const prisma = new PrismaClient({
  log: ["warn", "error"],
});

let shutdownRegistered = false;

export function registerPrismaShutdown(): void {
  if (shutdownRegistered) return;
  shutdownRegistered = true;
  const shutdown = async (): Promise<void> => {
    try {
      await prisma.$disconnect();
    } catch {
      // best-effort shutdown
    }
  };
  process.once("beforeExit", shutdown);
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}
