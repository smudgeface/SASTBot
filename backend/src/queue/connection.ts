import { Redis } from "ioredis";

import { loadConfig } from "../config.js";

let client: Redis | null = null;

/**
 * Shared ioredis connection for BullMQ. BullMQ requires
 * `maxRetriesPerRequest: null` so that its blocking reads don't time out.
 */
export function getRedis(): Redis {
  if (client) return client;
  const redis = new Redis(loadConfig().redisUrl, {
    maxRetriesPerRequest: null,
  });
  client = redis;
  return redis;
}

export async function closeRedis(): Promise<void> {
  if (!client) return;
  try {
    await client.quit();
  } catch {
    // best-effort
  }
  client = null;
}
