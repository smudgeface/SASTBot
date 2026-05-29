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
    // Surface a startup Redis outage within 10s instead of hanging on the OS
    // TCP timeout. BullMQ's blocking reads still reconnect indefinitely after
    // the initial connection (maxRetriesPerRequest: null governs that).
    connectTimeout: 10_000,
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
