import { Queue } from "bullmq";

import { getRedis } from "./connection.js";

export const SCAN_QUEUE_NAME = "scans";

export interface ScanJobData {
  scanRunId: string;
  scopeId: string;
  /** Relative path within the repo clone to scan. "/" means root. */
  scopePath: string;
}

let queue: Queue<ScanJobData> | null = null;

export function getScanQueue(): Queue<ScanJobData> {
  if (!queue) {
    queue = new Queue<ScanJobData>(SCAN_QUEUE_NAME, { connection: getRedis() });
  }
  return queue;
}

export async function closeScanQueue(): Promise<void> {
  if (!queue) return;
  await queue.close();
  queue = null;
}
