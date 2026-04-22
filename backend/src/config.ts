import "dotenv/config";

import { z } from "zod";

/**
 * Environment schema. Parsed once on boot; `loadConfig()` throws with a clear
 * message on missing/invalid vars. The backend refuses to start if MASTER_KEY
 * is missing or does not decode to exactly 32 bytes.
 */

const boolString = z
  .union([z.string(), z.boolean()])
  .transform((v) => {
    if (typeof v === "boolean") return v;
    return ["1", "true", "True", "TRUE", "yes", "on"].includes(v);
  });

const composeDatabaseUrl = (env: NodeJS.ProcessEnv): string | undefined => {
  const user = env.POSTGRES_USER;
  const password = env.POSTGRES_PASSWORD;
  const host = env.POSTGRES_HOST;
  const port = env.POSTGRES_PORT ?? "5432";
  const db = env.POSTGRES_DB;
  if (user && password && host && db) {
    return `postgresql://${user}:${password}@${host}:${port}/${db}`;
  }
  return undefined;
};

const EnvSchema = z.object({
  MASTER_KEY: z
    .string({ required_error: "MASTER_KEY is required (base64 of 32 bytes)" })
    .min(1, "MASTER_KEY must not be empty"),
  DATABASE_URL: z.string().min(1, "DATABASE_URL is required"),
  REDIS_URL: z.string().default("redis://redis:6379/0"),
  APP_ORIGIN: z.string().default("http://localhost:5173"),
  SESSION_COOKIE_SECURE: boolString.default(false),
  BOOTSTRAP_ADMIN_EMAIL: z.string().default("admin@sastbot.local"),
  // pino requires lowercase level names ("info" not "INFO").
  LOG_LEVEL: z.string().default("info").transform((v) => v.toLowerCase()),
  PORT: z.coerce.number().int().positive().default(8000),
});

export type AppConfig = {
  masterKey: Buffer;
  databaseUrl: string;
  redisUrl: string;
  appOrigin: string;
  sessionCookieSecure: boolean;
  bootstrapAdminEmail: string;
  logLevel: string;
  port: number;
};

let cached: AppConfig | null = null;

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

export function loadConfig(): AppConfig {
  if (cached) return cached;

  const env = { ...process.env };
  if (!env.DATABASE_URL) {
    const composed = composeDatabaseUrl(env);
    if (composed) env.DATABASE_URL = composed;
  }

  const parsed = EnvSchema.safeParse(env);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `  - ${i.path.join(".")}: ${i.message}`)
      .join("\n");
    throw new ConfigError(`Invalid environment configuration:\n${issues}`);
  }

  let masterKey: Buffer;
  try {
    masterKey = Buffer.from(parsed.data.MASTER_KEY, "base64");
  } catch {
    throw new ConfigError("MASTER_KEY must be valid base64");
  }
  if (masterKey.length !== 32) {
    throw new ConfigError(
      `MASTER_KEY must decode to exactly 32 bytes (got ${masterKey.length})`,
    );
  }

  cached = {
    masterKey,
    databaseUrl: parsed.data.DATABASE_URL,
    redisUrl: parsed.data.REDIS_URL,
    appOrigin: parsed.data.APP_ORIGIN,
    sessionCookieSecure: parsed.data.SESSION_COOKIE_SECURE,
    bootstrapAdminEmail: parsed.data.BOOTSTRAP_ADMIN_EMAIL,
    logLevel: parsed.data.LOG_LEVEL,
    port: parsed.data.PORT,
  };
  return cached;
}

/** Testing helper — clears the cached config so a re-read picks up env changes. */
export function _resetConfigForTests(): void {
  cached = null;
}
