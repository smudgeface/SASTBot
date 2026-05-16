import "dotenv/config";

import * as fs from "node:fs";
import * as path from "node:path";
import { parseArgs } from "node:util";

import { parse as parseYaml } from "yaml";
import { z } from "zod";

/**
 * Layered runtime configuration.
 *
 * Sources are merged in this precedence order (highest wins per-key):
 *   1. Environment variables  — SCREAMING_SNAKE_CASE  (e.g. MASTER_KEY)
 *   2. YAML config file       — snake_case keys       (e.g. master_key)
 *   3. CLI arguments          — kebab-case flags      (e.g. --master-key=...)
 *
 * All three forms normalise to SCREAMING_SNAKE_CASE before the Zod schema runs,
 * so the schema is unchanged from the env-only era.
 *
 * YAML file resolution order (first found wins):
 *   1. Path given by SASTBOT_CONFIG_FILE env var (if set).
 *   2. /etc/sastbot/config.yaml
 *   3. backend/config.local.yaml  (relative to the repo root, dev convenience)
 *
 * A missing file is silently skipped. A present-but-unparseable file aborts boot.
 */

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Convert snake_case or kebab-case key → SCREAMING_SNAKE_CASE */
function toScreamingSnake(key: string): string {
  return key.replace(/-/g, "_").toUpperCase();
}

/**
 * Load the YAML config file, if any. Returns a flat record of
 * SCREAMING_SNAKE_CASE keys (values are always strings, matching env behaviour).
 */
function loadYamlConfig(configFilePath?: string): Record<string, string> {
  const candidates: string[] = [];

  if (configFilePath) {
    candidates.push(configFilePath);
  } else {
    candidates.push("/etc/sastbot/config.yaml");
    // Resolve relative to this file's location: backend/src/config.ts → backend/ → repo root
    const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");
    candidates.push(path.join(repoRoot, "backend", "config.local.yaml"));
  }

  for (const candidate of candidates) {
    if (!fs.existsSync(candidate)) {
      // Silent skip — missing file is fine
      continue;
    }

    let raw: string;
    try {
      raw = fs.readFileSync(candidate, "utf8");
    } catch (err) {
      throw new ConfigError(`Cannot read config file ${candidate}: ${String(err)}`);
    }

    let parsed: unknown;
    try {
      parsed = parseYaml(raw);
    } catch (err) {
      throw new ConfigError(`Cannot parse YAML config file ${candidate}: ${String(err)}`);
    }

    if (parsed === null || parsed === undefined) {
      // Empty file — treat as no config
      return {};
    }

    if (typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new ConfigError(
        `Config file ${candidate} must be a YAML mapping (got ${Array.isArray(parsed) ? "array" : typeof parsed})`,
      );
    }

    const result: Record<string, string> = {};
    for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
      const normalized = toScreamingSnake(k);
      result[normalized] = String(v ?? "");
    }
    return result;
  }

  return {};
}

/**
 * Parse CLI arguments in --key=value or --key value form.
 * Returns a flat record of SCREAMING_SNAKE_CASE keys.
 *
 * Only recognised flags are accepted; unknown flags are ignored.
 * We can't use parseArgs's `options` dict without knowing all keys in
 * advance, so we do a manual pass over argv instead.
 */
function loadCliArgs(): Record<string, string> {
  const result: Record<string, string> = {};
  const argv = process.argv.slice(2);

  // parseArgs with allowPositionals and no strict mode to harvest all --flags
  try {
    // Collect all --key=value and --key value pairs manually
    for (let i = 0; i < argv.length; i++) {
      const arg = argv[i];
      if (!arg) continue;

      if (arg.startsWith("--")) {
        const eqIdx = arg.indexOf("=");
        if (eqIdx !== -1) {
          const k = arg.slice(2, eqIdx);
          const v = arg.slice(eqIdx + 1);
          result[toScreamingSnake(k)] = v;
        } else {
          // --key value form: peek at next arg
          const k = arg.slice(2);
          const next = argv[i + 1];
          if (next !== undefined && !next.startsWith("--")) {
            result[toScreamingSnake(k)] = next;
            i++; // consume the value token
          }
          // If no value follows, skip (boolean flag — not relevant here)
        }
      }
    }
  } catch {
    // Ignore parse failures — CLI args are best-effort
  }

  return result;
}

// ---------------------------------------------------------------------------
// Zod schema (same as before — operates on SCREAMING_SNAKE_CASE keys)
// ---------------------------------------------------------------------------

const boolString = z
  .union([z.string(), z.boolean()])
  .transform((v) => {
    if (typeof v === "boolean") return v;
    return ["1", "true", "True", "TRUE", "yes", "on"].includes(v);
  });

const composeDatabaseUrl = (env: Record<string, string | undefined>): string | undefined => {
  const user = env["POSTGRES_USER"];
  const password = env["POSTGRES_PASSWORD"];
  const host = env["POSTGRES_HOST"];
  const port = env["POSTGRES_PORT"] ?? "5432";
  const db = env["POSTGRES_DB"];
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
  // DEV-ONLY convenience: when set, bootstrapIfEmpty uses this exact value
  // for the bootstrap admin password instead of a random base64url string.
  // Lets the operator restart with a wiped DB and still log in with the
  // same known credential. Production deployments must leave this UNSET so
  // the password is random per boot. See "Pre-launch closing tasks" in the
  // pending-features memory; this stanza is slated for removal at launch.
  BOOTSTRAP_ADMIN_PASSWORD: z.string().optional(),
  // pino requires lowercase level names ("info" not "INFO").
  LOG_LEVEL: z.string().default("info").transform((v) => v.toLowerCase()),
  PORT: z.coerce.number().int().positive().default(8000),
  // Directory where retained per-repo clones live. In compose this is a
  // named volume mounted into both the backend and worker services so
  // either can purge the cache.
  CLONE_CACHE_DIR: z.string().default("/app/clones"),
});

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type AppConfig = {
  masterKey: Buffer;
  databaseUrl: string;
  redisUrl: string;
  appOrigin: string;
  sessionCookieSecure: boolean;
  bootstrapAdminEmail: string;
  bootstrapAdminPassword: string | undefined;
  logLevel: string;
  port: number;
  cloneCacheDir: string;
};

let cached: AppConfig | null = null;

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

// ---------------------------------------------------------------------------
// Main loader
// ---------------------------------------------------------------------------

export function loadConfig(): AppConfig {
  if (cached) return cached;

  // 1. Start with environment variables (already loaded by dotenv/config above)
  const merged: Record<string, string | undefined> = { ...process.env };

  // 2. Layer YAML config on top (YAML wins over env for keys it provides)
  //    Note: precedence is lowest→highest, so we apply YAML first, then env,
  //    then CLI. But it's easier to build lowest-first and let higher-priority
  //    sources override, so: start with env, merge YAML over it, merge CLI over both.
  //    Actually the rule is: CLI > YAML > ENV, meaning CLI is highest priority.
  //    We build: base = env, then yaml overrides env, then CLI overrides yaml+env.
  //    Re-reading: "lowest → highest: env < yaml < cli" means CLI wins overall.
  //    So: merge order = first apply env, then overlay yaml, then overlay cli.

  // Load YAML — may throw ConfigError on parse failure
  const yamlConfig = loadYamlConfig(process.env["SASTBOT_CONFIG_FILE"]);

  // Load CLI args
  const cliConfig = loadCliArgs();

  // Merge: env < yaml < cli (later entries win)
  const raw: Record<string, string | undefined> = {
    ...merged,      // env (lowest priority)
    ...yamlConfig,  // yaml (overrides env)
    ...cliConfig,   // cli (highest priority)
  };

  // Compose DATABASE_URL from POSTGRES_* parts if not already present
  if (!raw["DATABASE_URL"]) {
    const composed = composeDatabaseUrl(raw);
    if (composed) raw["DATABASE_URL"] = composed;
  }

  const parsed = EnvSchema.safeParse(raw);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `  - ${i.path.join(".")}: ${i.message}`)
      .join("\n");
    throw new ConfigError(`Invalid configuration:\n${issues}\n\nSources checked: env vars, YAML file, CLI args.`);
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
    bootstrapAdminPassword: parsed.data.BOOTSTRAP_ADMIN_PASSWORD,
    logLevel: parsed.data.LOG_LEVEL,
    port: parsed.data.PORT,
    cloneCacheDir: parsed.data.CLONE_CACHE_DIR,
  };
  return cached;
}

/** Testing helper — clears the cached config so a re-read picks up env changes. */
export function _resetConfigForTests(): void {
  cached = null;
}
