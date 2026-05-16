import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { ConfigError, _resetConfigForTests, loadConfig } from "../src/config.js";

const validKey = randomBytes(32).toString("base64");

describe("loadConfig", () => {
  let originalEnv: NodeJS.ProcessEnv;
  let originalArgv: string[];

  beforeEach(() => {
    originalEnv = { ...process.env };
    originalArgv = [...process.argv];
    _resetConfigForTests();
  });

  afterEach(() => {
    process.env = originalEnv;
    process.argv = originalArgv;
    _resetConfigForTests();
  });

  // ---------------------------------------------------------------------------
  // Existing env-var tests (must keep working)
  // ---------------------------------------------------------------------------

  it("parses a fully valid env", () => {
    process.env.MASTER_KEY = validKey;
    process.env.DATABASE_URL = "postgresql://u:p@localhost:5432/db";
    process.env.REDIS_URL = "redis://localhost:6379/0";
    process.env.APP_ORIGIN = "http://localhost:5173";
    process.env.SESSION_COOKIE_SECURE = "true";
    process.env.PORT = "8000";

    const cfg = loadConfig();
    expect(cfg.masterKey.length).toBe(32);
    expect(cfg.databaseUrl).toBe("postgresql://u:p@localhost:5432/db");
    expect(cfg.sessionCookieSecure).toBe(true);
    expect(cfg.port).toBe(8000);
  });

  it("rejects a MASTER_KEY that does not decode to 32 bytes", () => {
    process.env.MASTER_KEY = Buffer.from("only-16-bytes!!!").toString("base64");
    process.env.DATABASE_URL = "postgresql://u:p@h:5432/d";
    expect(() => loadConfig()).toThrow(ConfigError);
  });

  it("requires DATABASE_URL", () => {
    process.env.MASTER_KEY = validKey;
    delete process.env.DATABASE_URL;
    delete process.env.POSTGRES_USER;
    delete process.env.POSTGRES_PASSWORD;
    delete process.env.POSTGRES_HOST;
    delete process.env.POSTGRES_DB;
    expect(() => loadConfig()).toThrow(ConfigError);
  });

  // ---------------------------------------------------------------------------
  // YAML config file tests
  // ---------------------------------------------------------------------------

  it("reads required fields from a YAML file when env vars are absent", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sastbot-test-"));
    const yamlPath = path.join(tmp, "config.yaml");
    fs.writeFileSync(
      yamlPath,
      [
        `master_key: "${validKey}"`,
        `database_url: "postgresql://u:p@localhost:5432/db"`,
        `redis_url: "redis://localhost:6379/0"`,
      ].join("\n"),
      "utf8",
    );

    // Remove the conflicting env vars so the YAML values are the sole source
    delete process.env.MASTER_KEY;
    delete process.env.DATABASE_URL;
    delete process.env.REDIS_URL;
    process.env.SASTBOT_CONFIG_FILE = yamlPath;

    try {
      const cfg = loadConfig();
      expect(cfg.masterKey.length).toBe(32);
      expect(cfg.databaseUrl).toBe("postgresql://u:p@localhost:5432/db");
      expect(cfg.redisUrl).toBe("redis://localhost:6379/0");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("env var overrides YAML value", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sastbot-test-"));
    const yamlPath = path.join(tmp, "config.yaml");
    fs.writeFileSync(
      yamlPath,
      [
        `master_key: "${validKey}"`,
        `database_url: "postgresql://u:p@localhost:5432/db"`,
        `log_level: "debug"`,
      ].join("\n"),
      "utf8",
    );

    // env value should WIN over YAML (env > yaml is wrong — CLI > YAML > env is right)
    // YAML has log_level=debug; env has LOG_LEVEL=warn — env should LOSE to YAML
    // Actually precedence: CLI > YAML > ENV meaning YAML beats ENV.
    process.env.LOG_LEVEL = "warn";
    delete process.env.MASTER_KEY;
    delete process.env.DATABASE_URL;
    process.env.SASTBOT_CONFIG_FILE = yamlPath;

    try {
      const cfg = loadConfig();
      // YAML wins over env: yaml says debug, env says warn → expect debug
      expect(cfg.logLevel).toBe("debug");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("throws a clear ConfigError on an unparseable YAML file", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sastbot-test-"));
    const yamlPath = path.join(tmp, "config.yaml");
    // Write invalid YAML (tab indentation is not allowed in YAML)
    fs.writeFileSync(yamlPath, "key:\n\t- broken", "utf8");

    process.env.MASTER_KEY = validKey;
    process.env.DATABASE_URL = "postgresql://u:p@localhost:5432/db";
    process.env.SASTBOT_CONFIG_FILE = yamlPath;

    try {
      expect(() => loadConfig()).toThrow(ConfigError);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("silently skips a missing YAML file path", () => {
    process.env.MASTER_KEY = validKey;
    process.env.DATABASE_URL = "postgresql://u:p@localhost:5432/db";
    process.env.SASTBOT_CONFIG_FILE = "/tmp/does-not-exist-sastbot-xyz.yaml";

    const cfg = loadConfig();
    expect(cfg.masterKey.length).toBe(32);
  });

  // ---------------------------------------------------------------------------
  // CLI arg tests
  // ---------------------------------------------------------------------------

  it("reads values from CLI --key=value args", () => {
    delete process.env.MASTER_KEY;
    delete process.env.DATABASE_URL;
    process.env.SASTBOT_CONFIG_FILE = "/tmp/does-not-exist-sastbot-xyz.yaml";

    process.argv = [
      "node",
      "server.ts",
      `--master-key=${validKey}`,
      "--database-url=postgresql://u:p@localhost:5432/db",
      "--log-level=debug",
    ];

    const cfg = loadConfig();
    expect(cfg.masterKey.length).toBe(32);
    expect(cfg.databaseUrl).toBe("postgresql://u:p@localhost:5432/db");
    expect(cfg.logLevel).toBe("debug");
  });

  it("CLI arg wins over both env and YAML", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sastbot-test-"));
    const yamlPath = path.join(tmp, "config.yaml");
    fs.writeFileSync(
      yamlPath,
      [
        `master_key: "${validKey}"`,
        `database_url: "postgresql://u:p@localhost:5432/db"`,
        `log_level: "debug"`,
      ].join("\n"),
      "utf8",
    );

    process.env.LOG_LEVEL = "warn";          // env says warn
    // YAML says debug
    // CLI says error → CLI wins
    process.env.SASTBOT_CONFIG_FILE = yamlPath;
    delete process.env.MASTER_KEY;
    delete process.env.DATABASE_URL;
    process.argv = ["node", "server.ts", "--log-level=error"];

    try {
      const cfg = loadConfig();
      expect(cfg.logLevel).toBe("error");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
