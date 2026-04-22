import { randomBytes } from "node:crypto";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { ConfigError, _resetConfigForTests, loadConfig } from "../src/config.js";

const validKey = randomBytes(32).toString("base64");

describe("loadConfig", () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
    _resetConfigForTests();
  });

  afterEach(() => {
    process.env = originalEnv;
    _resetConfigForTests();
  });

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
});
