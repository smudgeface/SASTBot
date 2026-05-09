import { randomBytes } from "node:crypto";

import { beforeAll, describe, expect, it } from "vitest";

// osvService → config → loadConfig() requires MASTER_KEY + DATABASE_URL at
// import time. Set them before the dynamic import below.
beforeAll(() => {
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
});

describe("purlWithoutVersion", () => {
  it("strips @version from a simple versioned purl", async () => {
    const { purlWithoutVersion } = await import("../src/services/osvService.js");
    expect(purlWithoutVersion("pkg:nuget/System.Net.Http@4.3.4")).toBe(
      "pkg:nuget/System.Net.Http",
    );
  });

  it("returns a bare purl unchanged", async () => {
    const { purlWithoutVersion } = await import("../src/services/osvService.js");
    expect(purlWithoutVersion("pkg:nuget/System.Net.Http")).toBe(
      "pkg:nuget/System.Net.Http",
    );
  });

  it("strips version while preserving qualifiers", async () => {
    const { purlWithoutVersion } = await import("../src/services/osvService.js");
    expect(
      purlWithoutVersion("pkg:maven/org.apache.commons/commons-lang3@3.12.0?type=jar"),
    ).toBe("pkg:maven/org.apache.commons/commons-lang3?type=jar");
  });

  it("strips version while preserving subpath", async () => {
    const { purlWithoutVersion } = await import("../src/services/osvService.js");
    expect(purlWithoutVersion("pkg:generic/foo@1.2.3#path/to/file")).toBe(
      "pkg:generic/foo#path/to/file",
    );
  });

  it("handles scoped npm packages (percent-encoded @ in name)", async () => {
    // The literal `@` between name and version is the version separator; the
    // scope-prefix `@types` is encoded as `%40types`, so lastIndexOf('@') is safe.
    const { purlWithoutVersion } = await import("../src/services/osvService.js");
    expect(purlWithoutVersion("pkg:npm/%40types/node@20.12.7")).toBe(
      "pkg:npm/%40types/node",
    );
  });
});

describe("buildOsvQueryBody", () => {
  it("includes version + bare purl when version is provided and purl is bare", async () => {
    const { buildOsvQueryBody } = await import("../src/services/osvService.js");
    expect(buildOsvQueryBody("pkg:nuget/System.Net.Http", "4.3.4")).toEqual({
      version: "4.3.4",
      package: { purl: "pkg:nuget/System.Net.Http" },
    });
  });

  it("strips @version from a versioned purl when version is also provided (OSV rejects both)", async () => {
    const { buildOsvQueryBody } = await import("../src/services/osvService.js");
    expect(buildOsvQueryBody("pkg:npm/lodash@4.17.10", "4.17.10")).toEqual({
      version: "4.17.10",
      package: { purl: "pkg:npm/lodash" },
    });
  });

  it("omits version field when no version is known (rare fallback)", async () => {
    const { buildOsvQueryBody } = await import("../src/services/osvService.js");
    expect(buildOsvQueryBody("pkg:nuget/SomePkg", null)).toEqual({
      package: { purl: "pkg:nuget/SomePkg" },
    });
  });
});
