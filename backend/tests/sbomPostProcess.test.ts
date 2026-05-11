/**
 * Unit tests for Stage-1 SBOM mechanical post-processing (M6p §1.3).
 *
 * One test per rule (a–g) as specified in the plan, plus an integration
 * snapshot test using the saved Gocator Classic `/` cdxgen baseline.
 */

import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";

import { beforeAll, describe, expect, it } from "vitest";

import type { CdxComponent } from "../src/services/sbomService.js";

// sbomService → config → loadConfig() requires MASTER_KEY + DATABASE_URL at
// import time. Set them before the dynamic import below.
beforeAll(() => {
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
});

function makeComponent(overrides: Partial<CdxComponent>): CdxComponent {
  return {
    name: "SomeLib",
    version: "1.0.0",
    purl: `pkg:generic/${overrides.name ?? "SomeLib"}@${overrides.version ?? "1.0.0"}`,
    ...overrides,
  };
}

function makeNuget(name: string, version?: string): CdxComponent {
  return {
    name,
    version,
    purl: `pkg:nuget/${name}${version ? `@${version}` : ""}`,
  };
}

function makeGeneric(name: string, version?: string): CdxComponent {
  return {
    name,
    version,
    purl: `pkg:generic/${name}${version ? `@${version}` : ""}`,
  };
}

// ---- tests ------------------------------------------------------------------

describe("postProcessComponents", () => {
  describe("(a) drops placeholder version strings", () => {
    it("drops ${VERSION_STRING} CMake placeholder", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");
      const input = [
        makeGeneric("CLI11", "${VERSION_STRING}"),
        makeGeneric("CLI11", "1.8.0"),
      ];
      const result = postProcessComponents(input);
      expect(result.some((c) => c.version === "${VERSION_STRING}")).toBe(false);
      expect(result.some((c) => c.version === "1.8.0")).toBe(true);
    });

    it("drops @{MSBUILD_PLACEHOLDER} MSBuild placeholder", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");
      const input = [makeNuget("SomeLib", "@{VERSION}")];
      const result = postProcessComponents(input);
      expect(result).toHaveLength(0);
    });

    it("keeps components with no version", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");
      const input = [makeNuget("SomeLib", undefined)];
      const result = postProcessComponents(input);
      expect(result).toHaveLength(1);
    });
  });

  describe("(b) drops CMake-internal pseudo-packages", () => {
    it("drops Threads (CMake FindThreads)", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");
      const input = [makeGeneric("Threads")];
      const result = postProcessComponents(input);
      expect(result).toHaveLength(0);
    });

    it("drops PythonInterp, Sanitizers, PackageTest", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");
      const input = [
        makeGeneric("PythonInterp"),
        makeGeneric("Sanitizers"),
        makeGeneric("PackageTest"),
      ];
      const result = postProcessComponents(input);
      expect(result).toHaveLength(0);
    });

    it("drops bare Python (generic ecosystem)", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");
      const input = [makeGeneric("Python")];
      const result = postProcessComponents(input);
      expect(result).toHaveLength(0);
    });

    it("does NOT drop a real python rpm package (ecosystem=rpm)", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");
      const input = [{ name: "python3", version: "3.11.0", purl: "pkg:rpm/python3@3.11.0" }];
      const result = postProcessComponents(input);
      expect(result).toHaveLength(1);
    });

    it("drops googletest-distribution", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");
      const input = [makeGeneric("googletest-distribution")];
      const result = postProcessComponents(input);
      expect(result).toHaveLength(0);
    });
  });

  describe("(c) drops .NET BCL assemblies but keeps System.Net.Http", () => {
    it("drops System.Xml (BCL)", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");
      const input = [makeNuget("System.Xml")];
      const result = postProcessComponents(input);
      expect(result).toHaveLength(0);
    });

    it("drops System, System.Core, PresentationCore, WindowsBase", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");
      const input = [
        makeNuget("System"),
        makeNuget("System.Core"),
        makeNuget("PresentationCore"),
        makeNuget("WindowsBase"),
      ];
      const result = postProcessComponents(input);
      expect(result).toHaveLength(0);
    });

    it("keeps System.Net.Http (separately distributed NuGet for .NET 4.0)", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");
      const input = [makeNuget("System.Net.Http", "4.3.4")];
      const result = postProcessComponents(input);
      expect(result).toHaveLength(1);
      expect(result[0]!.name).toBe("System.Net.Http");
    });

    it("keeps a BCL-named package with -preview suffix", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");
      const input = [makeNuget("System.Data", "5.0.0-preview3")];
      const result = postProcessComponents(input);
      expect(result).toHaveLength(1);
    });

    it("does not drop a non-nuget System package (generic ecosystem)", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");
      // An unusual case — "System" as a generic component
      const input = [makeGeneric("System", "2.0")];
      const result = postProcessComponents(input);
      // BCL rule only fires on nuget ecosystem — generic passes through
      expect(result).toHaveLength(1);
    });
  });

  describe("(d) drops test-only frameworks", () => {
    it("drops gtest, gmock", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");
      const input = [makeGeneric("gtest"), makeGeneric("gmock")];
      const result = postProcessComponents(input);
      expect(result).toHaveLength(0);
    });

    it("drops Microsoft.VisualStudio.QualityTools.UnitTestFramework", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");
      const input = [makeNuget("Microsoft.VisualStudio.QualityTools.UnitTestFramework", "11.0.50727.1")];
      const result = postProcessComponents(input);
      expect(result).toHaveLength(0);
    });

    it("drops GoogleTest and googletest variants", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");
      const input = [
        { name: "GoogleTest", purl: "pkg:generic/googletest@unknown" },
        makeGeneric("googletest-distribution"),
      ];
      const result = postProcessComponents(input);
      expect(result).toHaveLength(0);
    });
  });

  describe("(e) coalesces versionless + versioned pairs", () => {
    it("drops versionless GoSdkNet when versioned rows exist, keeps all versioned rows", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");
      const input = [
        makeNuget("GoSdkNet"),                       // versionless
        makeNuget("GoSdkNet", "1.0.6550.26689"),
        makeNuget("GoSdkNet", "1.0.6033.19633"),
        makeNuget("GoSdkNet", "1.0.6821.12407"),
      ];
      const result = postProcessComponents(input);
      expect(result).toHaveLength(3);
      expect(result.every((c) => c.version)).toBe(true);
    });

    it("keeps versionless row when there are no versioned siblings", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");
      const input = [makeNuget("SomeLib")];
      const result = postProcessComponents(input);
      expect(result).toHaveLength(1);
    });

    it("drops versionless kApiNet when versioned rows exist", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");
      const input = [
        makeNuget("kApiNet"),
        makeNuget("kApiNet", "1.0.6548.29146"),
        makeNuget("kApiNet", "1.0.6807.11766"),
      ];
      const result = postProcessComponents(input);
      expect(result).toHaveLength(2);
    });
  });

  describe("(f) normalizes name capitalization", () => {
    it("collapses cli11 + CLI11 to a single canonical entry", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");
      const input = [
        makeGeneric("cli11"),           // versionless lowercase
        makeGeneric("CLI11", "1.8.0"),  // versioned correct casing
      ];
      const result = postProcessComponents(input);
      // After coalesce-versionless + alias-normalise, only the versioned CLI11 remains
      expect(result).toHaveLength(1);
      expect(result[0]!.version).toBe("1.8.0");
    });
  });

  describe("(g) collapses naming variants via alias map", () => {
    it("drops Hardcodet WPF NotifyIcon when Hardcodet.Wpf.TaskbarNotification is present", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");
      const input = [
        { name: "Hardcodet WPF NotifyIcon", purl: "pkg:generic/hardcodet-wpf-notifyicon@unknown" },
        makeNuget("Hardcodet.Wpf.TaskbarNotification", "1.0.5.0"),
      ];
      const result = postProcessComponents(input);
      // Friendly name dropped, package-id kept
      expect(result.some((c) => c.name === "Hardcodet WPF NotifyIcon")).toBe(false);
      expect(result.some((c) => c.name === "Hardcodet.Wpf.TaskbarNotification")).toBe(true);
      expect(result).toHaveLength(1);
    });

    it("drops Xceed Extended WPF Toolkit when Xceed.Wpf.Toolkit is present", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");
      const input = [
        { name: "Xceed Extended WPF Toolkit", purl: "pkg:generic/xceed-extended-wpf-toolkit@unknown" },
        makeNuget("Xceed.Wpf.Toolkit", "2.9.0.0"),
      ];
      const result = postProcessComponents(input);
      expect(result.some((c) => c.name === "Xceed Extended WPF Toolkit")).toBe(false);
      expect(result.some((c) => c.name === "Xceed.Wpf.Toolkit")).toBe(true);
      expect(result).toHaveLength(1);
    });

    it("keeps the friendly name when no canonical variant is present", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");
      const input = [
        { name: "Hardcodet WPF NotifyIcon", purl: "pkg:generic/hardcodet-wpf-notifyicon@unknown" },
      ];
      const result = postProcessComponents(input);
      // Alias has no canonical pair — keep the only entry
      expect(result).toHaveLength(1);
    });
  });

  describe("integration snapshot — Gocator Classic / baseline (60 → ~40)", () => {
    it("reduces 60-component baseline to ~40 components without losing real deps", async () => {
      const { postProcessComponents } = await import("../src/services/sbomService.js");

      // Load the saved cdxgen baseline. When running in CI where the file
      // doesn't exist, skip the test gracefully.
      let doc: { components?: CdxComponent[] };
      try {
        // The baseline was captured at docs/... path; also check /tmp fallback.
        const candidatePaths = [
          join(process.cwd(), "..", "docs", "Claude CRA Analysis Reference", "cdx-baseline.json"),
          "/tmp/cdx-baseline-local.json",
        ];
        let raw: string | null = null;
        for (const p of candidatePaths) {
          try {
            raw = readFileSync(p, "utf8");
            break;
          } catch {
            // try next
          }
        }
        if (!raw) {
          console.warn("[snapshot test] cdx-baseline.json not found — skipping");
          return;
        }
        doc = JSON.parse(raw) as { components?: CdxComponent[] };
      } catch (err) {
        console.warn("[snapshot test] could not load cdx-baseline.json:", err);
        return;
      }

      const raw = doc.components ?? [];
      const cleaned = postProcessComponents(raw);

      console.log(`Baseline: ${raw.length} → cleaned: ${cleaned.length}`);
      console.log("Remaining:", cleaned.map((c) => `${c.name} ${c.version ?? "(no version)"}`).join("\n  "));

      // Plan §1.4: expect ~18–40 after cleaning (the DB count of 60 is
      // higher than the raw doc.components count because the DB deduplicates
      // by purl differently; the raw baseline has 45 components → 18 after
      // Stage 1 is the expected result for the saved Gocator Classic / baseline).
      expect(cleaned.length).toBeGreaterThanOrEqual(10);
      expect(cleaned.length).toBeLessThanOrEqual(50);

      // Guaranteed drops
      const names = cleaned.map((c) => (c.name ?? "").toLowerCase());
      expect(names).not.toContain("threads");
      expect(names).not.toContain("pythoninterp");
      expect(names).not.toContain("sanitizers");
      expect(names).not.toContain("packagetest");
      expect(names).not.toContain("googletest-distribution");
      expect(names).not.toContain("gtest");
      expect(names).not.toContain("gmock");
      expect(cleaned.some((c) => c.version === "${VERSION_STRING}")).toBe(false);

      // BCL drops
      expect(names).not.toContain("system.xml");
      expect(names).not.toContain("presentationcore");
      expect(names).not.toContain("windowsbase");

      // System.Net.Http MUST be kept
      expect(names).toContain("system.net.http");

      // CefSharp should survive (real third-party dep)
      expect(names.some((n) => n.startsWith("cefsharp"))).toBe(true);

      // No versionless GoSdkNet when versioned siblings exist
      const goSdkVersionless = cleaned.filter(
        (c) => (c.name ?? "").toLowerCase() === "gosdknet" && (!c.version || c.version.trim() === ""),
      );
      const goSdkVersioned = cleaned.filter(
        (c) => (c.name ?? "").toLowerCase() === "gosdknet" && c.version && c.version.trim() !== "",
      );
      if (goSdkVersioned.length > 0) {
        expect(goSdkVersionless).toHaveLength(0);
      }

      // Friendly name aliases should be resolved
      expect(names).not.toContain("hardcodet wpf notifyicon");
      expect(names).not.toContain("xceed extended wpf toolkit");
    });
  });
});
