/**
 * Unit tests for the 7-tier deterministic component matcher.
 *
 * Source: backend/src/services/componentMatch.ts
 *
 * Pure logic, no DB access required.
 *
 * Tests each tier in isolation with a candidate set crafted to hit ONLY that
 * tier, plus cross-tier priority and pickCanonicalName behavior.
 */

import { randomUUID } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  matchComponent,
  normalizeName,
  pickCanonicalName,
  extractCpeFamily,
  pathContainment,
  type ComponentIdentity,
} from "../src/services/componentMatch.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeCandidate(overrides: Partial<ComponentIdentity> = {}): ComponentIdentity {
  return {
    id: randomUUID(),
    name: "some-lib",
    version: "1.0.0",
    purl: `pkg:generic/some-lib@1.0.0-${randomUUID()}`,
    ecosystem: "generic",
    componentRoot: null,
    cpe: null,
    manifestFile: null,
    ...overrides,
  };
}

function makeIncoming(overrides: Partial<ComponentIdentity> = {}): ComponentIdentity {
  return {
    // Incoming components don't have an id yet.
    name: "some-lib",
    version: "1.0.0",
    purl: `pkg:generic/some-lib@1.0.0-${randomUUID()}`,
    ecosystem: "generic",
    componentRoot: null,
    cpe: null,
    manifestFile: null,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tier 1: component_root exact equality
// ---------------------------------------------------------------------------

describe("matchComponent — Tier 1: component_root_exact", () => {
  it("matches when componentRoot is identical", () => {
    const root = "extern/Xenomai";
    const candidate = makeCandidate({ componentRoot: root });
    const incoming = makeIncoming({ componentRoot: root, purl: "pkg:generic/different-purl" });

    const result = matchComponent(incoming, [candidate]);
    expect(result).not.toBeNull();
    expect(result!.tier).toBe("component_root_exact");
    expect(result!.matchedId).toBe(candidate.id);
  });

  it("does not match when componentRoot differs", () => {
    const candidate = makeCandidate({ componentRoot: "extern/Foo" });
    const incoming = makeIncoming({ componentRoot: "extern/Bar" });

    // Use a purl that won't match tier 5 either.
    const result = matchComponent(incoming, [{ ...candidate, purl: "pkg:generic/different@1.0" }]);
    // May match on a lower tier but not on root_exact.
    if (result) {
      expect(result.tier).not.toBe("component_root_exact");
    }
  });
});

// ---------------------------------------------------------------------------
// Tier 2: component_root prefix containment
// ---------------------------------------------------------------------------

describe("matchComponent — Tier 2: component_root_prefix", () => {
  it("matches when incoming root is a sub-path of the candidate root", () => {
    const candidate = makeCandidate({
      componentRoot: "extern/Xenomai",
      purl: "pkg:generic/candidate-unique-purl@1.0",
    });
    const incoming = makeIncoming({
      componentRoot: "extern/Xenomai/drivers",
      purl: "pkg:generic/incoming-unique-purl@1.0",
    });

    const result = matchComponent(incoming, [candidate]);
    expect(result).not.toBeNull();
    expect(result!.tier).toBe("component_root_prefix");
    expect(result!.matchedId).toBe(candidate.id);
  });

  it("matches when candidate root is a sub-path of the incoming root", () => {
    const candidate = makeCandidate({
      componentRoot: "extern/Xenomai/core",
      purl: "pkg:generic/candidate-unique-purl2@1.0",
    });
    const incoming = makeIncoming({
      componentRoot: "extern/Xenomai",
      purl: "pkg:generic/incoming-unique-purl2@1.0",
    });

    const result = matchComponent(incoming, [candidate]);
    expect(result).not.toBeNull();
    expect(result!.tier).toBe("component_root_prefix");
  });

  it("does not match on prefix when roots share a common prefix but are siblings", () => {
    // extern/FooBar is NOT a sub-path of extern/Foo
    const candidate = makeCandidate({
      componentRoot: "extern/Foo",
      purl: "pkg:generic/sibling-a@1.0",
    });
    const incoming = makeIncoming({
      componentRoot: "extern/FooBar",
      purl: "pkg:generic/sibling-b@1.0",
    });

    const result = matchComponent(incoming, [candidate]);
    // Should not match on component_root_prefix (or _exact).
    if (result) {
      expect(result.tier).not.toBe("component_root_exact");
      expect(result.tier).not.toBe("component_root_prefix");
    }
  });
});

// ---------------------------------------------------------------------------
// Tier 3: CPE exact equality
// ---------------------------------------------------------------------------

describe("matchComponent — Tier 3: cpe_exact", () => {
  it("matches on exact CPE string", () => {
    const cpe = "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*";
    const candidate = makeCandidate({
      cpe,
      purl: "pkg:generic/cpe-exact-candidate@1.0",
      componentRoot: null,
    });
    const incoming = makeIncoming({
      cpe,
      purl: "pkg:generic/cpe-exact-incoming@1.0", // different purl
      componentRoot: null,
    });

    const result = matchComponent(incoming, [candidate]);
    expect(result).not.toBeNull();
    expect(result!.tier).toBe("cpe_exact");
    expect(result!.matchedId).toBe(candidate.id);
  });

  it("does not match when CPEs differ", () => {
    const candidate = makeCandidate({
      cpe: "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*",
      purl: "pkg:generic/cpe-diff-candidate@1.0",
      componentRoot: null,
    });
    const incoming = makeIncoming({
      cpe: "cpe:2.3:a:openssl:openssl:3.1.0:*:*:*:*:*:*:*",
      purl: "pkg:generic/cpe-diff-incoming@1.0",
      componentRoot: null,
    });

    const result = matchComponent(incoming, [candidate]);
    // May match on cpe_family (tier 4) but not cpe_exact.
    if (result) {
      expect(result.tier).not.toBe("cpe_exact");
    }
  });
});

// ---------------------------------------------------------------------------
// Tier 4: CPE vendor+product equality (version-agnostic)
// ---------------------------------------------------------------------------

describe("matchComponent — Tier 4: cpe_family", () => {
  it("matches two CPEs for the same vendor+product with different versions", () => {
    const cpeOld = "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*";
    const cpeNew = "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*";
    const candidate = makeCandidate({
      cpe: cpeOld,
      purl: "pkg:generic/family-candidate@1.0",
      componentRoot: null,
    });
    const incoming = makeIncoming({
      cpe: cpeNew,
      purl: "pkg:generic/family-incoming@1.0", // different purl
      componentRoot: null,
    });

    const result = matchComponent(incoming, [candidate]);
    expect(result).not.toBeNull();
    expect(result!.tier).toBe("cpe_family");
    expect(result!.matchedId).toBe(candidate.id);
  });

  it("does not match CPEs from different vendors", () => {
    const candidate = makeCandidate({
      cpe: "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*",
      purl: "pkg:generic/vendor-diff-candidate@1.0",
      componentRoot: null,
    });
    const incoming = makeIncoming({
      cpe: "cpe:2.3:a:microsoft:openssl:3.0.0:*:*:*:*:*:*:*",
      purl: "pkg:generic/vendor-diff-incoming@1.0",
      componentRoot: null,
    });

    const result = matchComponent(incoming, [candidate]);
    if (result) {
      expect(result.tier).not.toBe("cpe_family");
      expect(result.tier).not.toBe("cpe_exact");
    }
  });
});

// ---------------------------------------------------------------------------
// Tier 5: PURL exact equality
// ---------------------------------------------------------------------------

describe("matchComponent — Tier 5: purl_exact", () => {
  it("matches on exact PURL when no root or CPE overlap exists", () => {
    const purl = "pkg:npm/%40types/node@18.0.0";
    const candidate = makeCandidate({
      purl,
      componentRoot: null,
      cpe: null,
    });
    const incoming = makeIncoming({
      purl,
      componentRoot: null,
      cpe: null,
      name: "different-display-name", // name differs to avoid tier 6
    });

    const result = matchComponent(incoming, [candidate]);
    expect(result).not.toBeNull();
    expect(result!.tier).toBe("purl_exact");
    expect(result!.matchedId).toBe(candidate.id);
  });
});

// ---------------------------------------------------------------------------
// Tier 6: normalized name + version
// ---------------------------------------------------------------------------

describe("matchComponent — Tier 6: normalized_name", () => {
  it("matches despite case difference", () => {
    const candidate = makeCandidate({
      name: "OpenSSL",
      version: "3.0.0",
      purl: "pkg:generic/openssl-candidate@3.0.0",
      componentRoot: null,
      cpe: null,
    });
    const incoming = makeIncoming({
      name: "openssl",
      version: "3.0.0",
      purl: "pkg:generic/openssl-incoming@3.0.0",
      componentRoot: null,
      cpe: null,
    });

    const result = matchComponent(incoming, [candidate]);
    expect(result).not.toBeNull();
    expect(result!.tier).toBe("normalized_name");
  });

  it("matches despite separator difference (dashes vs underscores)", () => {
    const candidate = makeCandidate({
      name: "boost-filesystem",
      version: "1.80",
      purl: "pkg:generic/boost-filesystem@1.80",
      componentRoot: null,
      cpe: null,
    });
    const incoming = makeIncoming({
      name: "boost_filesystem",
      version: "1.80",
      purl: "pkg:generic/boost_filesystem@1.80",
      componentRoot: null,
      cpe: null,
    });

    const result = matchComponent(incoming, [candidate]);
    expect(result).not.toBeNull();
    expect(result!.tier).toBe("normalized_name");
  });

  it("does NOT match when versions differ (different package)", () => {
    const candidate = makeCandidate({
      name: "openssl",
      version: "1.1.1",
      purl: "pkg:generic/openssl@1.1.1",
      componentRoot: null,
      cpe: null,
    });
    const incoming = makeIncoming({
      name: "openssl",
      version: "3.0.0",
      purl: "pkg:generic/openssl@3.0.0",
      componentRoot: null,
      cpe: null,
    });

    const result = matchComponent(incoming, [candidate]);
    // Different versions must NOT match on tier 6.
    if (result) {
      expect(result.tier).not.toBe("normalized_name");
    }
  });

  it("matches when both versions are null", () => {
    const candidate = makeCandidate({
      name: "yaffs2",
      version: null,
      purl: "pkg:generic/yaffs2-candidate",
      componentRoot: null,
      cpe: null,
    });
    const incoming = makeIncoming({
      name: "yaffs2",
      version: null,
      purl: "pkg:generic/yaffs2-incoming",
      componentRoot: null,
      cpe: null,
    });

    const result = matchComponent(incoming, [candidate]);
    expect(result).not.toBeNull();
    expect(result!.tier).toBe("normalized_name");
  });
});

// ---------------------------------------------------------------------------
// Tier 7: manifest file + name
// ---------------------------------------------------------------------------

describe("matchComponent — Tier 7: manifest_file", () => {
  it("matches when manifest file and normalized name agree", () => {
    const candidate = makeCandidate({
      name: "lodash",
      version: "4.17.21",
      purl: "pkg:npm/lodash@4.17.21-candidate",
      componentRoot: null,
      cpe: null,
      manifestFile: "package.json",
    });
    const incoming = makeIncoming({
      name: "Lodash",    // different case — normalization must handle it
      version: "4.17.21",
      purl: "pkg:npm/lodash@4.17.21-incoming",
      componentRoot: null,
      cpe: null,
      manifestFile: "package.json",
    });

    // Force tier 6 to miss by using distinct purls AND making names distinct
    // at tier 6 level while still matching at tier 7. Actually both normalize
    // to "lodash" so tier 6 will match. We need tier 6 to miss:
    // use different versions so tier 6 doesn't fire.
    incoming.version = "4.18.0"; // tier 6 won't match (different version)

    const result = matchComponent(incoming, [candidate]);
    expect(result).not.toBeNull();
    expect(result!.tier).toBe("manifest_file");
    expect(result!.matchedId).toBe(candidate.id);
  });

  it("does not match when manifest files differ even if names match", () => {
    const candidate = makeCandidate({
      name: "lodash",
      version: null,
      purl: "pkg:npm/lodash-manifest-diff-candidate",
      componentRoot: null,
      cpe: null,
      manifestFile: "frontend/package.json",
    });
    const incoming = makeIncoming({
      name: "lodash",
      version: "5.0.0", // different version → tier 6 skipped
      purl: "pkg:npm/lodash-manifest-diff-incoming",
      componentRoot: null,
      cpe: null,
      manifestFile: "backend/package.json",
    });

    const result = matchComponent(incoming, [candidate]);
    if (result) {
      expect(result.tier).not.toBe("manifest_file");
    }
  });
});

// ---------------------------------------------------------------------------
// No match
// ---------------------------------------------------------------------------

describe("matchComponent — no match", () => {
  it("returns null when no candidate satisfies any tier", () => {
    const candidate = makeCandidate({
      componentRoot: "extern/Alpha",
      cpe: "cpe:2.3:a:alpha:alpha:1.0:*:*:*:*:*:*:*",
      purl: "pkg:generic/alpha@1.0",
      name: "alpha",
      version: "1.0",
      manifestFile: "CMakeLists.txt",
    });
    const incoming = makeIncoming({
      componentRoot: "third-party/Beta",
      cpe: "cpe:2.3:a:beta:beta:2.0:*:*:*:*:*:*:*",
      purl: "pkg:generic/beta@2.0",
      name: "beta",
      version: "2.0",
      manifestFile: "Makefile",
    });

    const result = matchComponent(incoming, [candidate]);
    expect(result).toBeNull();
  });

  it("returns null for empty candidate list", () => {
    const incoming = makeIncoming();
    expect(matchComponent(incoming, [])).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// First-match-wins priority
// ---------------------------------------------------------------------------

describe("matchComponent — first-match-wins priority", () => {
  it("a tier-1 root-exact match wins even when a tier-5 PURL match is also present", () => {
    const purl = "pkg:generic/shared-purl@1.0";
    const tier1Candidate = makeCandidate({
      id: "tier-1-id",
      componentRoot: "extern/MyLib",
      purl: "pkg:generic/some-other-purl@1.0",  // different purl → would NOT match tier 5
      cpe: null,
    });
    const tier5Candidate = makeCandidate({
      id: "tier-5-id",
      componentRoot: null,
      purl,
      cpe: null,
    });
    const incoming = makeIncoming({
      componentRoot: "extern/MyLib",
      purl, // same as tier5Candidate — but tier 1 should fire first
      cpe: null,
    });

    // Tier-1 candidate is first in the list.
    const result = matchComponent(incoming, [tier1Candidate, tier5Candidate]);
    expect(result).not.toBeNull();
    expect(result!.tier).toBe("component_root_exact");
    expect(result!.matchedId).toBe("tier-1-id");
  });
});

// ---------------------------------------------------------------------------
// pickCanonicalName
// ---------------------------------------------------------------------------

describe("pickCanonicalName", () => {
  it("returns empty string for an empty array", () => {
    expect(pickCanonicalName([])).toBe("");
  });

  it("returns the sole element for a single-element array", () => {
    expect(pickCanonicalName(["Xenomai"])).toBe("Xenomai");
  });

  it("prefers the more-kebab-case name (more separators)", () => {
    // "boost-filesystem" has 1 separator; "boostfilesystem" has 0.
    expect(pickCanonicalName(["boostfilesystem", "boost-filesystem"])).toBe("boost-filesystem");
  });

  it("prefers more lowercase characters when separators are tied", () => {
    // "Xenomai" has 0 separators, 6 lowercase + 1 uppercase
    // "xenomai" has 0 separators, 7 lowercase → higher lowerRatio
    expect(pickCanonicalName(["Xenomai", "xenomai"])).toBe("xenomai");
  });

  it("among kebab variants prefers the one with more separators", () => {
    // "boost-filesystem" (1 sep) vs "boost-file-system" (2 seps)
    expect(pickCanonicalName(["boost-filesystem", "boost-file-system"])).toBe("boost-file-system");
  });
});

// ---------------------------------------------------------------------------
// normalizeName helpers
// ---------------------------------------------------------------------------

describe("normalizeName", () => {
  it("lowercases the input", () => {
    expect(normalizeName("OpenSSL")).toBe("openssl");
  });

  it("strips dashes and underscores", () => {
    expect(normalizeName("boost-filesystem")).toBe("boostfilesystem");
    expect(normalizeName("boost_filesystem")).toBe("boostfilesystem");
  });

  it("strips leading 'lib' prefix", () => {
    expect(normalizeName("libxml2")).toBe("xml2");
  });

  it("does not strip 'lib' in the middle of a name", () => {
    expect(normalizeName("xmllib")).toBe("xmllib");
  });
});

// ---------------------------------------------------------------------------
// extractCpeFamily helpers
// ---------------------------------------------------------------------------

describe("extractCpeFamily", () => {
  it("extracts vendor and product from a valid CPE 2.3 string", () => {
    const result = extractCpeFamily("cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*");
    expect(result).toEqual({ vendor: "openssl", product: "openssl" });
  });

  it("returns null for null/undefined input", () => {
    expect(extractCpeFamily(null)).toBeNull();
    expect(extractCpeFamily(undefined)).toBeNull();
  });

  it("returns null for non-CPE strings", () => {
    expect(extractCpeFamily("not-a-cpe")).toBeNull();
    expect(extractCpeFamily("")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// pathContainment helpers
// ---------------------------------------------------------------------------

describe("pathContainment", () => {
  it("returns null for two equal paths (exact equality is tier 1, not tier 2)", () => {
    expect(pathContainment("extern/Foo", "extern/Foo")).toBeNull();
  });

  it("detects a → b containment", () => {
    const result = pathContainment("extern/Foo", "extern/Foo/bar");
    expect(result).not.toBeNull();
    expect(result!.deeper).toBe("extern/Foo/bar");
    expect(result!.shallower).toBe("extern/Foo");
  });

  it("detects b → a containment", () => {
    const result = pathContainment("extern/Foo/bar", "extern/Foo");
    expect(result).not.toBeNull();
    expect(result!.deeper).toBe("extern/Foo/bar");
  });

  it("returns null for sibling paths that share a prefix", () => {
    expect(pathContainment("extern/FooBar", "extern/Foo")).toBeNull();
  });

  it("returns null when either argument is null", () => {
    expect(pathContainment(null, "extern/Foo")).toBeNull();
    expect(pathContainment("extern/Foo", null)).toBeNull();
  });
});
