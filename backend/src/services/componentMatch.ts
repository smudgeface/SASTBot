// Deterministic component-identity matcher.
//
// Used in two places:
//   1. `applySbomAugmentation` (intra-scan dedup): compares each newly-emitted
//      add against survivors AND prior adds in the same scan.
//   2. `persistScanComponentsToScopeState` (vs DB): compares each incoming
//      component against active scope_components for the scope.
//
// The chain runs strict → progressively-tolerant matches:
//
//   1. component_root exact equality
//   2. component_root prefix containment (one is a sub-path of the other)
//   3. CPE exact equality
//   4. CPE vendor+product equality (version-agnostic — collapses `*` and
//      version-specific CPEs for the same upstream)
//   5. PURL exact equality
//   6. Normalized name + version equality (lowercase, strip separators,
//      strip leading `lib`/`vendor-` prefixes — tolerates the LLM's naming
//      drift across scans)
//   7. Manifest file + name equality (catches manifest-tracked components
//      where path/CPE don't apply but the source manifest does)
//
// First match wins. Returns null if nothing matched (caller decides what to
// do — insert as new, hand off to LLM, etc.). Each tier records which step
// hit so callers can log dedup behavior.
//
// Out of scope here: writing rows to the DB. This module is pure logic.
// The wrapper in scopeComponentService handles the actual upsert/insert.

export interface ComponentIdentity {
  /** Present on existing rows, undefined on incoming components. */
  id?: string;
  name: string;
  version: string | null;
  purl: string;
  ecosystem: string | null;
  /** Shallowest repo-relative dir uniquely owned by this component. */
  componentRoot: string | null;
  /** Legacy single-file evidence path, used as a fallback when the row
   *  predates the component_root migration. */
  evidencePath?: string | null;
  cpe: string | null;
  manifestFile: string | null;
}

export type MatchTier =
  | "component_root_exact"
  | "component_root_prefix"
  | "cpe_exact"
  | "cpe_family"
  | "purl_exact"
  | "normalized_name"
  | "manifest_file";

export interface MatchResult {
  matchedId: string;
  tier: MatchTier;
}

// ── Tier helpers ──────────────────────────────────────────────────────────

const STRIP_PREFIXES = ["lib", "libxx-", "vendor-"];

/**
 * Reduce a package name to a comparison form:
 *   lowercase, strip whitespace/dashes/underscores, drop a leading
 *   `lib` (or `vendor-`) prefix. Tolerates LLM naming variance like
 *   "ophir-lm-measurement" vs "ophir-lmmeasurement",
 *   "Nerian visiontransfer" vs "nerian-visiontransfer".
 */
export function normalizeName(name: string): string {
  let n = name.toLowerCase().replace(/[\s\-_]+/g, "");
  for (const p of STRIP_PREFIXES) {
    if (n.startsWith(p)) {
      n = n.slice(p.length);
      break;
    }
  }
  return n;
}

/**
 * Parse a CPE 2.3 string into vendor + product (the bits that identify the
 * upstream regardless of version). Returns null if the input isn't a
 * recognizable CPE 2.3 URI.
 *
 * CPE 2.3 format: `cpe:2.3:<part>:<vendor>:<product>:<version>:...`
 */
export function extractCpeFamily(
  cpe: string | null | undefined,
): { vendor: string; product: string } | null {
  if (!cpe) return null;
  const parts = cpe.split(":");
  if (parts.length < 5) return null;
  if (parts[0] !== "cpe" || parts[1] !== "2.3") return null;
  const vendor = (parts[3] ?? "").toLowerCase();
  const product = (parts[4] ?? "").toLowerCase();
  if (!vendor || !product) return null;
  return { vendor, product };
}

/**
 * True when `parent` is a directory-prefix of `child`, or vice versa, with
 * proper component-aware matching (so `extern/Foo` matches `extern/Foo/bar`
 * but not `extern/Foobar`). Treats POSIX-style separators.
 *
 * Returns the deeper (more-specific) path when a containment relation holds,
 * else null. The deeper path is the canonical identity — collapsing to it
 * preserves the more precise location.
 */
export function pathContainment(
  a: string | null | undefined,
  b: string | null | undefined,
): { deeper: string; shallower: string } | null {
  if (!a || !b) return null;
  const norm = (p: string): string => p.replace(/^\/+|\/+$/g, "");
  const na = norm(a);
  const nb = norm(b);
  if (na === nb) return null; // exact equality is Tier 1, not prefix
  if (na.startsWith(nb + "/")) return { deeper: na, shallower: nb };
  if (nb.startsWith(na + "/")) return { deeper: nb, shallower: na };
  return null;
}

// ── Main matcher ──────────────────────────────────────────────────────────

/**
 * Run the deterministic match chain. Each tier is evaluated in order; first
 * candidate that satisfies the predicate wins. Caller can act on the result
 * (upsert into the matched row, or insert as new if no match).
 */
export function matchComponent(
  incoming: ComponentIdentity,
  candidates: ComponentIdentity[],
): MatchResult | null {
  if (candidates.length === 0) return null;

  const incomingRoot = incoming.componentRoot ?? incoming.evidencePath ?? null;

  // Tier 1: component_root exact equality.
  if (incomingRoot) {
    for (const c of candidates) {
      const cRoot = c.componentRoot ?? c.evidencePath ?? null;
      if (cRoot && cRoot === incomingRoot && c.id) {
        return { matchedId: c.id, tier: "component_root_exact" };
      }
    }
  }

  // Tier 2: component_root prefix containment.
  if (incomingRoot) {
    for (const c of candidates) {
      const cRoot = c.componentRoot ?? c.evidencePath ?? null;
      if (cRoot && c.id && pathContainment(incomingRoot, cRoot)) {
        return { matchedId: c.id, tier: "component_root_prefix" };
      }
    }
  }

  // Tier 3: CPE exact equality.
  if (incoming.cpe) {
    for (const c of candidates) {
      if (c.cpe && c.cpe === incoming.cpe && c.id) {
        return { matchedId: c.id, tier: "cpe_exact" };
      }
    }
  }

  // Tier 4: CPE vendor+product equality (version-agnostic).
  const incomingFamily = extractCpeFamily(incoming.cpe);
  if (incomingFamily) {
    for (const c of candidates) {
      const cFamily = extractCpeFamily(c.cpe);
      if (
        cFamily &&
        cFamily.vendor === incomingFamily.vendor &&
        cFamily.product === incomingFamily.product &&
        c.id
      ) {
        return { matchedId: c.id, tier: "cpe_family" };
      }
    }
  }

  // Tier 5: PURL exact equality.
  if (incoming.purl) {
    for (const c of candidates) {
      if (c.purl === incoming.purl && c.id) {
        return { matchedId: c.id, tier: "purl_exact" };
      }
    }
  }

  // Tier 6: Normalized name + version equality.
  const incomingNormName = normalizeName(incoming.name);
  for (const c of candidates) {
    if (!c.id) continue;
    if (normalizeName(c.name) === incomingNormName) {
      // Version must agree exactly (both null counts as agreement). Different
      // versions of the same library are NOT a dedup match.
      const incomingVersion = (incoming.version ?? "").trim();
      const cVersion = (c.version ?? "").trim();
      if (incomingVersion === cVersion) {
        return { matchedId: c.id, tier: "normalized_name" };
      }
    }
  }

  // Tier 7: Manifest file + name equality. Catches ecosystem packages where
  // the LLM might rewrite the name but the source manifest is unchanged.
  if (incoming.manifestFile) {
    const incomingNorm = normalizeName(incoming.name);
    for (const c of candidates) {
      if (!c.id) continue;
      if (
        c.manifestFile === incoming.manifestFile &&
        normalizeName(c.name) === incomingNorm
      ) {
        return { matchedId: c.id, tier: "manifest_file" };
      }
    }
  }

  return null;
}

/**
 * Picks a "canonical" name from a set of candidate names. Used when the
 * matcher collapses two rows and the caller needs to choose which name to
 * keep on the surviving row. Heuristic: prefer the name with MORE separators
 * (kebab-case is the canonical upstream convention), then more lowercase
 * characters (e.g. `xenomai` over `Xenomai`).
 */
export function pickCanonicalName(names: string[]): string {
  if (names.length === 0) return "";
  if (names.length === 1) return names[0]!;
  let best = names[0]!;
  let bestScore = scoreName(best);
  for (let i = 1; i < names.length; i++) {
    const s = scoreName(names[i]!);
    if (s > bestScore) {
      best = names[i]!;
      bestScore = s;
    }
  }
  return best;
}

function scoreName(name: string): number {
  const separators = (name.match(/[-_]/g) ?? []).length;
  const lowerRatio =
    name.length === 0 ? 0 : (name.match(/[a-z]/g) ?? []).length / name.length;
  return separators * 10 + lowerRatio;
}
