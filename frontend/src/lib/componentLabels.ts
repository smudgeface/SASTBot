/**
 * componentLabels.ts — M6q
 *
 * Helpers for displaying SBOM component metadata in a human-readable way.
 */

/**
 * Map raw cdxgen/CycloneDX ecosystem identifiers to a properly-cased display
 * label. Acronym ecosystems (NPM, PyPI as a brand) stay uppercase; brand-cased
 * ones (NuGet, RubyGems) get their brand casing back; everything else falls
 * back to title case so we never show all-caps "MAVEN" / "GOLANG".
 */
function formatEcosystemLabel(raw: string): string {
  const k = raw.toLowerCase();
  switch (k) {
    case "npm":     return "npm";
    case "nuget":   return "NuGet";
    case "pypi":    return "PyPI";
    case "maven":   return "Maven";
    case "golang":  return "Go";
    case "cargo":   return "Cargo";
    case "rubygems":return "RubyGems";
    case "gem":     return "RubyGems";
    case "composer":return "Composer";
    case "deb":     return "Debian";
    case "rpm":     return "RPM";
    case "generic": return "Generic";
    default:        return k.charAt(0).toUpperCase() + k.slice(1);
  }
}

/**
 * Returns the display label for the Ecosystem column in the Components tab.
 *
 * Design decision (per M6q investigation): 100% of `generic`-ecosystem rows
 * are LLM-augmentation finds in practice, but we key on discovery_method
 * rather than ecosystem to be forward-compatible with future non-LLM
 * `generic` rows.
 *
 * Returns a plain string — callers render it the same way for every variant
 * (no special badge for "Vendored", per UX feedback #8).
 *
 * @param ecosystem - raw ecosystem string (e.g. "npm", "nuget", "generic", null)
 * @param discoveryMethod - "manifest" | "llm_augmentation" | null
 */
export function prettyEcosystem(
  ecosystem: string | null | undefined,
  discoveryMethod: string | null | undefined,
): string {
  if (discoveryMethod === "llm_augmentation") return "Vendored";
  if (!ecosystem) return "—";
  return formatEcosystemLabel(ecosystem);
}
