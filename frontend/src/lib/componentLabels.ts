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
 * Normalise a license label for display.
 *
 * SPDX IDs are case-sensitive (MIT, Apache-2.0, BSD-3-Clause, GPL-3.0-only,
 * CC0-1.0, etc.) so we preserve them verbatim — they're recognisable by
 * containing a hyphen or a digit. Short all-caps abbreviations (≤4 chars
 * like MIT, ISC, BSD, GPL, LGPL, AGPL, MPL) are also kept verbatim.
 *
 * Everything else that's purely all-caps (CUSTOM, UNKNOWN, PROPRIETARY)
 * is treated as a bare-word descriptor — title-cased so it doesn't shout
 * (per UX feedback #10).
 */
export function prettyLicense(raw: string): string {
  const s = raw.trim();
  if (!s) return s;
  // SPDX-style IDs have hyphens or digits — preserve casing.
  if (/[-.]/.test(s) || /\d/.test(s)) return s;
  // Short SPDX abbreviations stay all-caps.
  if (/^[A-Z]+$/.test(s) && s.length <= 4) return s;
  // Bare-word all-caps label → title case.
  if (/^[A-Z]+$/.test(s)) {
    return s.charAt(0) + s.slice(1).toLowerCase();
  }
  return s;
}

/**
 * Returns the display label for the Ecosystem column in the Components tab.
 * Formats the stored ecosystem string verbatim (e.g. `generic` → "Generic");
 * null/empty renders as an em-dash.
 *
 * @param ecosystem - raw ecosystem string (e.g. "npm", "nuget", "generic", null)
 */
export function prettyEcosystem(ecosystem: string | null | undefined): string {
  if (!ecosystem) return "—";
  return formatEcosystemLabel(ecosystem);
}
