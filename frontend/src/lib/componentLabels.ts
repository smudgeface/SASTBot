/**
 * componentLabels.ts — M6q Phase 3
 *
 * Helpers for displaying SBOM component metadata in a human-readable way.
 */

/**
 * Returns a display label and visual variant for the ecosystem/discovery-method
 * column in the Components tab.
 *
 * Design decision (per M6q investigation): 100% of `generic`-ecosystem rows
 * are LLM-augmentation finds in practice, but we key on discovery_method rather
 * than ecosystem to be forward-compatible with any future non-LLM generic rows.
 *
 * @param ecosystem - raw ecosystem string (e.g. "npm", "nuget", "generic", null)
 * @param discoveryMethod - "manifest" | "llm_augmentation" | null
 */
export function prettyEcosystem(
  ecosystem: string | null | undefined,
  discoveryMethod: string | null | undefined,
): { label: string; variant: "ecosystem" | "vendored" } {
  if (discoveryMethod === "llm_augmentation") {
    return { label: "Vendored", variant: "vendored" };
  }
  const raw = ecosystem ?? null;
  return {
    label: raw ? raw.toUpperCase() : "—",
    variant: "ecosystem",
  };
}
