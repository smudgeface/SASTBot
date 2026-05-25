// Vite-bundled asset URLs for the screenshots embedded in the user manual.
// Manual sections import the URL and use it as the `src` attribute via
// markdown `![alt](url)` after string substitution at render time.
//
// To add a screenshot:
//   1. Drop the .png under this directory.
//   2. Export it from here (as a URL).
//   3. Reference the placeholder in your markdown via `:::asset:<name>:::`
//      (the substitution map is in ManualSection.tsx).

import scopesOverview from "./scopes-overview.png";
import scopeDetailSca from "./scope-detail-sca.png";
import sastSarifViewer from "./sast-sarif-viewer.png";

export const MANUAL_ASSETS: Record<string, string> = {
  "scopes-overview": scopesOverview,
  "scope-detail-sca": scopeDetailSca,
  "sast-sarif-viewer": sastSarifViewer,
};
