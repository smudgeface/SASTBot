// User manual section manifest. The content files live under
// `./content/*.md` and are imported as raw strings via Vite's `?raw` query.
// Adding a section: drop a new .md file under content/, add an entry here.
//
// `slug` becomes the URL fragment under /manual/:slug. `title` shows in the
// TOC sidebar. `kind` is used by the sidebar to group narrative pages from
// the protocol reference (which is a live-rendered React route, not markdown).

import indexBody from "./content/index.md?raw";
import quickStartBody from "./content/quick-start.md?raw";
import overviewBody from "./content/overview.md?raw";
import repositoriesBody from "./content/repositories.md?raw";
import scopesBody from "./content/scopes.md?raw";
import scansBody from "./content/scans.md?raw";
import scaIssuesBody from "./content/sca-issues.md?raw";
import sastIssuesBody from "./content/sast-issues.md?raw";
import componentsSbomBody from "./content/components-sbom.md?raw";
import jiraBody from "./content/jira.md?raw";
import credentialsBody from "./content/credentials.md?raw";
import adminUsersBody from "./content/admin-users.md?raw";
import adminSettingsBody from "./content/admin-settings.md?raw";
import adminConfigurationBody from "./content/admin-configuration.md?raw";
import adminBackupRestoreBody from "./content/admin-backup-restore.md?raw";
import adminVersioningBody from "./content/admin-versioning.md?raw";
import adminDeploymentBody from "./content/admin-deployment.md?raw";
import troubleshootingBody from "./content/troubleshooting.md?raw";

export type ManualKind = "markdown" | "api-reference";

export interface ManualSection {
  slug: string;
  title: string;
  kind: ManualKind;
  /** Group label for the sidebar TOC. Empty string = ungrouped. */
  group: string;
  /** Markdown body. Empty when kind === "api-reference". */
  body: string;
}

export const MANUAL_SECTIONS: ManualSection[] = [
  { slug: "index", title: "Welcome", kind: "markdown", group: "", body: indexBody },
  { slug: "quick-start", title: "Quick start", kind: "markdown", group: "Getting started", body: quickStartBody },
  { slug: "overview", title: "How SASTBot works", kind: "markdown", group: "Getting started", body: overviewBody },
  { slug: "repositories", title: "Repositories", kind: "markdown", group: "Day-to-day use", body: repositoriesBody },
  { slug: "scopes", title: "Scopes", kind: "markdown", group: "Day-to-day use", body: scopesBody },
  { slug: "scans", title: "Scans", kind: "markdown", group: "Day-to-day use", body: scansBody },
  { slug: "sca-issues", title: "SCA (CVE) findings", kind: "markdown", group: "Day-to-day use", body: scaIssuesBody },
  { slug: "sast-issues", title: "SAST (CWE) findings", kind: "markdown", group: "Day-to-day use", body: sastIssuesBody },
  { slug: "components-sbom", title: "Components & SBOM", kind: "markdown", group: "Day-to-day use", body: componentsSbomBody },
  { slug: "jira", title: "Jira integration", kind: "markdown", group: "Day-to-day use", body: jiraBody },
  { slug: "credentials", title: "Credentials", kind: "markdown", group: "Administration", body: credentialsBody },
  { slug: "admin-users", title: "Users", kind: "markdown", group: "Administration", body: adminUsersBody },
  { slug: "admin-settings", title: "Settings page", kind: "markdown", group: "Administration", body: adminSettingsBody },
  { slug: "admin-configuration", title: "Configuration", kind: "markdown", group: "Administration", body: adminConfigurationBody },
  { slug: "admin-backup-restore", title: "Backup & restore", kind: "markdown", group: "Administration", body: adminBackupRestoreBody },
  { slug: "admin-versioning", title: "Versioning & upgrades", kind: "markdown", group: "Administration", body: adminVersioningBody },
  { slug: "admin-deployment", title: "Deployment", kind: "markdown", group: "Administration", body: adminDeploymentBody },
  { slug: "troubleshooting", title: "Troubleshooting", kind: "markdown", group: "Reference", body: troubleshootingBody },
  { slug: "api-reference", title: "API reference", kind: "api-reference", group: "Reference", body: "" },
];

export function findManualSection(slug: string | undefined): ManualSection | undefined {
  if (!slug) return MANUAL_SECTIONS[0];
  return MANUAL_SECTIONS.find((s) => s.slug === slug);
}
