// SARIF v2.1.0 export — derives an industry-standard static-analysis result
// document from the SAST issues observed in a scan run.
//
// Why we still produce SARIF when LLM SAST replaced Opengrep:
//   - Operators (and downstream tools) expect a portable file they can hand
//     off to dashboards, CI gates, or compliance evidence collection.
//   - SARIF gives us a single export schema that's not coupled to our
//     internal table layout, so we can refactor sast_issues freely.
//
// Producer / RMS distinction (SARIF §3.27.23, Appendix B): a direct SARIF
// producer SHOULD NOT populate `partialFingerprints`, and lifecycle metadata
// (first_seen_at, last_seen_at, triage_status) belongs to the result-management
// system, not the producer. In SASTBot, the *scan* is the producer (a single
// LLM run on one revision) and the *scope* is the RMS (cross-scan dedup,
// triage, lifecycle). So this builder emits a producer-shaped SARIF: raw
// findings only, no fingerprints, no lifecycle fields. A scope-level export
// could emit the RMS-augmented variant later if needed.
//
// Schema reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html

import type { SastIssue } from "@prisma/client";

const SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json";
const TOOL_NAME = "SASTBot";
const TOOL_INFO_URI = "https://github.com/smudgeface/SASTBot";
const ABSENCE_SNIPPET_PREFIX = "__absence__:";

export interface SarifBuildOpts {
  /** Tool version string surfaced under `runs[0].tool.driver.version`. */
  toolVersion: string;
  /** LLM model that produced the detections — recorded as a tool property
   *  so consumers know which model the run was based on. */
  modelName?: string | null;
  /** Repo-rooted scope prefix ("/", "/GoWeb"). Currently only used in the
   *  invocation properties so consumers can tell sub-scope runs apart. */
  scopePath?: string;
  /** Wall-clock window of the scan, used in `runs[0].invocations[0]`. */
  startedAt?: Date | null;
  endedAt?: Date | null;
}

// SARIF level mapping from our internal severity vocabulary. SARIF only has
// {none, note, warning, error}, so critical and high collapse to "error".
function severityToLevel(sev: string): "error" | "warning" | "note" | "none" {
  switch (sev) {
    case "critical": return "error";
    case "high":     return "error";
    case "medium":   return "warning";
    case "low":      return "note";
    case "info":     return "note";
    default:         return "none";
  }
}

interface SarifReportingDescriptorRelationship {
  target: SarifTaxonReference;
  // SARIF §3.53.3 — "relevant" means the source rule assesses the target
  // weakness. That's exactly our LLM-mode mapping: each rule asks
  // "does this CWE apply here?".
  kinds: ["relevant"];
}

interface SarifReportingDescriptor {
  id: string;
  name?: string;
  shortDescription?: { text: string };
  fullDescription?: { text: string };
  helpUri?: string;
  relationships?: SarifReportingDescriptorRelationship[];
  properties?: Record<string, unknown>;
}

interface SarifRegion {
  startLine: number;
  endLine?: number;
  snippet?: { text: string };
}

interface SarifTaxonReference {
  toolComponent: { name: string };
  id: string;
}

interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note" | "none";
  kind?: "informational" | "fail";
  message: { text: string };
  locations?: {
    physicalLocation: {
      artifactLocation: { uri: string };
      // SARIF §3.30: `region` points at the problem itself; `contextRegion`
      // is a superset that gives surrounding lines for display. Keeping the
      // snippet on contextRegion (not region) matches how IDEs and review
      // tools render results — bold the region, dim the rest.
      region?: SarifRegion;
      contextRegion?: SarifRegion;
    };
  }[];
  // CWE references live on the rule descriptor via `relationships`, not
  // here — emitting them per-result would duplicate the rule→CWE mapping
  // on every finding. Consumers dereference through `ruleId`.
  // No `fingerprints` either — RMS field per SARIF §3.27.23.
  properties?: Record<string, unknown>;
}

interface SarifTaxon {
  id: string;
  helpUri?: string;
}

interface SarifTaxonomy {
  name: string;
  organization?: string;
  informationUri?: string;
  shortDescription?: { text: string };
  isComprehensive?: boolean;
  taxa: SarifTaxon[];
}

const CWE_TOOL_COMPONENT_NAME = "CWE";

/** Strip "CWE-" prefix and return just the numeric id ("CWE-798" → "798").
 *  SARIF taxon ids are bare identifiers; the CWE prefix is encoded by the
 *  taxonomy's `name`. Returns null if the input doesn't look like a CWE. */
function cweNumericId(raw: string): string | null {
  const m = raw.match(/^CWE-(\d+)$/i) ?? raw.match(/^(\d+)$/);
  return m ? m[1]! : null;
}

// LLM detection prompt asks for 3 lines above + match span + 3 lines below.
// Mirrors the frontend `STORED_CONTEXT_LINES` constant — kept in sync because
// both sides interpret the same persisted snippet.
const STORED_CONTEXT_LINES = 3;

/**
 * Build a SARIF v2.1.0 document from the SAST issues for one scan run.
 * The caller is responsible for filtering `issues` to a single scan
 * (typically `lastSeenScanRunId == scanRunId`).
 */
export function buildSarifFromIssues(issues: SastIssue[], opts: SarifBuildOpts): unknown {
  // Dedupe rules by ruleId. CWE references are accumulated per-rule and
  // emitted as `relationships` on the rule descriptor at the end — that's
  // the single canonical place for the rule→weakness mapping. Results
  // inherit through `ruleId` and don't need to repeat it.
  const ruleById = new Map<string, SarifReportingDescriptor>();
  const ruleCwes = new Map<string, Set<string>>();
  const results: SarifResult[] = [];
  // Collect every CWE id we cite so the run-level taxonomy can list them.
  const citedCweIds = new Set<string>();

  for (const issue of issues) {
    const ruleId = issue.latestRuleId || "llm:UNKNOWN";
    if (!ruleById.has(ruleId)) {
      const firstCwe = issue.latestCweIds?.[0];
      const helpUri = firstCwe
        ? `https://cwe.mitre.org/data/definitions/${firstCwe.replace(/^CWE-/, "")}.html`
        : undefined;
      ruleById.set(ruleId, {
        id: ruleId,
        name: issue.latestRuleName ?? undefined,
        shortDescription: issue.latestRuleMessage
          ? { text: issue.latestRuleMessage }
          : undefined,
        helpUri,
      });
    }
    // Accumulate CWE ids per rule. In LLM mode a rule's id IS its CWE
    // (`llm:CWE-798`), so this set typically has one entry — but we still
    // dedupe in case different findings under the same ruleId reported
    // different CWE lists.
    let perRule = ruleCwes.get(ruleId);
    if (!perRule) {
      perRule = new Set();
      ruleCwes.set(ruleId, perRule);
    }
    for (const raw of issue.latestCweIds ?? []) {
      const num = cweNumericId(raw);
      if (!num) continue;
      perRule.add(num);
      citedCweIds.add(num);
    }

    const isAbsence = issue.latestSnippet?.startsWith(ABSENCE_SNIPPET_PREFIX) ?? false;
    const level = severityToLevel(issue.latestSeverity);
    // Prefer the LLM summary (one or two sentences with context); fall back
    // to the rule message; last resort is the rule id.
    const messageText = issue.latestLlmSummary ?? issue.latestRuleMessage ?? ruleId;

    const result: SarifResult = {
      ruleId,
      level,
      kind: isAbsence ? "informational" : "fail",
      message: { text: messageText },
      // `severity` is producer-side and intentionally kept in `properties`:
      // SARIF's `level` only spans 4 values (none/note/warning/error) and
      // can't carry our finer-grained 5-band scale. Lifecycle / triage are
      // RMS concerns and are deliberately omitted here.
      properties: {
        severity: issue.latestSeverity,
      },
    };

    // Only attach a physicalLocation when we have a real code site.
    // `__absence__:`-tagged issues describe missing controls, not a single
    // line — emitting a fake location confuses downstream tools.
    if (!isAbsence && issue.latestFilePath && issue.latestStartLine > 0) {
      const region: SarifRegion = { startLine: issue.latestStartLine };
      if (issue.latestEndLine && issue.latestEndLine !== issue.latestStartLine) {
        region.endLine = issue.latestEndLine;
      }
      // contextRegion covers what the worker stored from disk — 3 lines above
      // the match, the match span, and 3 lines below. File-line range is
      // `(startLine - 3) .. (startLine - 3 + N - 1)` where N is the number of
      // lines in the persisted snippet. Clamp the start at 1 so we don't emit
      // zero/negative line numbers when the match sits in the first few lines.
      let contextRegion: SarifRegion | undefined;
      if (issue.latestSnippet) {
        const snippetLineCount = issue.latestSnippet.split("\n").length;
        const ctxStart = Math.max(1, issue.latestStartLine - STORED_CONTEXT_LINES);
        contextRegion = {
          startLine: ctxStart,
          endLine: ctxStart + snippetLineCount - 1,
          snippet: { text: issue.latestSnippet },
        };
      }
      result.locations = [
        {
          physicalLocation: {
            artifactLocation: { uri: issue.latestFilePath },
            region,
            ...(contextRegion ? { contextRegion } : {}),
          },
        },
      ];
    }

    results.push(result);
  }

  // Attach CWE references to each rule via SARIF `relationships`. Single
  // canonical place for the rule→weakness mapping; results dereference
  // through `ruleId`.
  for (const [ruleId, cwes] of ruleCwes) {
    if (cwes.size === 0) continue;
    const rule = ruleById.get(ruleId);
    if (!rule) continue;
    rule.relationships = Array.from(cwes)
      .sort((a, b) => Number(a) - Number(b))
      .map((id) => ({
        target: { toolComponent: { name: CWE_TOOL_COMPONENT_NAME }, id },
        kinds: ["relevant"],
      }));
  }

  const driver: Record<string, unknown> = {
    name: TOOL_NAME,
    version: opts.toolVersion,
    informationUri: TOOL_INFO_URI,
    rules: Array.from(ruleById.values()),
  };
  if (opts.modelName) driver.semanticVersion = opts.modelName;

  const invocation: Record<string, unknown> = {
    executionSuccessful: true,
  };
  if (opts.startedAt) invocation.startTimeUtc = opts.startedAt.toISOString();
  if (opts.endedAt) invocation.endTimeUtc = opts.endedAt.toISOString();
  if (opts.scopePath) invocation.workingDirectory = { uri: opts.scopePath };

  // Declare the CWE taxonomy at the run level if any result references one.
  // SARIF §3.19 — `taxonomies` is an array of `toolComponent` objects, each
  // with its own `taxa[]`. We only list the CWEs we actually cite (so the
  // file stays small and `isComprehensive: false` is truthful).
  const taxonomies: SarifTaxonomy[] = [];
  if (citedCweIds.size > 0) {
    const taxa: SarifTaxon[] = Array.from(citedCweIds)
      .sort((a, b) => Number(a) - Number(b))
      .map((id) => ({
        id,
        helpUri: `https://cwe.mitre.org/data/definitions/${id}.html`,
      }));
    taxonomies.push({
      name: CWE_TOOL_COMPONENT_NAME,
      organization: "MITRE",
      informationUri: "https://cwe.mitre.org/",
      shortDescription: { text: "Common Weakness Enumeration" },
      isComprehensive: false,
      taxa,
    });
  }

  const run: Record<string, unknown> = {
    tool: { driver },
    invocations: [invocation],
    results,
  };
  if (taxonomies.length > 0) run.taxonomies = taxonomies;

  return {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [run],
  };
}
