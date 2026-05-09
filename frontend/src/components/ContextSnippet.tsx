// Code snippet renderer with a highlighted match span.
//
// Used by:
//   - SAST issue rows (LLM-emitted snippet around `start_line`)
//   - SCA issue rows (manifest file snippet around `manifest_line`)
//
// What the backend SHOULD have stored per the SAST detection prompt
// (3 lines above match + the match span + 3 lines below). The LLM is
// inconsistent about following this rule — sometimes it emits 20+ lines
// around the match. We treat 8 (3 + 2-line span + 3) as the canonical
// short-snippet length and fall back to a keyword-search heuristic when
// the snippet is longer.
const STORED_CONTEXT_LINES = 3;
// Lines of context shown above the first highlighted line and below the
// last. 3 each gives "before / span / after" visual orientation.
const DISPLAYED_CONTEXT_LINES = 3;
// Minimum shared leading-trimmed prefix for an adjacent line to count as
// structurally parallel to the anchor (e.g. two `#define DEFAULT_X_PW...`
// lines). Tuned to capture multi-line hardcoded-credential patterns
// without bridging into unrelated nearby code.
const PARALLEL_PREFIX_MIN = 8;

/**
 * Best-effort: locate ALL snippet lines that look like part of the issue's
 * span. Used when the LLM emitted more context than the prompt asked for,
 * so the simple "match line is at index STORED_CONTEXT_LINES" assumption
 * doesn't hold. We search for distinctive identifiers and content keywords
 * from the issue's summary. Returns the indices of every line that scores
 * at least one keyword hit, in document order. Empty array means nothing
 * matched and the caller should fall back to offset-from-top.
 */
function findAllKeywordMatchIndices(
  lines: string[],
  summary: string | null,
  ruleMessage: string | null,
): number[] {
  const summaryRaw = (summary ?? ruleMessage ?? "").trim();
  if (!summaryRaw) return [];

  // First pass: distinctive UPPER_SNAKE_CASE identifiers in the summary.
  // For a finding like "GS_SUPER_USER_PASSWORD ..." this nails every line
  // that mentions one. Strong signal — return all such hits, in order.
  const idents = summaryRaw.match(/[A-Z][A-Z0-9_]{3,}/g) ?? [];
  if (idents.length > 0) {
    const hits: number[] = [];
    for (let i = 0; i < lines.length; i++) {
      if (idents.some((id) => lines[i].includes(id))) hits.push(i);
    }
    if (hits.length > 0) return hits;
  }

  // Second pass: content keywords. Pick distinctive content words ≥5 chars,
  // skip common verbs/connectors. Naive trailing-s stemming so "passwords"
  // matches identifiers like GS_SUPER_USER_PASSWORD.
  const STOPWORDS = new Set([
    "allows", "enables", "exposes", "exploits", "grants", "leaves", "stores",
    "device", "system", "access", "remote", "attack", "attacker", "attackers",
    "unrestricted", "unauthenticated", "unauthorized",
    "potentially", "improperly", "without", "before", "after",
    "could", "would", "should", "their", "these", "those", "which",
    // Stems that fall out after singularizing
    "attacker", "exploit", "grant", "store",
  ]);
  const stem = (w: string): string =>
    w.length > 4 && w.endsWith("s") && !w.endsWith("ss") ? w.slice(0, -1) : w;

  const keywords = (summaryRaw.toLowerCase().match(/\b[a-z][a-z]{4,}\b/g) ?? [])
    .map(stem)
    .filter((w) => !STOPWORDS.has(w))
    .slice(0, 6);

  if (keywords.length === 0) return [];

  const scores: number[] = lines.map((line) => {
    const lower = line.toLowerCase();
    let s = 0;
    for (const kw of keywords) if (lower.includes(kw)) s++;
    return s;
  });
  const bestScore = Math.max(...scores);
  if (bestScore < 1) return [];
  return scores.flatMap((s, i) => (s === bestScore ? [i] : []));
}

/**
 * Renders a multi-line code snippet with the matching span highlighted.
 * `matchLine` is the 1-indexed file line number where the issue starts.
 *
 * Locating the match line within the snippet is hard because the LLM is
 * inconsistent about how much context it includes above the issue. The
 * prompt asks for "3 lines above start_line" but actual snippets have
 * anywhere from 0 to 20+ lines of preamble. Short snippets and long
 * snippets are both affected — so we always try keyword-search first,
 * falling back to "snippet[STORED_CONTEXT_LINES] is the match" only when
 * the search yields no hits.
 */
export function ContextSnippet({
  snippet,
  matchLine,
  className,
  summary,
  ruleMessage,
}: {
  snippet: string;
  matchLine: number;
  className?: string;
  summary?: string | null;
  ruleMessage?: string | null;
}) {
  const allLines = snippet.split("\n");

  let spanStart: number;
  if (allLines.length === 1) {
    spanStart = 0;
  } else {
    const hits = findAllKeywordMatchIndices(allLines, summary ?? null, ruleMessage ?? null);
    spanStart = hits.length > 0
      ? hits[0]
      : Math.min(STORED_CONTEXT_LINES, matchLine - 1);
  }

  // Extend forward through structurally parallel adjacent lines — i.e. lines
  // that share a substantial leading-whitespace-trimmed prefix with the
  // anchor. Two `#define DEFAULT_WAGSTAFF_..._PW` lines share enough prefix
  // to be highlighted together; an `if (...)` line that follows a
  // `kTest(...)` does not. Conservative: stop at the first non-match.
  let spanEnd = spanStart;
  const trimLeading = (s: string) => s.replace(/^\s+/, "");
  const anchorBody = trimLeading(allLines[spanStart] ?? "");
  if (anchorBody.length >= PARALLEL_PREFIX_MIN) {
    for (let j = spanStart + 1; j < allLines.length; j++) {
      const candidate = trimLeading(allLines[j]);
      let common = 0;
      while (
        common < anchorBody.length &&
        common < candidate.length &&
        anchorBody[common] === candidate[common]
      ) common++;
      if (common >= PARALLEL_PREFIX_MIN) {
        spanEnd = j;
      } else {
        break;
      }
    }
  }

  const startIdx = Math.max(0, spanStart - DISPLAYED_CONTEXT_LINES);
  const endIdx = Math.min(allLines.length, spanEnd + DISPLAYED_CONTEXT_LINES + 1);
  const lines = allLines.slice(startIdx, endIdx);
  const firstLineNumber = matchLine - (spanStart - startIdx);
  const hlStart = spanStart - startIdx;
  const hlEnd = spanEnd - startIdx;

  return (
    <div className={`overflow-x-auto rounded border bg-background text-xs font-mono ${className ?? ""}`}>
      <table className="w-full border-collapse">
        <tbody>
          {lines.map((line, i) => {
            const isMatch = i >= hlStart && i <= hlEnd;
            const isFirstMatch = i === hlStart;
            const lineNumber = firstLineNumber + i;
            return (
              <tr key={i} className={isMatch ? "bg-yellow-50 dark:bg-yellow-950/40" : ""}>
                <td className="select-none px-2 py-0.5 text-right text-muted-foreground/50 w-10 border-r border-border tabular-nums">
                  {lineNumber}
                </td>
                <td className="select-none px-1 py-0.5 text-center text-muted-foreground/60 w-4">
                  {isFirstMatch ? "→" : " "}
                </td>
                <td className={`px-3 py-0.5 whitespace-pre ${isMatch ? "font-semibold" : ""}`}>
                  {line || " "}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
