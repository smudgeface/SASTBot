// Code snippet renderer with a highlighted match span.
//
// Used by:
//   - SAST issue rows (latestSnippet around `latest_start_line`)
//   - SCA issue rows (manifest file snippet around `manifest_line`)
//
// Canonical snippet layout (worker-built, M6k onward):
//
//     SOURCE_CONTEXT_LINES lines above start_line
//   + the [start_line .. end_line] match span
//   + SOURCE_CONTEXT_LINES lines below end_line
//
// So the match span sits at offset `min(SOURCE_CONTEXT_LINES, start_line - 1)`
// within the snippet (the min handles top-of-file clamping). For data that
// pre-dates M6k, the snippet is whatever the LLM emitted — usually but not
// always canonical. The renderer trusts the offset; the worker startup
// backfill regenerates legacy rows from disk so they conform too.

const SOURCE_CONTEXT_LINES = 3;

export function ContextSnippet({
  snippet,
  matchLine,
  matchEndLine,
  className,
}: {
  snippet: string;
  /** 1-indexed first line of the problem in the source file. */
  matchLine: number;
  /** 1-indexed last line of the problem (inclusive). Defaults to `matchLine`
   *  for single-line problems. */
  matchEndLine?: number | null;
  className?: string;
}) {
  const allLines = snippet.split("\n");
  const lastLine = Math.max(matchLine, matchEndLine ?? matchLine);

  // Offset of the first matching line within the snippet. Clamped because
  // when matchLine is in the first few lines of a file, the snippet can't
  // include 3 leading context lines.
  const hlStart = Math.min(SOURCE_CONTEXT_LINES, matchLine - 1, allLines.length - 1);
  const hlEnd = Math.min(hlStart + (lastLine - matchLine), allLines.length - 1);

  // First snippet line corresponds to file line `matchLine - hlStart` because
  // the snippet was built with hlStart leading context lines.
  const firstFileLine = matchLine - hlStart;

  return (
    <div className={`overflow-x-auto rounded border bg-background text-xs font-mono ${className ?? ""}`}>
      <table className="w-full border-collapse">
        <tbody>
          {allLines.map((line, i) => {
            const isMatch = i >= hlStart && i <= hlEnd;
            const isFirstMatch = i === hlStart;
            const lineNumber = firstFileLine + i;
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
