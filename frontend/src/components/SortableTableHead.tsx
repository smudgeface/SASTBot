import { ArrowDown, ArrowUp, ChevronsUpDown } from "lucide-react";

import { TableHead } from "@/components/ui/table";
import { cn } from "@/lib/utils";

export type SortDir = "asc" | "desc";

export type SortState<K extends string> = {
  sort_by: K | undefined;
  sort_dir: SortDir;
};

interface SortableTableHeadProps<K extends string>
  extends React.ThHTMLAttributes<HTMLTableCellElement> {
  /** Column key this header represents (matches the backend's sort_by enum). */
  columnKey: K;
  /** Currently active sort state. */
  state: SortState<K>;
  /** Called when the header is clicked. Caller decides the cycle:
   *  this component just emits the target column + direction. */
  onSort: (next: SortState<K>) => void;
  /** Human-readable column label. */
  children: React.ReactNode;
}

/**
 * Column header that toggles between three states on click:
 *   1. Inactive → ascending on this column
 *   2. Ascending → descending on this column
 *   3. Descending → cleared (sort_by=undefined; backend reverts to default)
 *
 * Visual: ▲ when ascending, ▼ when descending, faded ⇅ when inactive.
 * Hover highlights the entire cell to telegraph clickability.
 */
export function SortableTableHead<K extends string>({
  columnKey,
  state,
  onSort,
  children,
  className,
  ...rest
}: SortableTableHeadProps<K>) {
  const isActive = state.sort_by === columnKey;
  const dir = isActive ? state.sort_dir : null;

  const handleClick = () => {
    if (!isActive) {
      onSort({ sort_by: columnKey, sort_dir: "asc" });
    } else if (state.sort_dir === "asc") {
      onSort({ sort_by: columnKey, sort_dir: "desc" });
    } else {
      onSort({ sort_by: undefined, sort_dir: "asc" });
    }
  };

  return (
    <TableHead
      {...rest}
      className={cn(
        "cursor-pointer select-none hover:bg-muted/30 group",
        isActive && "text-foreground",
        className,
      )}
      onClick={handleClick}
    >
      <span className="inline-flex items-center gap-1">
        {children}
        {dir === "asc" ? (
          <ArrowUp className="h-3 w-3" />
        ) : dir === "desc" ? (
          <ArrowDown className="h-3 w-3" />
        ) : (
          <ChevronsUpDown className="h-3 w-3 opacity-30 group-hover:opacity-70" />
        )}
      </span>
    </TableHead>
  );
}
