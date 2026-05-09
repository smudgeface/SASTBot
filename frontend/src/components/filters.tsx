import { cn } from "@/lib/utils";

/** Vertical pipe separator between filter groups. */
export function Pipe() {
  return <div className="self-stretch w-px bg-border mx-1" />;
}

/**
 * Segmented control filter group — items share a connected border, no "|"
 * separators inside the group. Multiple can be active simultaneously; an
 * empty active set means "show all".
 */
export function FilterGroup<T extends string>({
  items,
  active,
  onToggle,
  label,
  colorFn,
}: {
  items: readonly T[];
  active: ReadonlySet<T>;
  onToggle: (v: T) => void;
  label?: (v: T) => string;
  colorFn?: (v: T) => string;
}) {
  return (
    <div className="flex items-center">
      {items.map((item, i) => {
        const isFirst = i === 0;
        const isLast = i === items.length - 1;
        const isActive = active.has(item);
        return (
          <button
            key={item}
            onClick={() => onToggle(item)}
            className={cn(
              "relative px-2 py-0.5 text-xs font-medium border transition-colors",
              isFirst ? "rounded-l-sm" : "-ml-px",
              isLast ? "rounded-r-sm" : "",
              isActive
                ? cn("z-10", colorFn ? colorFn(item) : "bg-accent text-accent-foreground border-border")
                : "border-border/50 text-muted-foreground hover:bg-muted/30 hover:text-foreground hover:z-10",
            )}
          >
            {label ? label(item) : item}
          </button>
        );
      })}
    </div>
  );
}

/**
 * Group of independent boolean toggles — no "|" separators, items sit side
 * by side with a small gap. Use when the toggles are unrelated (e.g.
 * "include resolved" + "show dev only").
 */
export function ToggleGroup({
  items,
}: {
  items: { key: string; label: string; active: boolean; onToggle: () => void }[];
}) {
  return (
    <div className="flex items-center gap-1.5">
      {items.map(({ key, label, active, onToggle }) => (
        <button
          key={key}
          onClick={onToggle}
          className={`rounded px-2 py-0.5 text-xs border transition-colors ${
            active
              ? "bg-accent text-accent-foreground border-border"
              : "border-transparent text-muted-foreground hover:border-border hover:text-foreground"
          }`}
        >
          {label}
        </button>
      ))}
    </div>
  );
}
