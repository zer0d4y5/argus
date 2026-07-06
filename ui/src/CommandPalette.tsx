import { useEffect, useMemo, useRef, useState } from "react";

// A command the palette can run. `group` buckets it under a heading; `keywords`
// widens what the fuzzy match will catch beyond the visible label.
export type Command = {
  id: string;
  label: string;
  group: string;
  run: () => void;
  hint?: string;
  keywords?: string;
};

// subsequenceScore returns a match rank for `query` against `text` (lower is
// better), or null when the query isn't a subsequence. A run of adjacent
// matches and a match at a word boundary both score better, so "sev" ranks
// "Filter severity" above an incidental scatter of s/e/v.
function subsequenceScore(query: string, text: string): number | null {
  if (!query) return 0;
  const q = query.toLowerCase();
  const t = text.toLowerCase();
  let ti = 0;
  let score = 0;
  let prevMatch = -2;
  for (let qi = 0; qi < q.length; qi++) {
    const ch = q[qi];
    const found = t.indexOf(ch, ti);
    if (found === -1) return null;
    score += found; // earlier matches are cheaper
    if (found !== prevMatch + 1) score += 4; // reward contiguous runs
    if (found > 0 && /\s/.test(t[found - 1])) score -= 2; // reward word starts
    prevMatch = found;
    ti = found + 1;
  }
  return score;
}

export function CommandPalette({
  open,
  onClose,
  commands,
}: {
  open: boolean;
  onClose: () => void;
  commands: Command[];
}) {
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // Reset each time it opens, and move focus into the input.
  useEffect(() => {
    if (open) {
      setQuery("");
      setActive(0);
      // rAF so the element exists and the browser doesn't scroll the page.
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  const results = useMemo(() => {
    const scored = commands
      .map((c) => ({ c, s: subsequenceScore(query, `${c.label} ${c.keywords ?? ""}`) }))
      .filter((x): x is { c: Command; s: number } => x.s !== null)
      .sort((a, b) => a.s - b.s || a.c.label.length - b.c.label.length);
    return scored.map((x) => x.c);
  }, [commands, query]);

  // Keep the active index in range as results shrink.
  useEffect(() => {
    setActive((a) => Math.min(a, Math.max(0, results.length - 1)));
  }, [results.length]);

  // Scroll the active row into view on arrow navigation.
  useEffect(() => {
    const el = listRef.current?.querySelector<HTMLElement>(`[data-idx="${active}"]`);
    el?.scrollIntoView({ block: "nearest" });
  }, [active]);

  if (!open) return null;

  const run = (c: Command | undefined) => {
    if (!c) return;
    onClose();
    c.run();
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => Math.min(a + 1, results.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      run(results[active]);
    } else if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    }
  };

  // Group results, preserving the score order within each group.
  const groups: { name: string; items: { c: Command; idx: number }[] }[] = [];
  results.forEach((c, idx) => {
    let g = groups.find((x) => x.name === c.group);
    if (!g) {
      g = { name: c.group, items: [] };
      groups.push(g);
    }
    g.items.push({ c, idx });
  });

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-gray-950/40 px-4 pt-[12vh] backdrop-blur-sm motion-safe:animate-[fadeIn_120ms_ease-out]"
      onMouseDown={onClose}
      role="presentation"
    >
      <div
        className="w-full max-w-xl overflow-hidden rounded-lg border border-gray-300 bg-white shadow-float dark:border-gray-700 dark:bg-gray-900 motion-safe:animate-[popIn_120ms_ease-out]"
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        onMouseDown={(e) => e.stopPropagation()}
        onKeyDown={onKeyDown}
      >
        <input
          ref={inputRef}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Jump to a target, filter, view, or action…"
          className="w-full border-b border-gray-200 bg-transparent px-4 py-3 text-sm outline-none placeholder:text-gray-400 dark:border-gray-800"
          spellCheck={false}
          autoComplete="off"
        />
        <div ref={listRef} className="scroll-thin max-h-80 overflow-y-auto py-1">
          {results.length === 0 ? (
            <div className="px-4 py-6 text-center text-sm text-gray-500">No matches for “{query}”.</div>
          ) : (
            groups.map((g) => (
              <div key={g.name} className="py-1">
                <div className="px-4 py-1 text-[10px] font-semibold uppercase tracking-wide text-gray-400">
                  {g.name}
                </div>
                {g.items.map(({ c, idx }) => (
                  <button
                    key={c.id}
                    data-idx={idx}
                    onMouseMove={() => setActive(idx)}
                    onClick={() => run(c)}
                    className={`flex w-full items-center gap-3 px-4 py-1.5 text-left text-sm ${
                      idx === active
                        ? "bg-accent-100 text-accent-800 dark:bg-accent-500/15 dark:text-accent-100"
                        : "text-gray-700 dark:text-gray-200"
                    }`}
                  >
                    <span className="min-w-0 flex-1 truncate">{c.label}</span>
                    {c.hint && (
                      <span className="shrink-0 font-mono text-[11px] text-gray-400">{c.hint}</span>
                    )}
                  </button>
                ))}
              </div>
            ))
          )}
        </div>
        <div className="flex items-center gap-4 border-t border-gray-200 px-4 py-1.5 text-[10px] text-gray-400 dark:border-gray-800">
          <span>
            <kbd className="font-mono">↑↓</kbd> navigate
          </span>
          <span>
            <kbd className="font-mono">↵</kbd> run
          </span>
          <span>
            <kbd className="font-mono">esc</kbd> close
          </span>
        </div>
      </div>
    </div>
  );
}
