import { useEffect, useMemo, useRef, useState } from "react";
import { Command, Search, XCircle } from "lucide-react";
import { searchDesktopCommands, type DesktopCommand } from "../commandCatalog";

export function CommandPalette({ open, onClose, onExecute }: { open: boolean; onClose: () => void; onExecute: (command: DesktopCommand) => void }) {
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const commands = useMemo(() => searchDesktopCommands(query), [query]);

  useEffect(() => {
    if (!open) return;
    setQuery("");
    setActiveIndex(0);
    window.setTimeout(() => inputRef.current?.focus(), 0);
  }, [open]);

  if (!open) return null;
  const choose = (item: DesktopCommand | undefined) => {
    if (!item) return;
    onExecute(item);
    onClose();
  };

  return (
    <div className="command-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <section className="command-palette" role="dialog" aria-modal="true" aria-label="Fabric command palette">
        <header>
          <Command size={18} />
          <input
            ref={inputRef}
            value={query}
            onChange={(event) => { setQuery(event.target.value); setActiveIndex(0); }}
            onKeyDown={(event) => {
              if (event.key === "Escape") onClose();
              if (event.key === "ArrowDown") { event.preventDefault(); setActiveIndex((value) => Math.min(commands.length - 1, value + 1)); }
              if (event.key === "ArrowUp") { event.preventDefault(); setActiveIndex((value) => Math.max(0, value - 1)); }
              if (event.key === "Enter") { event.preventDefault(); choose(commands[activeIndex]); }
            }}
            placeholder="Search commands and platform alternatives"
            aria-label="Search Fabric commands"
            aria-controls="fabric-command-results"
            aria-activedescendant={commands[activeIndex] ? `command-${commands[activeIndex].id}` : undefined}
          />
          <button onClick={onClose} aria-label="Close command palette" title="Close"><XCircle size={17} /></button>
        </header>
        <div className="command-results" id="fabric-command-results" role="listbox">
          {commands.map((item, index) => (
            <button
              id={`command-${item.id}`}
              key={item.id}
              role="option"
              aria-selected={index === activeIndex}
              className={index === activeIndex ? "active" : ""}
              onMouseMove={() => setActiveIndex(index)}
              onClick={() => choose(item)}
            >
              <Search size={14} />
              <span><strong>{item.label}</strong><small>{item.alternative ?? `${item.category} · ${item.availability}`}</small></span>
              <em>{item.category}</em>
            </button>
          ))}
          {commands.length === 0 && <p>No commands match “{query}”.</p>}
        </div>
        <footer><span>↑↓ navigate</span><span>Enter run</span><span>Esc close</span><span>Ctrl+Shift+P open</span></footer>
      </section>
    </div>
  );
}
