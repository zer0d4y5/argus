import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ThreatModelDetail, LibraryComponent } from "../api";

const NODE_W = 160;
const NODE_H = 54;
const BND_W = 300;
const BND_H = 220;
const BND_MIN_W = 140;
const BND_MIN_H = 90;
const CANVAS_W = 1200;
const CANVAS_H = 640;
const KINDS: { kind: string; label: string }[] = [
  { kind: "component", label: "Component" },
  { kind: "asset", label: "Asset" },
  { kind: "external-entity", label: "External" },
  { kind: "boundary", label: "Trust boundary" },
];
// Zone types for a trust boundary, stored in the component's `tech` field (which
// carries no meaning for a boundary otherwise). Values are lowercase because the
// server lowercases tech; labels are what the canvas shows.
const BOUNDARY_TYPES: { value: string; label: string }[] = [
  { value: "dmz", label: "DMZ" },
  { value: "vpc", label: "VPC / VNet" },
  { value: "subnet", label: "Subnet" },
  { value: "on-prem", label: "On-prem" },
  { value: "internet", label: "Internet / public" },
  { value: "cloud-account", label: "Cloud account" },
  { value: "cluster", label: "Kubernetes cluster" },
];
function boundaryTypeLabel(tech?: string): string {
  if (!tech) return "";
  return BOUNDARY_TYPES.find((b) => b.value === tech)?.label ?? tech.toUpperCase();
}

function clamp(v: number, min: number, max: number) {
  return Math.max(min, Math.min(max, v));
}

type Geom = { x: number; y: number; w: number; h: number };

export function ThreatCanvas({
  detail, canEdit, library,
  onSavePositions, onAddComponent, onUpdateComponent, onDeleteComponent,
  onAddFlow, onRemoveFlow, onSelectComponent,
}: {
  detail: ThreatModelDetail;
  canEdit: boolean;
  library: LibraryComponent[];
  onSavePositions: (positions: { componentId: string; x: number; y: number; w?: number; h?: number }[]) => void;
  onAddComponent: (kind: string, x: number, y: number) => void;
  onUpdateComponent: (id: string, req: { name: string; tech?: string; kind?: string }) => void;
  onDeleteComponent: (id: string) => void;
  onAddFlow: (fromId: string, toId: string, label: string) => void;
  onRemoveFlow: (flowId: string) => void;
  onSelectComponent?: (id: string) => void;
}): JSX.Element {
  const [geom, setGeom] = useState<Record<string, Geom>>({});
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [addMode, setAddMode] = useState<string | null>(null); // a kind to place, or null
  const [flowMode, setFlowMode] = useState(false);
  const [flowLabel, setFlowLabel] = useState("");
  const [flowFrom, setFlowFrom] = useState<string | null>(null);

  const svgRef = useRef<SVGSVGElement>(null);
  const dragId = useRef<string | null>(null);
  const dragOff = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const dragStart = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const live = useRef<Geom | null>(null);       // live geometry of the node under manipulation
  const resizeId = useRef<string | null>(null); // set while resizing a boundary

  const kindOf = useCallback((id: string) => detail.components.find((c) => c.id === id)?.kind ?? "component", [detail.components]);
  const defW = (kind: string) => (kind === "boundary" ? BND_W : NODE_W);
  const defH = (kind: string) => (kind === "boundary" ? BND_H : NODE_H);

  // One initializer per model: seed saved geometry, auto-lay the unplaced ones.
  useEffect(() => {
    const next: Record<string, Geom> = {};
    detail.components.forEach((c) => {
      if (c.x >= 0 && c.y >= 0) next[c.id] = { x: c.x, y: c.y, w: c.w > 0 ? c.w : defW(c.kind), h: c.h > 0 ? c.h : defH(c.kind) };
    });
    let bi = 0;
    detail.components.filter((c) => c.kind === "boundary" && !next[c.id]).forEach((c) => {
      next[c.id] = { x: 40 + bi * 340, y: 40, w: c.w > 0 ? c.w : BND_W, h: c.h > 0 ? c.h : BND_H };
      bi++;
    });
    let ni = 0;
    detail.components.filter((c) => c.kind !== "boundary" && !next[c.id]).forEach((c) => {
      next[c.id] = { x: 40 + (ni % 5) * 220, y: 320 + Math.floor(ni / 5) * 110, w: defW(c.kind), h: defH(c.kind) };
      ni++;
    });
    setGeom(next);
    setFlowFrom(null);
    setFlowMode(false);
    setAddMode(null);
    setFlowLabel("");
    setSelectedId(null);
  }, [detail.id, detail.components]);

  const threatCounts = useMemo(() => {
    const m: Record<string, number> = {};
    detail.threats.forEach((t) => { if (t.componentId) m[t.componentId] = (m[t.componentId] || 0) + 1; });
    return m;
  }, [detail.threats]);

  const svgPoint = (e: { clientX: number; clientY: number }) => {
    const svg = svgRef.current!;
    const pt = svg.createSVGPoint();
    pt.x = e.clientX; pt.y = e.clientY;
    return pt.matrixTransform(svg.getScreenCTM()!.inverse());
  };
  const g = useCallback((id: string): Geom => geom[id] || { x: 0, y: 0, w: NODE_W, h: NODE_H }, [geom]);

  const startDrag = useCallback((e: React.PointerEvent, id: string) => {
    // In add mode a node click is ignored (you're placing on the background).
    // In flow mode we DO track the press so a click can pick source/target;
    // handleUp decides drag-vs-flowpick by distance.
    if (!canEdit || addMode) return;
    e.preventDefault();
    e.stopPropagation();
    try { (e.target as Element).setPointerCapture(e.pointerId); } catch { /* gone */ }
    const p = svgPoint(e);
    const cur = g(id);
    dragOff.current = { x: p.x - cur.x, y: p.y - cur.y };
    dragStart.current = { x: p.x, y: p.y };
    dragId.current = id;
    live.current = cur;
  }, [canEdit, flowMode, addMode, g]);

  const startResize = useCallback((e: React.PointerEvent, id: string) => {
    if (!canEdit) return;
    e.preventDefault();
    e.stopPropagation();
    try { (e.target as Element).setPointerCapture(e.pointerId); } catch { /* gone */ }
    resizeId.current = id;
    live.current = g(id);
  }, [canEdit, g]);

  const handleMove = useCallback((e: React.PointerEvent) => {
    const p = svgPoint(e);
    if (resizeId.current) {
      const id = resizeId.current;
      const cur = g(id);
      const w = clamp(p.x - cur.x, BND_MIN_W, CANVAS_W - cur.x);
      const h = clamp(p.y - cur.y, BND_MIN_H, CANVAS_H - cur.y);
      const next = { ...cur, w, h };
      live.current = next;
      setGeom((prev) => ({ ...prev, [id]: next }));
      return;
    }
    const id = dragId.current;
    if (!id) return;
    const cur = g(id);
    const next = {
      ...cur,
      x: clamp(p.x - dragOff.current.x, 0, CANVAS_W - cur.w),
      y: clamp(p.y - dragOff.current.y, 0, CANVAS_H - cur.h),
    };
    live.current = next;
    setGeom((prev) => ({ ...prev, [id]: next }));
  }, [g]);

  const handleUp = useCallback((e: React.PointerEvent) => {
    const p = svgPoint(e);
    if (resizeId.current) {
      const id = resizeId.current;
      resizeId.current = null;
      const fin = live.current;
      live.current = null;
      if (fin) onSavePositions([{ componentId: id, x: fin.x, y: fin.y, w: fin.w, h: fin.h }]);
      return;
    }
    const id = dragId.current;
    if (!id) return;
    try { (e.target as Element).releasePointerCapture(e.pointerId); } catch { /* released */ }
    const dist = Math.hypot(p.x - dragStart.current.x, p.y - dragStart.current.y);
    dragId.current = null;
    const fin = live.current;
    live.current = null;
    if (dist > 3 && fin) {
      onSavePositions([{ componentId: id, x: fin.x, y: fin.y }]);
      return;
    }
    // A click (no move): flow-pick, or select.
    if (flowMode) {
      if (kindOf(id) === "boundary") return;
      if (!flowFrom) setFlowFrom(id);
      else if (flowFrom !== id) { onAddFlow(flowFrom, id, flowLabel); setFlowFrom(null); setFlowLabel(""); setFlowMode(false); }
      return;
    }
    setSelectedId(id);
    onSelectComponent?.(id);
  }, [flowMode, flowFrom, flowLabel, kindOf, onSavePositions, onAddFlow, onSelectComponent]);

  // Click on the empty canvas (the background grid rect, which sits above the
  // <svg> and below every node): place a node in add mode, else deselect. Node
  // and boundary groups handle their own pointerup and don't bubble here.
  const handleBackgroundUp = useCallback((e: React.PointerEvent) => {
    if (addMode && canEdit) {
      const p = svgPoint(e);
      const w = defW(addMode), h = defH(addMode);
      onAddComponent(addMode, clamp(p.x - w / 2, 0, CANVAS_W - w), clamp(p.y - h / 2, 0, CANVAS_H - h));
      setAddMode(null);
      return;
    }
    setSelectedId(null);
  }, [addMode, canEdit, onAddComponent]);

  const selected = detail.components.find((c) => c.id === selectedId) || null;
  const boundaries = detail.components.filter((c) => c.kind === "boundary");
  const nodes = detail.components.filter((c) => c.kind !== "boundary");

  if (detail.components.length === 0 && !canEdit) {
    return <div className="flex h-[560px] items-center justify-center rounded-lg border border-gray-200 bg-gray-50/50 dark:border-gray-800 dark:bg-gray-950/40"><p className="text-sm text-gray-500">No components to draw yet.</p></div>;
  }

  return (
    <div className="rounded-lg border border-gray-200 bg-gray-50/50 dark:border-gray-800 dark:bg-gray-950/40">
      {canEdit && (
        <div className="flex flex-wrap items-center gap-2 border-b border-gray-200 p-2 text-xs dark:border-gray-800">
          <span className="text-gray-400">Add:</span>
          {KINDS.map((k) => (
            <button key={k.kind} onClick={() => { setAddMode(addMode === k.kind ? null : k.kind); setFlowMode(false); }}
              className={`rounded px-2 py-1 ${addMode === k.kind ? "bg-accent-600 text-white" : "border border-gray-300 dark:border-gray-700"}`}>
              {k.label}
            </button>
          ))}
          <span className="mx-1 h-4 w-px bg-gray-200 dark:bg-gray-700" />
          <button onClick={() => { setFlowMode(!flowMode); setAddMode(null); setFlowFrom(null); }}
            className={`rounded px-2 py-1 ${flowMode ? "bg-accent-600 text-white" : "border border-gray-300 dark:border-gray-700"}`}>Add flow</button>
          {flowMode && (
            <input value={flowLabel} onChange={(e) => setFlowLabel(e.target.value)} placeholder="flow label (optional)"
              className="min-w-0 flex-1 rounded-md border border-gray-300 bg-white px-2 py-1 text-xs dark:border-gray-700 dark:bg-gray-900" />
          )}
          <span className="text-gray-400">
            {addMode ? "click the canvas to place it" : flowMode ? (flowFrom ? "click the target node" : "click a source node") : "click a node to edit; drag to move"}
          </span>
        </div>
      )}

      <div className="overflow-auto">
        <svg
          ref={svgRef}
          viewBox={`0 0 ${CANVAS_W} ${CANVAS_H}`}
          className="w-full"
          style={{ height: 560, cursor: addMode ? "crosshair" : "default" }}
        >
          <defs>
            <marker id="tc-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">
              <path d="M 0 0 L 10 5 L 0 10 z" className="fill-gray-400 dark:fill-gray-600" />
            </marker>
            <pattern id="tc-grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" className="stroke-gray-200/60 dark:stroke-gray-800/50" strokeWidth="1" />
            </pattern>
          </defs>
          {/* Background hit-target (the whole plane is clickable, unlike the
              grid pattern whose thin lines only paint slivers) + visual grid. */}
          <rect x="0" y="0" width={CANVAS_W} height={CANVAS_H} fill="transparent" style={{ pointerEvents: "all" }} onPointerUp={handleBackgroundUp} />
          <rect x="0" y="0" width={CANVAS_W} height={CANVAS_H} fill="url(#tc-grid)" style={{ pointerEvents: "none" }} />

          {/* Boundaries (behind) */}
          {boundaries.map((c) => {
            const b = g(c.id);
            const sel = selectedId === c.id;
            return (
              <g key={c.id} onPointerDown={(e) => startDrag(e, c.id)} onPointerMove={handleMove} onPointerUp={handleUp} style={{ cursor: canEdit ? "grab" : "default" }}>
                <rect x={b.x} y={b.y} width={b.w} height={b.h} rx={12} className={`fill-amber-500/5 ${sel ? "stroke-accent-500" : "stroke-amber-500/50"}`} strokeWidth={sel ? 2 : 1.5} strokeDasharray="6 4" />
                <text x={b.x + 10} y={b.y + 18} className="fill-amber-600 dark:fill-amber-400" fontSize={11} fontWeight={600}>{c.name}</text>
                {c.tech && (
                  <text x={b.x + b.w - 10} y={b.y + 18} textAnchor="end" className="fill-amber-500 dark:fill-amber-500/90" fontSize={10} fontWeight={700} letterSpacing={0.5}>{boundaryTypeLabel(c.tech).toUpperCase()}</text>
                )}
                {canEdit && sel && (
                  <rect x={b.x + b.w - 12} y={b.y + b.h - 12} width={12} height={12} className="fill-accent-500" style={{ cursor: "nwse-resize" }}
                    onPointerDown={(e) => startResize(e, c.id)} onPointerMove={handleMove} onPointerUp={handleUp} />
                )}
              </g>
            );
          })}

          {/* Flows */}
          {detail.flows.map((f) => {
            const fp = geom[f.fromId], tp = geom[f.toId];
            if (!fp || !tp) return null;
            const cx1 = fp.x + fp.w / 2, cy1 = fp.y + fp.h / 2;
            const cx2 = tp.x + tp.w / 2, cy2 = tp.y + tp.h / 2;
            const dxc = cx2 - cx1, dyc = cy2 - cy1;
            const dist = Math.hypot(dxc, dyc) || 1;
            const off = dist > 100 ? 40 : 0;
            const nx = dxc / dist, ny = dyc / dist;
            const x1 = cx1 + nx * off, y1 = cy1 + ny * off;
            const x2 = cx2 - nx * off, y2 = cy2 - ny * off;
            const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
            return (
              <g key={f.id}>
                <line x1={x1} y1={y1} x2={x2} y2={y2} className="stroke-gray-400 dark:stroke-gray-600" strokeWidth={1.2} markerEnd="url(#tc-arrow)" />
                {f.label && <text x={mx} y={my - 5} textAnchor="middle" className="fill-gray-500" fontSize={10}>{f.label}</text>}
                {canEdit && <text x={mx + 12} y={my - 5} className="fill-gray-400 hover:fill-red-600 cursor-pointer" fontSize={10} onClick={() => onRemoveFlow(f.id)}>✕</text>}
              </g>
            );
          })}

          {/* Nodes */}
          {nodes.map((c) => {
            const b = g(c.id);
            const isFlowSource = flowFrom === c.id;
            const sel = selectedId === c.id;
            const rx = c.kind === "asset" ? 20 : 8;
            const dash = c.kind === "external-entity" ? "4 3" : undefined;
            return (
              <g key={c.id} onPointerDown={(e) => startDrag(e, c.id)} onPointerMove={handleMove} onPointerUp={handleUp} style={{ cursor: canEdit ? "grab" : "pointer" }}>
                <rect x={b.x} y={b.y} width={b.w} height={b.h} rx={rx}
                  className={`fill-white dark:fill-gray-900 ${isFlowSource || sel ? "stroke-accent-500" : "stroke-gray-300 dark:stroke-gray-700"}`}
                  strokeWidth={isFlowSource || sel ? 2 : 1} strokeDasharray={dash} />
                <text x={b.x + 10} y={b.y + 22} className="fill-gray-900 dark:fill-gray-100" fontSize={12} fontWeight={600}>{c.name.length > 20 ? c.name.slice(0, 20) + "…" : c.name}</text>
                {c.tech && <text x={b.x + 10} y={b.y + 40} className="fill-gray-400" fontSize={10}>{c.tech}</text>}
                {threatCounts[c.id] ? (
                  <>
                    <circle cx={b.x + b.w - 4} cy={b.y + 4} r={9} className="fill-red-600" />
                    <text x={b.x + b.w - 4} y={b.y + 8} textAnchor="middle" className="fill-white" fontSize={10}>{threatCounts[c.id]}</text>
                  </>
                ) : null}
              </g>
            );
          })}
        </svg>
      </div>

      {/* Edit bar for the selected node */}
      {canEdit && selected && (
        <div className="flex flex-wrap items-center gap-2 border-t border-gray-200 p-2 text-xs dark:border-gray-800">
          <span className="text-gray-400">Selected</span>
          <input
            key={selected.id + "-name"}
            defaultValue={selected.name}
            onBlur={(e) => { const v = e.target.value.trim(); if (v && v !== selected.name) onUpdateComponent(selected.id, { name: v, tech: selected.tech, kind: selected.kind }); }}
            onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLInputElement).blur()}
            className="w-40 rounded-md border border-gray-300 bg-white px-2 py-1 dark:border-gray-700 dark:bg-gray-800" />
          <select value={selected.kind} onChange={(e) => onUpdateComponent(selected.id, { name: selected.name, tech: selected.tech, kind: e.target.value })}
            className="rounded-md border border-gray-300 bg-white px-2 py-1 dark:border-gray-700 dark:bg-gray-800">
            {KINDS.map((k) => <option key={k.kind} value={k.kind}>{k.label}</option>)}
          </select>
          {selected.kind === "boundary" ? (
            <select value={selected.tech ?? ""} onChange={(e) => onUpdateComponent(selected.id, { name: selected.name, tech: e.target.value, kind: selected.kind })}
              className="rounded-md border border-gray-300 bg-white px-2 py-1 dark:border-gray-700 dark:bg-gray-800" title="Zone type">
              <option value="">zone type…</option>
              {BOUNDARY_TYPES.map((b) => <option key={b.value} value={b.value}>{b.label}</option>)}
            </select>
          ) : (
            <select value={selected.tech ?? ""} onChange={(e) => onUpdateComponent(selected.id, { name: selected.name, tech: e.target.value, kind: selected.kind })}
              className="rounded-md border border-gray-300 bg-white px-2 py-1 dark:border-gray-700 dark:bg-gray-800" title="Technology">
              <option value="">tech…</option>
              {library.map((l) => <option key={l.tech} value={l.tech}>{l.title}</option>)}
            </select>
          )}
          <button onClick={() => { onDeleteComponent(selected.id); setSelectedId(null); }} className="ml-auto rounded-md border border-gray-300 px-2 py-1 text-red-600 hover:bg-red-50 dark:border-gray-700 dark:text-red-400 dark:hover:bg-red-950/30">Delete node</button>
        </div>
      )}
    </div>
  );
}
