import { Severity } from "./api";

// Severity → hex, matching tailwind.config.js `sev` ramp, for recharts (which
// needs literal colors, not classes).
export const SEV_COLOR: Record<Severity, string> = {
  critical: "#b91c1c",
  high: "#ea580c",
  medium: "#d97706",
  low: "#2563eb",
  info: "#6b7280",
};

// Tailwind classes for severity chips.
export const SEV_CHIP: Record<Severity, string> = {
  critical: "bg-red-700 text-white",
  high: "bg-orange-600 text-white",
  medium: "bg-amber-600 text-white",
  low: "bg-blue-600 text-white",
  info: "bg-gray-500 text-white",
};

// OWASP category palette (10 distinct hues, colorblind-considerate ordering).
export const OWASP_COLORS = [
  "#2563eb", "#7c3aed", "#db2777", "#dc2626", "#ea580c",
  "#ca8a04", "#16a34a", "#0891b2", "#4f46e5", "#9333ea",
];

export const VERDICT_LABEL: Record<string, string> = {
  "true-positive": "True positive",
  "false-positive": "False positive",
  uncertain: "Uncertain",
};

export const VERDICT_CHIP: Record<string, string> = {
  "true-positive": "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300",
  "false-positive": "bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300",
  uncertain: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300",
};

export function fmtTime(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function riskColor(score: number): string {
  if (score >= 9) return "#b91c1c";
  if (score >= 7) return "#ea580c";
  if (score >= 4) return "#d97706";
  return "#2563eb";
}
