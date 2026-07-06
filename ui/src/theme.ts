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

// Finding-category palette. Keys are the model's category constants
// (SAST/SECRET/SCA/IAC/DAST); unknown categories get neutral fallbacks in the
// components, never dropped.
export const CATEGORY_LABEL: Record<string, string> = {
  SAST: "Code (SAST)",
  SECRET: "Secrets",
  SCA: "Dependencies (SCA)",
  IAC: "Infrastructure (IaC)",
  DAST: "Dynamic (DAST)",
  CLOUD: "Cloud posture",
};

export const CATEGORY_CHIP: Record<string, string> = {
  SAST: "bg-indigo-100 text-indigo-800 dark:bg-indigo-900/40 dark:text-indigo-300",
  SECRET: "bg-rose-100 text-rose-800 dark:bg-rose-900/40 dark:text-rose-300",
  SCA: "bg-cyan-100 text-cyan-800 dark:bg-cyan-900/40 dark:text-cyan-300",
  IAC: "bg-teal-100 text-teal-800 dark:bg-teal-900/40 dark:text-teal-300",
  DAST: "bg-purple-100 text-purple-800 dark:bg-purple-900/40 dark:text-purple-300",
  CLOUD: "bg-sky-100 text-sky-800 dark:bg-sky-900/40 dark:text-sky-300",
};

export const CATEGORY_COLOR: Record<string, string> = {
  SAST: "#4f46e5",
  SECRET: "#e11d48",
  SCA: "#0891b2",
  IAC: "#0d9488",
  DAST: "#9333ea",
  CLOUD: "#0284c7",
};

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
