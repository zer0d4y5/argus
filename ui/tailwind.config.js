/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Severity ramp, tuned to read in both themes.
        sev: {
          critical: "#b91c1c",
          high: "#ea580c",
          medium: "#d97706",
          low: "#2563eb",
          info: "#6b7280",
        },
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
    },
  },
  plugins: [],
};
