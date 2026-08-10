/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx}",
  ],
  theme: {
    extend: {
      colors: {
        base: {
          bg: "#0B0F14",       // page background
          surface: "#131A22",  // cards, panels
          border: "#1E2730",
        },
        ink: {
          DEFAULT: "#E5E9F0",  // primary text
          muted: "#8A94A6",    // secondary text
        },
        signal: {
          DEFAULT: "#00D9C0",  // primary accent — links, active states, "scan" actions
          dim: "#0A9E8E",
        },
        risk: {
          low: "#3FB950",
          medium: "#D4A72C",
          high: "#F0883E",
          critical: "#F85149",
        },
      },
      fontFamily: {
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
      },
    },
  },
  plugins: [],
};