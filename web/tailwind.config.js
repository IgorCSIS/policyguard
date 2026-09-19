/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,js}"],
  theme: {
    extend: {
      /**
       * A security tool, not a cartoon SOC dashboard. Deep slate, one calm
       * teal accent, and the three decision colours kept distinct enough to
       * tell apart at a glance without relying on colour alone: every badge
       * also carries its word.
       */
      colors: {
        slate: {
          950: "#080D14", // page
          900: "#0D141E", // panel
          850: "#111A26", // card
          800: "#16212F", // raised
          700: "#223044", // hairline
          600: "#31435C", // hover
        },
        mist: {
          50: "#F6F8FA", // headings, 17.2:1 on slate-950
          200: "#C9D4E0", // body, 12.0:1
          400: "#8CA0B8", // muted, 6.5:1
        },
        teal: {
          300: "#5EEAD4", // accent on dark
          400: "#2DD4BF",
          500: "#14B8A6", // fill
        },
        verdict: {
          alert: "#F87171",
          "alert-bg": "#2B1417",
          allow: "#34D399",
          "allow-bg": "#0C2A22",
          ignore: "#94A3B8",
          "ignore-bg": "#161F2C",
        },
      },
      fontFamily: {
        // System stacks only. A web font would be a network request on a page
        // that promises the pasted log never leaves the browser.
        sans: ["system-ui", "-apple-system", "Segoe UI", "Roboto", "Helvetica", "Arial", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "SF Mono", "Menlo", "Consolas", "Liberation Mono", "monospace"],
      },
      borderRadius: { card: "0.75rem" },
    },
  },
  plugins: [],
};
