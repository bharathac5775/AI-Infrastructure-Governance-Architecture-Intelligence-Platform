import type { Config } from "tailwindcss";

// Design tokens live as CSS variables in index.css; Tailwind maps to them so
// light/dark themes swap by toggling a class on <html>. Neutral zinc palette +
// a single indigo accent used with discipline (primary, active, links, focus).
const config: Config = {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    container: {
      center: true,
      padding: "2rem",
      screens: { "2xl": "1400px" },
    },
    extend: {
      colors: {
        border: "hsl(var(--border))",
        "border-strong": "hsl(var(--border-strong))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        surface: "hsl(var(--surface))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
          hover: "hsl(var(--primary-hover))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        // Restrained semantic colors — used on small badges only, never cards.
        danger: "hsl(var(--danger))",
        warning: "hsl(var(--warning))",
        info: "hsl(var(--info))",
        success: "hsl(var(--success))",
      },
      borderRadius: {
        lg: "12px",
        md: "10px",
        sm: "8px",
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      boxShadow: {
        // Soft shadows only where elevation is real (menus/popovers/modals).
        overlay:
          "0 12px 32px -8px rgb(0 0 0 / 0.20), 0 4px 12px -6px rgb(0 0 0 / 0.14)",
        drawer: "-16px 0 48px -16px rgb(0 0 0 / 0.28)",
      },
      transitionTimingFunction: {
        // Linear's signature easing — quick out, gentle settle.
        smooth: "cubic-bezier(0.32, 0.72, 0, 1)",
      },
      transitionDuration: {
        "175": "175ms",
      },
      fontSize: {
        // Tighter, more deliberate scale than Tailwind defaults.
        "2xs": ["0.6875rem", { lineHeight: "1rem", letterSpacing: "0.01em" }],
      },
      keyframes: {
        "fade-in": { from: { opacity: "0" }, to: { opacity: "1" } },
        "fade-in-up": {
          from: { opacity: "0", transform: "translateY(4px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        "slide-in-right": {
          from: { transform: "translateX(100%)" },
          to: { transform: "translateX(0)" },
        },
        "scale-in": {
          from: { opacity: "0", transform: "scale(0.97)" },
          to: { opacity: "1", transform: "scale(1)" },
        },
      },
      animation: {
        "fade-in": "fade-in 150ms ease-out",
        "fade-in-up": "fade-in-up 200ms cubic-bezier(0.32, 0.72, 0, 1)",
        "slide-in-right": "slide-in-right 200ms cubic-bezier(0.32, 0.72, 0, 1)",
        "scale-in": "scale-in 150ms cubic-bezier(0.32, 0.72, 0, 1)",
      },
    },
  },
  plugins: [],
};

export default config;
