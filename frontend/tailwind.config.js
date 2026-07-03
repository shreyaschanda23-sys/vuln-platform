export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        bg: { DEFAULT: '#0a0a0b', surface: '#111113', elevated: '#18181b', border: '#27272a' },
        accent: { DEFAULT: '#22d3ee', dim: '#0e7490' },
        severity: { critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#2563eb', info: '#71717a' },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'ui-monospace', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
}