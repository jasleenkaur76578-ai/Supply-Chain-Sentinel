/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        sentinel: {
          bg: '#0B1120',
          sidebar: '#0F172A',
          card: '#111C30',
          elevated: '#17243A',
          border: '#1E293B',
          accent: '#38BDF8',
          accentIndigo: '#6366F1',
          critical: '#EF4444',
          high: '#F97316',
          medium: '#EAB308',
          low: '#22C55E',
          textPrimary: '#F8FAFC',
          textSecondary: '#94A3B8',
          textMuted: '#64748B',
        }
      }
    },
  },
  plugins: [],
}
