import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './app/**/*.{js,ts,jsx,tsx}',
    './components/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        background: 'hsl(0, 0%, 100%)',
        foreground: 'hsl(222, 28%, 14%)',
        primary: 'hsl(203, 78%, 46%)',
        secondary: 'hsl(336, 72%, 58%)',
        accent: 'hsl(42, 86%, 52%)',
        muted: 'hsl(220, 30%, 96%)',
      },
      borderRadius: {
        lg: '0.5rem',
        xl: '1rem',
      },
    },
  },
  plugins: [],
}
export default config
