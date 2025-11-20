/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // 🔥 STUNNING RED CYBERPUNK PALETTE 🔥
        cyber: {
          dark: '#0f0000',
          darker: '#080000',
          blood: '#1a0000',
          crimson: '#2d0000',
          red: {
            50: '#ffe6e6',
            100: '#ffb3b3', 
            200: '#ff8080',
            300: '#ff4d4d',
            400: '#ff1a1a',
            500: '#ff0040', // Main neon red
            600: '#e6003a',
            700: '#cc0033',
            800: '#b3002d',
            900: '#990026',
          },
          orange: {
            50: '#fff5e6',
            100: '#ffe6b3',
            200: '#ffd680',
            300: '#ffc74d',
            400: '#ffb81a',
            500: '#ff6b35', // Warning orange
            600: '#e65a2e',
            700: '#cc4927',
            800: '#b33820',
            900: '#992719',
          },
          purple: {
            50: '#f3e6ff',
            100: '#d9b3ff',
            200: '#bf80ff',
            300: '#a64dff',
            400: '#8c1aff',
            500: '#7300e6',
            600: '#5c00b3',
            700: '#450080',
            800: '#2e004d',
            900: '#17001a',
          },
          green: {
            50: '#e6ffe6',
            100: '#b3ffb3',
            200: '#80ff80',
            300: '#4dff4d',
            400: '#1aff1a',
            500: '#00ff88', // Main neon green
            600: '#00e673',
            700: '#00cc5e',
            800: '#00b349',
            900: '#009934',
          },
          blue: {
            50: '#e6f3ff',
            100: '#b3d9ff',
            200: '#80bfff',
            300: '#4da6ff',
            400: '#1a8cff',
            500: '#0066ff', // Main neon blue
            600: '#005ce6',
            700: '#0052cc',
            800: '#0047b3',
            900: '#003d99',
          }
        },
        // Glass effect colors
        glass: {
          light: 'rgba(255, 255, 255, 0.05)',
          medium: 'rgba(255, 255, 255, 0.1)',
          dark: 'rgba(0, 0, 0, 0.2)',
        }
      },
      fontFamily: {
        'cyber': ['JetBrains Mono', 'Monaco', 'Cascadia Code', 'Roboto Mono', 'monospace'],
        'display': ['Roboto', 'Inter', 'system-ui', 'sans-serif'],
      },
      animation: {
        'glow': 'glow 2s ease-in-out infinite alternate',
        'pulse-neon': 'pulse-neon 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'float': 'float 3s ease-in-out infinite',
        'radar': 'radar 2s linear infinite',
        'breathe': 'breathe 4s ease-in-out infinite',
        'scan-line': 'scan-line 2s linear infinite',
      },
      keyframes: {
        glow: {
          '0%': { 
            'box-shadow': '0 0 5px theme(colors.cyber.green.500), 0 0 10px theme(colors.cyber.green.500), 0 0 15px theme(colors.cyber.green.500)'
          },
          '100%': { 
            'box-shadow': '0 0 10px theme(colors.cyber.green.500), 0 0 20px theme(colors.cyber.green.500), 0 0 30px theme(colors.cyber.green.500)'
          },
        },
        'pulse-neon': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.5' },
        },
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-10px)' },
        },
        radar: {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
        breathe: {
          '0%, 100%': { transform: 'scale(1)' },
          '50%': { transform: 'scale(1.05)' },
        },
        'scan-line': {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' },
        },
      },
      backdropBlur: {
        'xs': '2px',
      },
      boxShadow: {
        'neon-green': '0 0 5px theme(colors.cyber.green.500), 0 0 20px theme(colors.cyber.green.500/50)',
        'neon-red': '0 0 5px theme(colors.cyber.red.500), 0 0 20px theme(colors.cyber.red.500/50)',
        'neon-blue': '0 0 5px theme(colors.cyber.blue.500), 0 0 20px theme(colors.cyber.blue.500/50)',
        'glass': '0 8px 32px 0 rgba(31, 38, 135, 0.37)',
        'cyber': '0 0 10px rgba(0, 255, 136, 0.3), inset 0 0 10px rgba(0, 255, 136, 0.1)',
      },
      backgroundImage: {
        'cyber-grid': 'linear-gradient(rgba(0, 255, 136, 0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 255, 136, 0.1) 1px, transparent 1px)',
        'cyber-gradient': 'linear-gradient(135deg, rgba(10, 14, 39, 0.9) 0%, rgba(5, 8, 18, 0.95) 100%)',
        'glass-gradient': 'linear-gradient(135deg, rgba(255, 255, 255, 0.1) 0%, rgba(255, 255, 255, 0.05) 100%)',
      },
      backgroundSize: {
        'grid': '20px 20px',
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
    function({ addUtilities }) {
      const newUtilities = {
        '.glass-morphism': {
          'background': 'rgba(255, 255, 255, 0.05)',
          'backdrop-filter': 'blur(10px)',
          'border': '1px solid rgba(255, 255, 255, 0.1)',
          'box-shadow': '0 8px 32px 0 rgba(31, 38, 135, 0.37)',
        },
        '.cyber-border': {
          'border': '1px solid rgba(0, 255, 136, 0.3)',
          'box-shadow': '0 0 10px rgba(0, 255, 136, 0.1)',
        },
        '.text-glow': {
          'text-shadow': '0 0 10px currentColor',
        },
        '.neon-glow': {
          'filter': 'drop-shadow(0 0 10px currentColor)',
        },
      }
      addUtilities(newUtilities)
    }
  ],
}