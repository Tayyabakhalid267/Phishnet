import type { Metadata, Viewport } from 'next'
import './globals.css'
import { UserProvider } from './context/UserContext'
import ClientLayout from './ClientLayout'

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  themeColor: '#00ff88',
}

export const metadata: Metadata = {
  title: '🧠 PHISHNET - AI Cybersecurity Suite',
  description: 'Detect, analyze, visualize, and neutralize phishing in real time',
  keywords: 'cybersecurity, phishing, AI, threat intelligence, email security',
  authors: [{ name: 'PHISHNET Team' }],
  icons: {
    icon: [
      { url: '/favicon-16x16.png', sizes: '16x16', type: 'image/png' },
      { url: '/favicon-32x32.png', sizes: '32x32', type: 'image/png' },
    ],
    apple: [
      { url: '/apple-touch-icon.png', sizes: '180x180', type: 'image/png' },
    ],
  },
  openGraph: {
    title: '🧠 PHISHNET - AI Cybersecurity Suite',
    description: 'Advanced AI-powered phishing detection and analysis platform',
    url: 'https://phishnet.ai',
    siteName: 'PHISHNET',
    type: 'website',
    locale: 'en_US',
  },
  twitter: {
    card: 'summary_large_image',
    title: '🧠 PHISHNET - AI Cybersecurity Suite',
    description: 'Advanced AI-powered phishing detection and analysis platform',
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link 
          href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&family=JetBrains+Mono:wght@300;400;500;700&display=swap" 
          rel="stylesheet" 
        />
      </head>
      <body className="min-h-screen bg-cyber-dark text-white antialiased">
        <UserProvider>
          <ClientLayout>
            {/* Background matrix effect */}
            <div className="fixed inset-0 cyber-grid opacity-10 pointer-events-none" />
            
            {/* Main content */}
            <main className="relative z-10">
              {children}
            </main>
            
            {/* Global toast notifications would go here */}
            <div id="toast-root" />
          </ClientLayout>
        </UserProvider>
      </body>
    </html>
  )
}