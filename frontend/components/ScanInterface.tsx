'use client'

interface ScanInterfaceProps {
  mode: 'email' | 'url' | 'file' | null
  onClose: () => void
}

export default function ScanInterface({ mode, onClose }: ScanInterfaceProps) {
  if (!mode) return null

  return (
    <div className="cyber-card max-w-4xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold text-cyber-green-500">
          {mode === 'email' && '📧 Email Analysis'}
          {mode === 'url' && '🔗 URL Scanner'}
          {mode === 'file' && '📎 File Analysis'}
        </h2>
        <button 
          onClick={onClose}
          className="text-gray-400 hover:text-white transition-colors"
        >
          ✕
        </button>
      </div>
      
      <div className="text-center py-12 text-gray-400">
        <div className="text-6xl mb-4">🚧</div>
        <h3 className="text-xl mb-2">Interface Coming Soon</h3>
        <p>Advanced {mode} scanning interface will be available in the next update.</p>
      </div>
    </div>
  )
}