import { useState } from 'react'
import DMARCChecker from './DMARCChecker'
import SPFChecker from './SPFChecker'
import DKIMChecker from './DKIMChecker'

function App() {
  const [activeTab, setActiveTab] = useState('spf')

  return (
    <div>
      <div className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-6xl mx-auto px-4">
          <div className="flex gap-1">
            <button
              onClick={() => setActiveTab('spf')}
              className={`px-6 py-4 font-semibold text-sm transition-colors relative ${
                activeTab === 'spf'
                  ? 'text-green-600 border-b-2 border-green-600'
                  : 'text-gray-600 hover:text-gray-800'
              }`}
            >
              SPF 검사
            </button>
            <button
                onClick={() => setActiveTab('dkim')}
                className={`px-6 py-4 font-semibold text-sm transition-colors relative ${
                    activeTab === 'dkim'
                        ? 'text-purple-600 border-b-2 border-purple-600'
                        : 'text-gray-600 hover:text-gray-800'
                }`}
            >
              DKIM 검사
            </button>
            <button
              onClick={() => setActiveTab('dmarc')}
              className={`px-6 py-4 font-semibold text-sm transition-colors relative ${
                activeTab === 'dmarc'
                  ? 'text-blue-600 border-b-2 border-blue-600'
                  : 'text-gray-600 hover:text-gray-800'
              }`}
            >
              DMARC 검사
            </button>
          </div>
        </div>
      </div>

      {activeTab === 'spf' ? <SPFChecker /> :
       activeTab === 'dmarc' ? <DMARCChecker /> :
       <DKIMChecker />}
    </div>
  )
}

export default App
