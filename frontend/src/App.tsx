import { useState } from 'react';
import { Shield, AlertTriangle, Activity, Zap, CheckCircle, BarChart3, FileText } from 'lucide-react';

const API_BASE_URL = 'http://localhost:8000';

interface VulnerabilitySummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

interface Vulnerability {
  id: string;
  title: string;
  severity: string;
  description: string;
  endpoint: string;
  evidence: string;
  recommendation: string;
}

interface ScanResult {
  scan_id: string;
  timestamp: string;
  target: string;
  api_type: string;
  duration: string;
  summary: VulnerabilitySummary;
  vulnerabilities: Vulnerability[];
  endpoints_tested: number;
  requests_sent: number;
  payloads_generated: number;
}

const VulnerabilityBadge = ({ severity }: { severity: string }) => {
  const colors: Record<string, string> = {
    critical: 'bg-red-100 text-red-800 border-red-300',
    high: 'bg-orange-100 text-orange-800 border-orange-300',
    medium: 'bg-yellow-100 text-yellow-800 border-yellow-300',
    low: 'bg-blue-100 text-blue-800 border-blue-300',
    info: 'bg-gray-100 text-gray-800 border-gray-300'
  };
  
  return (
    <span className={`px-2 py-1 rounded text-xs font-semibold border ${colors[severity] || colors.info}`}>
      {severity.toUpperCase()}
    </span>
  );
};

export default function APISecurityScanner() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [targetUrl, setTargetUrl] = useState('');
  const [apiType, setApiType] = useState('rest');
  const [authType, setAuthType] = useState('none');
  const [authToken, setAuthToken] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanResults, setScanResults] = useState<ScanResult | null>(null);
  const [scanHistory, setScanHistory] = useState<ScanResult[]>([]);
  const [error, setError] = useState<string | null>(null);

  const executeScan = async () => {
    setScanning(true);
    setScanProgress(0);
    setScanResults(null);
    setError(null);

    // Simulate progress updates
    const progressInterval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 90) return prev;
        return prev + 10;
      });
    }, 500);

    try {
      // Call the REAL backend API
      const response = await fetch(`${API_BASE_URL}/api/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          target_url: targetUrl,
          api_type: apiType,
          auth_type: authType,
          auth_token: authToken || null
        })
      });

      clearInterval(progressInterval);
      setScanProgress(100);

      if (!response.ok) {
        throw new Error(`Scan failed: ${response.statusText}`);
      }

      const result: ScanResult = await response.json();
      setScanResults(result);
      setScanHistory((prev) => [result, ...prev]);
    } catch (err) {
      clearInterval(progressInterval);
      setError(err instanceof Error ? err.message : 'Scan failed');
      console.error('Scan error:', err);
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 p-4 md:p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="bg-white rounded-lg shadow-lg border border-gray-200 p-6 mb-6">
          <div className="flex items-center gap-4 mb-2">
            <div className="bg-blue-600 rounded-lg p-3">
              <Shield className="w-8 h-8 text-white" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-gray-900">API Security Scanner</h1>
              <p className="text-gray-600">Automated OWASP API Top 10 vulnerability detection</p>
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 mb-6">
          <div className="flex border-b border-gray-200">
            {[
              { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
              { id: 'scanner', label: 'Scanner', icon: Zap },
              { id: 'history', label: 'History', icon: FileText }
            ].map(tab => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-2 px-6 py-4 font-semibold transition-colors ${
                    activeTab === tab.id
                      ? 'border-b-2 border-blue-600 text-blue-600'
                      : 'text-gray-600 hover:text-gray-900'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                  {tab.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Dashboard Tab */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-gradient-to-br from-blue-500 to-blue-600 rounded-lg shadow-lg p-6 text-white">
                <div className="flex items-center justify-between mb-4">
                  <Shield className="w-8 h-8" />
                  <span className="text-3xl font-bold">{scanHistory.length}</span>
                </div>
                <div className="text-sm font-medium opacity-90">Total Scans</div>
              </div>

              <div className="bg-gradient-to-br from-red-500 to-red-600 rounded-lg shadow-lg p-6 text-white">
                <div className="flex items-center justify-between mb-4">
                  <AlertTriangle className="w-8 h-8" />
                  <span className="text-3xl font-bold">
                    {scanHistory.reduce((sum, s) => sum + s.summary.critical + s.summary.high, 0)}
                  </span>
                </div>
                <div className="text-sm font-medium opacity-90">Critical + High Issues</div>
              </div>

              <div className="bg-gradient-to-br from-green-500 to-green-600 rounded-lg shadow-lg p-6 text-white">
                <div className="flex items-center justify-between mb-4">
                  <CheckCircle className="w-8 h-8" />
                  <span className="text-3xl font-bold">
                    {scanHistory.reduce((sum, s) => sum + s.endpoints_tested, 0)}
                  </span>
                </div>
                <div className="text-sm font-medium opacity-90">Endpoints Tested</div>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <h3 className="text-lg font-bold text-gray-900 mb-4">OWASP API Top 10 Coverage</h3>
              <div className="space-y-3">
                {[
                  'API1: Broken Object Level Authorization',
                  'API2: Broken Authentication',
                  'API3: Broken Object Property Level Authorization',
                  'API4: Unrestricted Resource Consumption',
                  'API5: Broken Function Level Authorization',
                  'API6: Unrestricted Access to Sensitive Business Flows',
                  'API7: Server Side Request Forgery',
                  'API8: Security Misconfiguration',
                  'API9: Improper Inventory Management',
                  'API10: Unsafe Consumption of APIs'
                ].map((item, idx) => (
                  <div key={idx} className="flex items-center gap-3">
                    <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0" />
                    <span className="text-sm text-gray-700">{item}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Scanner Tab */}
        {activeTab === 'scanner' && (
          <div className="space-y-6">
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <h2 className="text-xl font-bold text-gray-900 mb-4 flex items-center gap-2">
                <Zap className="w-5 h-5 text-blue-600" />
                Configure Security Scan
              </h2>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Target API URL
                  </label>
                  <input
                    type="text"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    placeholder="https://jsonplaceholder.typicode.com"
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    disabled={scanning}
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    Try: https://jsonplaceholder.typicode.com or https://reqres.in/api
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      API Type
                    </label>
                    <select
                      value={apiType}
                      onChange={(e) => setApiType(e.target.value)}
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                      disabled={scanning}
                    >
                      <option value="rest">REST API</option>
                      <option value="graphql">GraphQL</option>
                      <option value="soap">SOAP</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Authentication Type
                    </label>
                    <select
                      value={authType}
                      onChange={(e) => setAuthType(e.target.value)}
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                      disabled={scanning}
                    >
                      <option value="none">None</option>
                      <option value="bearer">Bearer Token</option>
                      <option value="basic">Basic Auth</option>
                      <option value="apikey">API Key</option>
                      <option value="oauth2">OAuth 2.0</option>
                    </select>
                  </div>
                </div>

                {authType !== 'none' && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Authentication Token/Key
                    </label>
                    <input
                      type="password"
                      value={authToken}
                      onChange={(e) => setAuthToken(e.target.value)}
                      placeholder="Enter token or credentials"
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                      disabled={scanning}
                    />
                  </div>
                )}

                <div className="flex gap-3 pt-4">
                  <button
                    onClick={executeScan}
                    disabled={!targetUrl || scanning}
                    className="flex-1 bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
                  >
                    {scanning ? (
                      <>
                        <Activity className="w-5 h-5 animate-spin" />
                        Scanning...
                      </>
                    ) : (
                      <>
                        <Shield className="w-5 h-5" />
                        Start Security Scan
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>

            {error && (
              <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                <div className="flex items-center gap-2 text-red-800">
                  <AlertTriangle className="w-5 h-5" />
                  <span className="font-semibold">Scan Error</span>
                </div>
                <p className="text-sm text-red-700 mt-1">{error}</p>
              </div>
            )}

            {scanning && (
              <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-sm">
                    <span className="font-medium text-gray-700">Scan Progress</span>
                    <span className="font-bold text-blue-600">{scanProgress}%</span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-3 overflow-hidden">
                    <div
                      className="bg-gradient-to-r from-blue-500 to-blue-600 h-full transition-all duration-500 ease-out"
                      style={{ width: `${scanProgress}%` }}
                    />
                  </div>
                  <p className="text-sm text-gray-600">
                    {scanProgress < 30 && "Discovering endpoints..."}
                    {scanProgress >= 30 && scanProgress < 60 && "Testing authentication..."}
                    {scanProgress >= 60 && scanProgress < 90 && "Fuzzing for vulnerabilities..."}
                    {scanProgress >= 90 && "Compiling results..."}
                  </p>
                </div>
              </div>
            )}

            {scanResults && (
              <div className="space-y-6">
                <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
                  <div className="grid grid-cols-3 gap-4 text-sm">
                    <div>
                      <span className="text-gray-600">Endpoints Tested:</span>
                      <span className="font-bold text-gray-900 ml-2">{scanResults.endpoints_tested}</span>
                    </div>
                    <div>
                      <span className="text-gray-600">Requests Sent:</span>
                      <span className="font-bold text-gray-900 ml-2">{scanResults.requests_sent}</span>
                    </div>
                    <div>
                      <span className="text-gray-600">Duration:</span>
                      <span className="font-bold text-gray-900 ml-2">{scanResults.duration}</span>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
                  {[
                    { label: 'Critical', count: scanResults.summary.critical },
                    { label: 'High', count: scanResults.summary.high },
                    { label: 'Medium', count: scanResults.summary.medium },
                    { label: 'Low', count: scanResults.summary.low },
                    { label: 'Info', count: scanResults.summary.info }
                  ].map(item => (
                    <div key={item.label} className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
                      <div className="text-2xl font-bold text-gray-900">{item.count}</div>
                      <div className="text-sm font-medium text-gray-600">{item.label}</div>
                    </div>
                  ))}
                </div>

                {scanResults.vulnerabilities.length > 0 ? (
                  <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                    <h3 className="text-lg font-bold text-gray-900 mb-4">Detected Vulnerabilities</h3>
                    <div className="space-y-4">
                      {scanResults.vulnerabilities.map((vuln, idx) => (
                        <div key={idx} className="border border-gray-200 rounded-lg p-4">
                          <div className="flex items-start justify-between mb-2">
                            <div className="flex items-center gap-3">
                              <AlertTriangle className="w-5 h-5 text-orange-500 flex-shrink-0" />
                              <div>
                                <h4 className="font-semibold text-gray-900">{vuln.title}</h4>
                                <p className="text-sm text-gray-500">{vuln.id}</p>
                              </div>
                            </div>
                            <VulnerabilityBadge severity={vuln.severity} />
                          </div>
                          <p className="text-sm text-gray-700 mb-2">{vuln.description}</p>
                          <div className="bg-gray-50 rounded p-3 space-y-2 text-sm">
                            <div>
                              <span className="font-medium text-gray-700">Endpoint:</span>
                              <code className="ml-2 text-blue-600">{vuln.endpoint}</code>
                            </div>
                            <div>
                              <span className="font-medium text-gray-700">Evidence:</span>
                              <span className="ml-2 text-gray-600">{vuln.evidence}</span>
                            </div>
                            <div>
                              <span className="font-medium text-gray-700">Fix:</span>
                              <span className="ml-2 text-gray-600">{vuln.recommendation}</span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="bg-green-50 border border-green-200 rounded-lg p-6 text-center">
                    <CheckCircle className="w-12 h-12 text-green-500 mx-auto mb-3" />
                    <h3 className="text-lg font-bold text-green-900 mb-2">No Vulnerabilities Found!</h3>
                    <p className="text-green-700">
                      The target API passed all OWASP API Top 10 security checks.
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* History Tab */}
        {activeTab === 'history' && (
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <h2 className="text-xl font-bold text-gray-900 mb-4 flex items-center gap-2">
              <FileText className="w-5 h-5 text-blue-600" />
              Scan History
            </h2>
            
            {scanHistory.length === 0 ? (
              <div className="text-center py-12 text-gray-500">
                <Shield className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p>No scans yet. Start your first security scan!</p>
              </div>
            ) : (
              <div className="space-y-3">
                {scanHistory.map((scan, idx) => (
                  <div
                    key={idx}
                    className="border border-gray-200 rounded-lg p-4 hover:border-blue-300 cursor-pointer transition-colors"
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="font-semibold text-gray-900">{scan.target}</div>
                        <div className="text-sm text-gray-500">
                          {new Date(scan.timestamp).toLocaleString()} • {scan.duration}
                        </div>
                        <div className="text-xs text-gray-500 mt-1">
                          {scan.requests_sent} requests • {scan.endpoints_tested} endpoints tested
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <span className="px-3 py-1 bg-red-100 text-red-800 rounded-full text-xs font-semibold">
                          {scan.summary.critical} Critical
                        </span>
                        <span className="px-3 py-1 bg-orange-100 text-orange-800 rounded-full text-xs font-semibold">
                          {scan.summary.high} High
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}