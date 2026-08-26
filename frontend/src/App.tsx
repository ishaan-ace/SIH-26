import { useState, useEffect } from 'react';
import axios from 'axios';
import { Shield, Upload, AlertCircle, CheckCircle, Info, Bot } from 'lucide-react';
import ReactMarkdown from 'react-markdown';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000';

function App() {
  const [jobId, setJobId] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [sessions, setSessions] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiReport, setAiReport] = useState('');
  const [aiError, setAiError] = useState('');

  const handleUpload = async () => {
    if (!file) return;
    setLoading(true);
    setAiReport('');
    const formData = new FormData();
    formData.append('pcap', file);
    try {
      const res = await axios.post(`${API_URL}/api/upload`, formData);
      setJobId(res.data.jobId);
    } catch (err) {
      console.error(err);
      alert("Upload failed");
      setLoading(false);
    }
  };

  const pollResults = async () => {
    if (!jobId) return;
    try {
      const res = await axios.get(`${API_URL}/api/sessions/${jobId}`);
      const job = res.data;
      if (job && job.status === 'completed') {
        setSessions(job.sessions || []);
        setLoading(false);
      } else if (job && job.status === 'error') {
        alert("Analysis failed: " + job.error);
        setLoading(false);
        setJobId('');
      }
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    let interval: number;
    if (jobId && loading) {
      interval = setInterval(pollResults, 3000);
    }
    return () => clearInterval(interval);
  }, [jobId, loading]);

  const generateAIReport = async () => {
    setAiLoading(true);
    setAiError('');
    try {
      const res = await axios.post(`${API_URL}/api/ai-explain/${jobId}`);
      setAiReport(res.data.explanation);
    } catch (err: any) {
      console.error(err);
      setAiError(err.response?.data?.error || 'Failed to generate AI report.');
    } finally {
      setAiLoading(false);
    }
  };

  const riskCounts = sessions.reduce((acc, curr) => {
    acc[curr.riskLevel] = (acc[curr.riskLevel] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 font-sans p-6">
      <header className="flex items-center space-x-3 mb-8 border-b border-slate-700 pb-4">
        <Shield className="w-8 h-8 text-blue-500" />
        <h1 className="text-2xl font-bold tracking-wider">SecureMailScope</h1>
        <span className="bg-slate-800 text-xs px-2 py-1 rounded text-slate-400">SOC Analyst Dashboard</span>
      </header>

      {!jobId && (
        <div className="flex flex-col items-center justify-center p-12 bg-slate-800 rounded-lg border border-slate-700 shadow-xl max-w-2xl mx-auto mt-20">
          <Upload className="w-16 h-16 text-slate-500 mb-4" />
          <h2 className="text-xl mb-4 text-slate-300">Upload PCAP/PCAPNG File</h2>
          <input 
            type="file" 
            className="mb-4 text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:text-sm file:bg-blue-600 file:text-white hover:file:bg-blue-700"
            onChange={(e) => setFile(e.target.files?.[0] || null)}
          />
          <button 
            onClick={handleUpload}
            disabled={!file}
            className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-bold py-2 px-6 rounded transition-colors"
          >
            Analyze Network Traffic
          </button>
        </div>
      )}

      {loading && jobId && (
        <div className="flex flex-col items-center justify-center mt-20">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mb-4"></div>
          <p className="text-slate-400 animate-pulse">Forensic Engine Analyzing Packets...</p>
        </div>
      )}

      {sessions.length > 0 && !loading && (
        <div className="grid grid-cols-3 gap-6">
          <div className="col-span-2">
            {/* Dashboard Summary Cards */}
            <div className="grid grid-cols-4 gap-4 mb-8">
              <div className="bg-slate-800 p-4 rounded-lg border border-slate-700">
                <h3 className="text-slate-400 text-sm mb-1">Total Email Sessions</h3>
                <p className="text-3xl font-bold">{sessions.length}</p>
              </div>
              <div className="bg-slate-800 p-4 rounded-lg border border-red-900/50">
                <h3 className="text-red-400 text-sm mb-1">CRITICAL Risk</h3>
                <p className="text-3xl font-bold text-red-500">{riskCounts['CRITICAL'] || 0}</p>
              </div>
              <div className="bg-slate-800 p-4 rounded-lg border border-orange-900/50">
                <h3 className="text-orange-400 text-sm mb-1">HIGH Risk</h3>
                <p className="text-3xl font-bold text-orange-500">{riskCounts['HIGH'] || 0}</p>
              </div>
              <div className="bg-slate-800 p-4 rounded-lg border border-green-900/50">
                <h3 className="text-green-400 text-sm mb-1">LOW Risk</h3>
                <p className="text-3xl font-bold text-green-500">{riskCounts['LOW'] || 0}</p>
              </div>
            </div>

            <h2 className="text-xl font-bold mb-4 border-b border-slate-700 pb-2">Session Investigation</h2>
            <div className="grid grid-cols-1 gap-4 h-[600px] overflow-y-auto pr-2">
              {sessions.map((s, idx) => (
                <div key={idx} className="bg-slate-800 rounded-lg p-5 border border-slate-700 flex justify-between items-center">
                  <div>
                    <div className="flex items-center space-x-3 mb-2">
                      <span className="font-mono text-blue-400 text-lg">{s.protocol}</span>
                      <span className="text-slate-500">|</span>
                      <span className="font-mono text-sm text-slate-300">{s.client} ➔ {s.server}</span>
                    </div>
                    <div className="flex items-center space-x-4 text-sm mt-3">
                      <div className={`flex items-center space-x-1 ${s.starttls ? 'text-green-400' : 'text-red-400'}`}>
                        {s.starttls ? <CheckCircle className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
                        <span>STARTTLS {s.starttls ? 'Detected' : 'Missing'}</span>
                      </div>
                      {s.tls && (
                        <>
                          <div className="flex items-center space-x-1 text-blue-300">
                            <Info className="w-4 h-4" />
                            <span>{s.tls.version}</span>
                          </div>
                          <div className="text-slate-400 text-xs font-mono bg-slate-900 px-2 py-1 rounded">
                            {s.tls.cipher_suite}
                          </div>
                        </>
                      )}
                    </div>
                  </div>
                  <div className="flex flex-col items-end">
                    <span className={`px-3 py-1 rounded font-bold text-sm ${s.riskLevel === 'CRITICAL' ? 'bg-red-500/20 text-red-500' : s.riskLevel === 'HIGH' ? 'bg-orange-500/20 text-orange-500' : 'bg-green-500/20 text-green-500'}`}>
                      Risk: {s.riskLevel} ({s.riskScore}/100)
                    </span>
                    {s.findings && s.findings.length > 0 && (
                      <div className="mt-2 flex gap-1">
                        {s.findings.map((f: string, i: number) => (
                          <span key={i} className="text-xs bg-slate-700 text-slate-300 px-2 py-0.5 rounded">{f}</span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
          
          {/* AI Intelligence Panel */}
          <div className="col-span-1 bg-slate-800 rounded-lg border border-slate-700 p-5 flex flex-col h-[750px]">
            <div className="flex items-center space-x-2 mb-4 border-b border-slate-700 pb-2">
              <Bot className="w-6 h-6 text-purple-400" />
              <h2 className="text-xl font-bold">AI Intelligence</h2>
            </div>
            
            {!aiReport && !aiLoading && (
              <div className="flex flex-col items-center justify-center flex-grow text-center p-4">
                <p className="text-slate-400 mb-4">Generate an AI-powered SOC report to explain these findings and recommend remediations.</p>
                <button 
                  onClick={generateAIReport}
                  className="bg-purple-600 hover:bg-purple-700 text-white font-bold py-2 px-4 rounded transition-colors w-full"
                >
                  Generate AI Report
                </button>
                {aiError && <p className="text-red-400 text-sm mt-4">{aiError}</p>}
              </div>
            )}

            {aiLoading && (
              <div className="flex flex-col items-center justify-center flex-grow">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-500 mb-4"></div>
                <p className="text-slate-400">Consulting Knowledge Base...</p>
              </div>
            )}

            {aiReport && (
              <div className="flex-grow overflow-y-auto text-sm text-slate-300 prose prose-invert pr-2">
                <ReactMarkdown>{aiReport}</ReactMarkdown>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
