import { useState } from 'react';
import { FileText, Upload, Play, Copy, Check, Trash2, Search } from 'lucide-react';

interface ParsedLog {
  id: string;
  timestamp: string;
  level: 'info' | 'warning' | 'error' | 'critical';
  source: string;
  message: string;
}

export default function LogParser() {
  const [inputLogs, setInputLogs] = useState('');
  const [parsedLogs, setParsedLogs] = useState<ParsedLog[]>([]);
  const [parserType, setParserType] = useState('auto');
  const [isParsing, setIsParsing] = useState(false);
  const [filterQuery, setFilterQuery] = useState('');
  const [copied, setCopied] = useState(false);

  const sampleLogs = `2024-03-12 14:23:15 [INFO] Authentication successful for user: admin@corp.local from IP: 192.168.1.100
2024-03-12 14:23:45 [WARNING] Multiple failed login attempts detected for user: guest
2024-03-12 14:24:12 [ERROR] Database connection timeout - retrying...
2024-03-12 14:25:01 [INFO] Scheduled backup completed successfully
2024-03-12 14:26:33 [CRITICAL] Suspicious process detected: powershell.exe -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMQAwAA==`;

  const handleParse = () => {
    if (!inputLogs.trim()) return;
    setIsParsing(true);
    
    setTimeout(() => {
      const lines = inputLogs.split('\n').filter(line => line.trim());
      const parsed: ParsedLog[] = lines.map((line, idx) => {
        const timestamp = line.match(/(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/)?.[1] || 'Unknown';
        const level = (line.match(/\[(INFO|WARNING|ERROR|CRITICAL)\]/i)?.[1].toLowerCase() || 'info') as any;
        const message = line.replace(/.*\[.*?\]\s*/, '').trim();
        
        return {
          id: `LOG-${String(idx + 1).padStart(4, '0')}`,
          timestamp,
          level,
          source: 'Parsed Log',
          message
        };
      });
      
      setParsedLogs(parsed);
      setIsParsing(false);
    }, 500);
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(JSON.stringify(parsedLogs, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleLoadSample = () => {
    setInputLogs(sampleLogs);
  };

  const handleClear = () => {
    setInputLogs('');
    setParsedLogs([]);
  };

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'info': return 'text-blue-400 bg-blue-400/10';
      case 'warning': return 'text-yellow-400 bg-yellow-400/10';
      case 'error': return 'text-red-400 bg-red-400/10';
      case 'critical': return 'text-purple-400 bg-purple-400/10';
      default: return 'text-gray-400';
    }
  };

  const filteredLogs = parsedLogs.filter(log => 
    log.message.toLowerCase().includes(filterQuery.toLowerCase()) ||
    log.timestamp.includes(filterQuery)
  );

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Log Parser</h1>
          <p className="text-gray-400 text-sm mt-1">Parse and analyze log files in various formats</p>
        </div>
        <div className="flex items-center gap-3">
          <button onClick={handleLoadSample} className="px-4 py-2 bg-white/5 border border-white/10 rounded-lg text-sm font-medium hover:bg-white/10 transition-all flex items-center gap-2">
            <FileText className="w-4 h-4" />
            Load Sample
          </button>
          <button onClick={handleClear} className="px-4 py-2 bg-white/5 border border-white/10 rounded-lg text-sm font-medium hover:bg-white/10 transition-all flex items-center gap-2">
            <Trash2 className="w-4 h-4" />
            Clear
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input Section */}
        <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-4">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold flex items-center gap-2">
              <Upload className="w-4 h-4 text-cyan-400" />
              Input Logs
            </h3>
            <select 
              value={parserType}
              onChange={(e) => setParserType(e.target.value)}
              className="px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-sm text-white focus:border-cyan-400 focus:outline-none"
            >
              <option value="auto">Auto Detect</option>
              <option value="syslog">Syslog</option>
              <option value="json">JSON</option>
              <option value="csv">CSV</option>
              <option value="windows">Windows Event</option>
            </select>
          </div>
          <textarea
            value={inputLogs}
            onChange={(e) => setInputLogs(e.target.value)}
            placeholder="Paste your logs here..."
            rows={20}
            className="w-full px-4 py-3 bg-black/40 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none font-mono text-sm resize-none"
          />
          <button 
            onClick={handleParse}
            disabled={!inputLogs.trim() || isParsing}
            className="w-full mt-4 px-4 py-3 bg-gradient-to-r from-cyan-400 to-cyan-600 rounded-lg text-black font-medium hover:shadow-lg hover:shadow-cyan-500/25 transition-all disabled:opacity-50 flex items-center justify-center gap-2"
          >
            {isParsing ? (
              <div className="w-4 h-4 border-2 border-black/30 border-t-black rounded-full animate-spin" />
            ) : (
              <Play className="w-4 h-4" />
            )}
            Parse Logs
          </button>
        </div>

        {/* Output Section */}
        <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-4">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold flex items-center gap-2">
              <FileText className="w-4 h-4 text-cyan-400" />
              Parsed Results ({filteredLogs.length})
            </h3>
            <div className="flex items-center gap-2">
              <div className="relative">
                <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                <input
                  type="text"
                  placeholder="Filter..."
                  value={filterQuery}
                  onChange={(e) => setFilterQuery(e.target.value)}
                  className="pl-8 pr-4 py-2 bg-black/40 border border-white/10 rounded-lg text-sm text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none w-40"
                />
              </div>
              <button 
                onClick={handleCopy}
                disabled={!parsedLogs.length}
                className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 transition-colors disabled:opacity-50"
              >
                {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
          </div>
          
          <div className="space-y-2 max-h-[500px] overflow-auto">
            {filteredLogs.map((log) => (
              <div key={log.id} className="p-3 rounded-lg bg-white/5 border border-white/5">
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-xs font-mono text-gray-500">{log.id}</span>
                  <span className={`px-2 py-0.5 text-xs rounded-full ${getLevelColor(log.level)}`}>
                    {log.level}
                  </span>
                  <span className="text-xs text-gray-400">{log.timestamp}</span>
                </div>
                <p className="text-sm text-gray-300">{log.message}</p>
              </div>
            ))}
            {filteredLogs.length === 0 && parsedLogs.length > 0 && (
              <p className="text-center text-gray-500 py-8">No logs match your filter</p>
            )}
            {parsedLogs.length === 0 && (
              <p className="text-center text-gray-500 py-8">Parse logs to see results</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
