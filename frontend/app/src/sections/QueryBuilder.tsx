import { useState } from 'react';
import { Code, Play, Copy, Check, Download, Database, Plus, Trash2 } from 'lucide-react';

interface QueryBlock {
  id: string;
  type: 'index' | 'sourcetype' | 'time' | 'field' | 'stats' | 'where' | 'table';
  value: string;
}

const platforms = [
  { id: 'splunk', name: 'Splunk SPL' },
  { id: 'sentinel', name: 'Azure KQL' },
  { id: 'elastic', name: 'Elasticsearch' },
  { id: 'qradar', name: 'IBM QRadar AQL' },
];

export default function QueryBuilder() {
  const [selectedPlatform, setSelectedPlatform] = useState('splunk');
  const [blocks, setBlocks] = useState<QueryBlock[]>([
    { id: '1', type: 'index', value: 'windows' },
    { id: '2', type: 'sourcetype', value: 'WinEventLog:Security' },
  ]);
  const [generatedQuery, setGeneratedQuery] = useState('');
  const [copied, setCopied] = useState(false);

  const blockTypes = [
    { id: 'index', name: 'Index', placeholder: 'e.g., windows, firewall' },
    { id: 'sourcetype', name: 'Source Type', placeholder: 'e.g., WinEventLog' },
    { id: 'time', name: 'Time Range', placeholder: 'e.g., last 24h' },
    { id: 'field', name: 'Field', placeholder: 'e.g., EventCode=4625' },
    { id: 'where', name: 'Where Clause', placeholder: 'e.g., match(CommandLine, ".*")' },
    { id: 'stats', name: 'Stats', placeholder: 'e.g., count by User' },
    { id: 'table', name: 'Table', placeholder: 'e.g., _time, User, Computer' },
  ];

  const addBlock = (type: string) => {
    setBlocks([...blocks, { id: Date.now().toString(), type: type as any, value: '' }]);
  };

  const updateBlock = (id: string, value: string) => {
    setBlocks(blocks.map(b => b.id === id ? { ...b, value } : b));
  };

  const removeBlock = (id: string) => {
    setBlocks(blocks.filter(b => b.id !== id));
  };

  const generateQuery = () => {
    let query = '';
    
    switch (selectedPlatform) {
      case 'splunk':
        query = blocks.map(b => {
          switch (b.type) {
            case 'index': return `index=${b.value}`;
            case 'sourcetype': return `sourcetype="${b.value}"`;
            case 'time': return `earliest=-${b.value}`;
            case 'field': return b.value;
            case 'where': return `| where ${b.value}`;
            case 'stats': return `| stats ${b.value}`;
            case 'table': return `| table ${b.value}`;
            default: return '';
          }
        }).filter(Boolean).join(' ');
        break;
      case 'sentinel':
        query = blocks.map(b => {
          switch (b.type) {
            case 'index': return `${b.value}`;
            case 'field': return `| where ${b.value}`;
            case 'where': return `| where ${b.value}`;
            case 'stats': return `| summarize ${b.value}`;
            case 'table': return `| project ${b.value}`;
            default: return '';
          }
        }).filter(Boolean).join('\n');
        break;
      default:
        query = blocks.map(b => `${b.type}: ${b.value}`).join('\n');
    }
    
    setGeneratedQuery(query);
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(generatedQuery);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Query Builder</h1>
          <p className="text-gray-400 text-sm mt-1">Build detection queries for multiple SIEM platforms</p>
        </div>
        <select 
          value={selectedPlatform}
          onChange={(e) => setSelectedPlatform(e.target.value)}
          className="px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:border-cyan-400 focus:outline-none"
        >
          {platforms.map(p => (
            <option key={p.id} value={p.id}>{p.name}</option>
          ))}
        </select>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Block Builder */}
        <div className="lg:col-span-2 space-y-4">
          <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-4">
            <h3 className="font-semibold mb-4 flex items-center gap-2">
              <Database className="w-4 h-4 text-cyan-400" />
              Query Blocks
            </h3>
            
            <div className="space-y-3">
              {blocks.map((block) => (
                <div key={block.id} className="flex items-center gap-2">
                  <span className="w-24 text-sm text-gray-400 capitalize">{block.type}</span>
                  <input
                    type="text"
                    value={block.value}
                    onChange={(e) => updateBlock(block.id, e.target.value)}
                    placeholder={blockTypes.find(t => t.id === block.type)?.placeholder}
                    className="flex-1 px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none"
                  />
                  <button 
                    onClick={() => removeBlock(block.id)}
                    className="p-2 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>

            <div className="mt-4 pt-4 border-t border-white/5">
              <p className="text-sm text-gray-400 mb-3">Add Block:</p>
              <div className="flex flex-wrap gap-2">
                {blockTypes.map(type => (
                  <button
                    key={type.id}
                    onClick={() => addBlock(type.id)}
                    className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-cyan-500/20 text-sm text-gray-300 hover:text-cyan-400 transition-colors flex items-center gap-1"
                  >
                    <Plus className="w-3 h-3" />
                    {type.name}
                  </button>
                ))}
              </div>
            </div>

            <button 
              onClick={generateQuery}
              className="w-full mt-4 px-4 py-3 bg-gradient-to-r from-cyan-400 to-cyan-600 rounded-lg text-black font-medium hover:shadow-lg hover:shadow-cyan-500/25 transition-all flex items-center justify-center gap-2"
            >
              <Play className="w-4 h-4" />
              Generate Query
            </button>
          </div>
        </div>

        {/* Output */}
        <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-4">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold flex items-center gap-2">
              <Code className="w-4 h-4 text-cyan-400" />
              Generated Query
            </h3>
            <div className="flex items-center gap-2">
              <button 
                onClick={handleCopy}
                disabled={!generatedQuery}
                className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 transition-colors disabled:opacity-50"
              >
                {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
              </button>
              <button 
                disabled={!generatedQuery}
                className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 transition-colors disabled:opacity-50"
              >
                <Download className="w-4 h-4" />
              </button>
            </div>
          </div>
          
          <div className="bg-black/40 border border-white/10 rounded-lg p-4 min-h-[300px] font-mono text-sm overflow-x-auto">
            {generatedQuery || (
              <span className="text-gray-500">Click "Generate Query" to see results...</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
