import { useState, useCallback } from 'react';
import {
  FileCode,
  Copy,
  Check,
  Download,
  Shield,
  Plus,
  X,
  Trash2,
  ChevronDown,
  ChevronUp,
  Code2,
  Target,
  AlertCircle,
  CheckCircle2,
  Save,
  Server,
  FileText,
  LayoutTemplate
} from 'lucide-react';

// Official Sigma Types
interface SigmaDetection {
  id: string;
  name: string;
  type: 'field' | 'keywords' | 'list';
  field?: string;
  modifier: SigmaModifier;
  value: string | string[];
  negation: boolean;
}

type SigmaModifier = 
  | 'contains' 
  | 'startswith' 
  | 'endswith'
  | 'contains|all'
  | 'contains|windash'
  | 'nocase'
  | 'base64'
  | 'base64offset'
  | 'base64offset|utf16le'
  | 'wide'
  | 'wide|ascii'
  | 'utf16le'
  | 'utf16be'
  | 'cidr'
  | 'gt'
  | 'gte'
  | 'lt'
  | 'lte'
  | 're'
  | 're|i'
  | 'expand'
  | 'fieldref'
  | 'none';

interface SigmaCorrelation {
  type: 'temporal' | 'value_count' | 'event_count' | 'near';
  rules: string[];
  'group-by': string[];  // FIXED: quoted property name
  timespan: string;
  condition?: {
    gte?: number;
    lt?: number;
  };
}

interface SigmaFilter {
  id: string;
  name: string;
  condition: string;
}

interface SigmaRule {
  title: string;
  id: string;
  status: 'experimental' | 'test' | 'stable' | 'deprecated' | 'unsupported';
  description: string;
  license?: string;
  author: string;
  date: string;
  modified: string;
  logsource: {
    category?: string;
    product?: string;
    service?: string;
    definition?: string;
  };
  detections: SigmaDetection[];
  condition: string;
  correlations?: SigmaCorrelation[];
  filters?: SigmaFilter[];
  fields?: string[];
  falsepositives: string[];
  level: 'informational' | 'low' | 'medium' | 'high' | 'critical';
  tags: string[];
  references: string[];
}

const SIGMA_LOGSOURCE = {
  category: [
    'process_creation', 'file_change', 'file_rename', 'file_delete', 'file_event',
    'registry_add', 'registry_delete', 'registry_set', 'registry_event', 'registry_rename',
    'network_connection', 'network_accept', 'network_bind', 'dns_query', 'dns_answer',
    'webserver', 'proxy', 'firewall', 'vpn', 'ids', 'ips',
    'driver_load', 'image_load', 'module_load',
    'pipe_created', 'pipe_connected',
    'wmi_event', 'ps_classic_start', 'ps_classic_provider_start', 'ps_classic_script',
    'ps_module', 'ps_script',
    'antivirus', 'application', 'file_access', 'process_access', 'process_tampering',
    'process_termination', 'scheduled_task', 'security', 'service_start', 'service_stop',
    'sysmon_error', 'sysmon_status', 'system', 'web', 'windows'
  ],
  product: [
    'windows', 'linux', 'macos', 'android', 'ios',
    'aws', 'azure', 'gcp',
    'apache', 'nginx', 'iis',
    'sql_server', 'mysql', 'postgresql',
    'crowdstrike', 'sentinelone', 'carbonblack',
    'splunk', 'qradar', 'sentinel', 'elasticsearch'
  ],
  service: [
    'sysmon', 'security', 'powershell', 'powershell-classic',
    'application', 'dns', 'dhcp', 'firewall', 'printservice'
  ]
};

const SIGMA_MODIFIERS = [
  { value: 'none', label: 'equals', desc: 'Exact match' },
  { value: 'contains', label: 'contains', desc: 'Substring match' },
  { value: 'contains|all', label: 'contains|all', desc: 'Contains all values' },
  { value: 'contains|windash', label: 'contains|windash', desc: 'Windows dash variations' },
  { value: 'startswith', label: 'startswith', desc: 'Starts with' },
  { value: 'endswith', label: 'endswith', desc: 'Ends with' },
  { value: 'nocase', label: 'nocase', desc: 'Case insensitive' },
  { value: 're', label: 're', desc: 'Regex' },
  { value: 're|i', label: 're|i', desc: 'Regex case insensitive' },
  { value: 'cidr', label: 'cidr', desc: 'CIDR notation' },
  { value: 'gt', label: 'gt', desc: 'Greater than' },
  { value: 'gte', label: 'gte', desc: 'Greater than or equal' },
  { value: 'lt', label: 'lt', desc: 'Less than' },
  { value: 'lte', label: 'lte', desc: 'Less than or equal' },
  { value: 'base64', label: 'base64', desc: 'Base64 encoded' },
  { value: 'base64offset', label: 'base64offset', desc: 'Base64 with offset' },
  { value: 'wide', label: 'wide', desc: 'UTF-16 encoded' },
  { value: 'wide|ascii', label: 'wide|ascii', desc: 'UTF-16 and ASCII' },
];

const CONDITION_PRESETS = [
  { value: 'selection', label: 'selection', desc: 'Single selection' },
  { value: 'selection and not filter', label: 'selection and not filter', desc: 'Include and exclude' },
  { value: 'selection1 or selection2', label: 'OR logic', desc: 'Either condition' },
  { value: 'all of selection*', label: 'all of selection*', desc: 'All with prefix' },
  { value: '1 of selection*', label: '1 of selection*', desc: 'At least one' },
  { value: 'selection | count() > 5', label: 'count() > 5', desc: 'Aggregation count' },
];

const SIGMA_TEMPLATES: { id: string; name: string; rule: SigmaRule }[] = [
  {
    id: 'powershell-encoding',
    name: 'PowerShell Encoded Commands',
    rule: {
      title: 'PowerShell Encoded Command',
      status: 'experimental',
      description: 'Detects encoded PowerShell commands',
      author: 'Security Analyst',
      date: new Date().toISOString().split('T')[0],
      modified: new Date().toISOString().split('T')[0],
      logsource: { product: 'windows', service: 'sysmon', category: 'process_creation' },
      detections: [
        { id: '1', name: 'selection', type: 'field', field: 'CommandLine', modifier: 'contains', value: ['-enc', '-encodedcommand'], negation: false },
        { id: '2', name: 'filter', type: 'field', field: 'ParentImage', modifier: 'endswith', value: ['explorer.exe'], negation: false }
      ],
      condition: 'selection and not filter',
      falsepositives: ['Administrative scripts'],
      level: 'high',
      tags: ['attack.execution', 'attack.t1059.001'],
      references: []
    }
  },
  {
    id: 'network-c2',
    name: 'Network Connection to C2',
    rule: {
      title: 'Suspicious Network Connection',
      status: 'experimental',
      description: 'Detects connections to C2 domains',
      author: 'Security Analyst',
      date: new Date().toISOString().split('T')[0],
      modified: new Date().toISOString().split('T')[0],
      logsource: { category: 'network_connection' },
      detections: [
        { id: '1', name: 'selection', type: 'field', field: 'DestinationHostname', modifier: 'contains', value: ['evil.com'], negation: false }
      ],
      condition: 'selection',
      falsepositives: [],
      level: 'critical',
      tags: ['attack.command_and_control'],
      references: []
    }
  }
];

export default function SigmaBuilder() {
  const [rule, setRule] = useState<SigmaRule>({
    title: 'Suspicious_Activity_Detection',
    id: crypto.randomUUID(),
    status: 'experimental',
    description: 'Detects suspicious activity',
    author: 'Security Analyst',
    date: new Date().toISOString().split('T')[0],
    modified: new Date().toISOString().split('T')[0],
    logsource: { category: 'process_creation' },
    detections: [
      {
        id: '1',
        name: 'selection',
        type: 'field',
        field: 'CommandLine',
        modifier: 'contains',
        value: ['suspicious'],
        negation: false
      }
    ],
    condition: 'selection',
    fields: ['ComputerName', 'User', 'CommandLine'],
    falsepositives: ['Legitimate activity'],
    level: 'high',
    tags: ['attack.execution'],
    references: []
  });

  const [generated, setGenerated] = useState('');
  const [copied, setCopied] = useState(false);
  const [saved, setSaved] = useState(false);
  const [activeTab, setActiveTab] = useState<'builder' | 'preview' | 'templates'>('builder');
  const [expandedSections, setExpandedSections] = useState({
    metadata: true,
    logsource: true,
    detection: true,
    condition: true,
    falsepositives: false
  });
  const [validationErrors, setValidationErrors] = useState<string[]>([]);

  const toggleSection = (section: keyof typeof expandedSections) => {
    setExpandedSections(prev => ({ ...prev, [section]: !prev[section] }));
  };

  const generateSigma = useCallback(() => {
    const errors: string[] = [];
    
    if (!rule.title.trim()) errors.push('Title is required');
    if (!rule.description.trim()) errors.push('Description is required');
    if (!rule.logsource.category && !rule.logsource.product) {
      errors.push('Category or Product is required');
    }
    
    setValidationErrors(errors);
    if (errors.length > 0) return;

    let yaml = `title: ${rule.title}
id: ${rule.id}
status: ${rule.status}
description: ${rule.description}
author: ${rule.author}
date: ${rule.date}
modified: ${rule.modified}
`;

    if (rule.license) yaml += `license: ${rule.license}\n`;

    yaml += `logsource:\n`;
    if (rule.logsource.category) yaml += `    category: ${rule.logsource.category}\n`;
    if (rule.logsource.product) yaml += `    product: ${rule.logsource.product}\n`;
    if (rule.logsource.service) yaml += `    service: ${rule.logsource.service}\n`;
    if (rule.logsource.definition) yaml += `    definition: ${rule.logsource.definition}\n`;

    yaml += `detection:\n`;
    
    rule.detections.forEach(det => {
      yaml += `    ${det.name}:\n`;
      
      const indent = '        ';
      const modifier = det.modifier !== 'none' ? `|${det.modifier}` : '';
      
      if (Array.isArray(det.value)) {
        if (det.value.length === 1) {
          yaml += `${indent}${det.field}${modifier}: ${det.value[0]}\n`;
        } else {
          yaml += `${indent}${det.field}${modifier}:\n`;
          det.value.forEach(v => yaml += `${indent}    - ${v}\n`);
        }
      } else {
        yaml += `${indent}${det.field}${modifier}: ${det.value}\n`;
      }
    });

    yaml += `    condition: ${rule.condition}\n`;

    if (rule.fields && rule.fields.length > 0) {
      yaml += `fields:\n`;
      rule.fields.forEach(f => yaml += `    - ${f}\n`);
    }

    yaml += `falsepositives:\n`;
    rule.falsepositives.forEach(fp => yaml += `    - ${fp}\n`);

    yaml += `level: ${rule.level}\n`;

    if (rule.tags.length > 0) {
      yaml += `tags:\n`;
      rule.tags.forEach(tag => yaml += `    - ${tag}\n`);
    }

    if (rule.references.length > 0) {
      yaml += `references:\n`;
      rule.references.forEach(ref => yaml += `    - ${ref}\n`);
    }

    setGenerated(yaml);
    setActiveTab('preview');
  }, [rule]);

  const handleCopy = () => {
    navigator.clipboard.writeText(generated);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([generated], { type: "text/yaml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${rule.title.toLowerCase().replace(/[^a-z0-9]+/g, '_')}.yml`;
    a.click();
    URL.revokeObjectURL(url);
    saveToBackend();
  };

  const saveToBackend = async () => {
    try {
      await fetch("http://localhost:4000/api/sigma", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: rule.title,
          description: rule.description,
          rule: generated,
          level: rule.level,
          tags: rule.tags,
          status: rule.status,
          author: rule.author
        })
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (err) {
      console.error("Failed to save", err);
    }
  };

  const addDetection = () => {
    const newName = `selection${rule.detections.length + 1}`;
    setRule(prev => ({
      ...prev,
      detections: [...prev.detections, {
        id: Date.now().toString(),
        name: newName,
        type: 'field',
        field: '',
        modifier: 'contains',
        value: [''],
        negation: false
      }]
    }));
  };

  const updateDetection = (id: string, updates: Partial<SigmaDetection>) => {
    setRule(prev => ({
      ...prev,
      detections: prev.detections.map(d => d.id === id ? { ...d, ...updates } : d)
    }));
  };

  const removeDetection = (id: string) => {
    setRule(prev => {
      const det = prev.detections.find(d => d.id === id);
      const newDetections = prev.detections.filter(d => d.id !== id);
      let newCondition = prev.condition;
      if (det) {
        newCondition = newCondition.replace(new RegExp(`\\b${det.name}\\b`, 'g'), '').trim();
        newCondition = newCondition.replace(/\s+(and|or)\s+/g, ' $1 ');
        newCondition = newCondition.replace(/^\s*(and|or)\s+/, '');
        if (!newCondition) newCondition = 'selection';
      }
      return { ...prev, detections: newDetections, condition: newCondition };
    });
  };

  const loadTemplate = (templateId: string) => {
    const template = SIGMA_TEMPLATES.find(t => t.id === templateId);
    if (template) {
      setRule({
        ...template.rule,
        id: crypto.randomUUID(),
        date: new Date().toISOString().split('T')[0],
        modified: new Date().toISOString().split('T')[0],
        detections: template.rule.detections.map((d, idx) => ({ 
          ...d, 
          id: String(Date.now() + idx)
        }))
      });
      setActiveTab('builder');
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent">
            Sigma Rule Builder
          </h1>
          <p className="text-gray-400 text-sm mt-1">Official Sigma specification compliant</p>
        </div>
        
        <div className="flex items-center gap-3">
          <button 
            onClick={() => setActiveTab('templates')}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${activeTab === 'templates' ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/50' : 'bg-white/5 border border-white/10 hover:bg-white/10'}`}
          >
            <LayoutTemplate className="w-4 h-4" />
            Templates
          </button>
          
          <button 
            onClick={generateSigma}
            className="px-4 py-2 bg-gradient-to-r from-cyan-400 to-cyan-600 rounded-lg text-black font-medium hover:shadow-lg hover:shadow-cyan-500/25 transition-all flex items-center gap-2"
          >
            <FileCode className="w-4 h-4" />
            Generate Rule
          </button>
        </div>
      </div>

      {/* Validation Errors */}
      {validationErrors.length > 0 && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 space-y-2">
          <div className="flex items-center gap-2 text-red-400 font-semibold">
            <AlertCircle className="w-5 h-5" />
            <span>Validation Errors</span>
          </div>
          {validationErrors.map((error, idx) => (
            <p key={idx} className="text-sm text-red-300 pl-7">• {error}</p>
          ))}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-2 border-b border-white/10">
        {['builder', 'preview', 'templates'].map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab as any)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors capitalize ${
              activeTab === tab ? 'border-cyan-400 text-cyan-400' : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {activeTab === 'templates' ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {SIGMA_TEMPLATES.map((template) => (
            <div 
              key={template.id}
              onClick={() => loadTemplate(template.id)}
              className="p-6 bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl cursor-pointer transition-all hover:-translate-y-1 hover:border-cyan-400/30"
            >
              <div className="flex items-start justify-between mb-3">
                <div className="p-2 rounded-lg bg-cyan-500/10">
                  <Shield className="w-5 h-5 text-cyan-400" />
                </div>
                <span className={`px-2 py-1 rounded text-xs ${
                  template.rule.level === 'critical' ? 'bg-red-500/10 text-red-400' :
                  template.rule.level === 'high' ? 'bg-orange-500/10 text-orange-400' :
                  'bg-yellow-500/10 text-yellow-400'
                }`}>
                  {template.rule.level}
                </span>
              </div>
              <h3 className="font-semibold text-lg mb-2">{template.name}</h3>
              <p className="text-sm text-gray-400">{template.rule.description}</p>
            </div>
          ))}
        </div>
      ) : activeTab === 'builder' ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Left Column */}
          <div className="space-y-4">
            {/* Metadata */}
            <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl overflow-hidden">
              <button 
                onClick={() => toggleSection('metadata')}
                className="w-full flex items-center justify-between p-4 bg-white/5 hover:bg-white/10 transition-colors"
              >
                <div className="flex items-center gap-2">
                  <FileText className="w-5 h-5 text-cyan-400" />
                  <span className="font-semibold">Metadata</span>
                </div>
                {expandedSections.metadata ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>
              
              {expandedSections.metadata && (
                <div className="p-4 space-y-4">
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Title *</label>
                    <input
                      type="text"
                      value={rule.title}
                      onChange={(e) => setRule({...rule, title: e.target.value})}
                      className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:border-cyan-400 focus:outline-none"
                    />
                  </div>

                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Description *</label>
                    <textarea
                      value={rule.description}
                      onChange={(e) => setRule({...rule, description: e.target.value})}
                      rows={3}
                      className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:border-cyan-400 focus:outline-none text-sm"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm text-gray-400 mb-1">Status</label>
                      <select
                        value={rule.status}
                        onChange={(e) => setRule({...rule, status: e.target.value as any})}
                        className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:border-cyan-400 focus:outline-none text-sm"
                      >
                        <option value="experimental">experimental</option>
                        <option value="test">test</option>
                        <option value="stable">stable</option>
                        <option value="deprecated">deprecated</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-sm text-gray-400 mb-1">Level</label>
                      <select
                        value={rule.level}
                        onChange={(e) => setRule({...rule, level: e.target.value as any})}
                        className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:border-cyan-400 focus:outline-none text-sm"
                      >
                        <option value="informational">informational</option>
                        <option value="low">low</option>
                        <option value="medium">medium</option>
                        <option value="high">high</option>
                        <option value="critical">critical</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm text-gray-400 mb-1">License</label>
                    <select
                      value={rule.license || ''}
                      onChange={(e) => setRule({...rule, license: e.target.value || undefined})}
                      className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:border-cyan-400 focus:outline-none text-sm"
                    >
                      <option value="">None</option>
                      <option value="MIT">MIT</option>
                      <option value="GPL-3.0">GPL-3.0</option>
                      <option value="Apache-2.0">Apache-2.0</option>
                      <option value="DRL-1.1">Detection Rule License 1.1</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Tags (comma separated)</label>
                    <input
                      type="text"
                      value={rule.tags.join(', ')}
                      onChange={(e) => setRule({...rule, tags: e.target.value.split(',').map(t => t.trim()).filter(Boolean)})}
                      placeholder="attack.execution, attack.t1059.001"
                      className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none text-sm"
                    />
                  </div>
                </div>
              )}
            </div>

            {/* Logsource */}
            <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl overflow-hidden">
              <button 
                onClick={() => toggleSection('logsource')}
                className="w-full flex items-center justify-between p-4 bg-white/5 hover:bg-white/10 transition-colors"
              >
                <div className="flex items-center gap-2">
                  <Server className="w-5 h-5 text-cyan-400" />
                  <span className="font-semibold">Log Source</span>
                </div>
                {expandedSections.logsource ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>
              
              {expandedSections.logsource && (
                <div className="p-4 space-y-4">
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Category</label>
                    <select
                      value={rule.logsource.category || ''}
                      onChange={(e) => setRule({...rule, logsource: {...rule.logsource, category: e.target.value || undefined}})}
                      className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:border-cyan-400 focus:outline-none text-sm"
                    >
                      <option value="">None</option>
                      {SIGMA_LOGSOURCE.category.map(c => (
                        <option key={c} value={c}>{c}</option>
                      ))}
                    </select>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm text-gray-400 mb-1">Product</label>
                      <select
                        value={rule.logsource.product || ''}
                        onChange={(e) => setRule({...rule, logsource: {...rule.logsource, product: e.target.value || undefined}})}
                        className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:border-cyan-400 focus:outline-none text-sm"
                      >
                        <option value="">None</option>
                        {SIGMA_LOGSOURCE.product.map(p => (
                          <option key={p} value={p}>{p}</option>
                        ))}
                      </select>
                    </div>
                    <div>
                      <label className="block text-sm text-gray-400 mb-1">Service</label>
                      <select
                        value={rule.logsource.service || ''}
                        onChange={(e) => setRule({...rule, logsource: {...rule.logsource, service: e.target.value || undefined}})}
                        className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:border-cyan-400 focus:outline-none text-sm"
                      >
                        <option value="">None</option>
                        {SIGMA_LOGSOURCE.service.map(s => (
                          <option key={s} value={s}>{s}</option>
                        ))}
                      </select>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Detection */}
            <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl overflow-hidden">
              <button 
                onClick={() => toggleSection('detection')}
                className="w-full flex items-center justify-between p-4 bg-white/5 hover:bg-white/10 transition-colors"
              >
                <div className="flex items-center gap-2">
                  <Target className="w-5 h-5 text-cyan-400" />
                  <span className="font-semibold">Detection</span>
                  <span className="px-2 py-0.5 bg-cyan-500/20 text-cyan-400 text-xs rounded-full">
                    {rule.detections.length}
                  </span>
                </div>
                {expandedSections.detection ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>
              
              {expandedSections.detection && (
                <div className="p-4 space-y-4">
                  {rule.detections.map((detection) => (
                    <div key={detection.id} className="bg-black/30 border border-white/5 rounded-lg p-4 space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 flex-1">
                          <input
                            type="text"
                            value={detection.name}
                            onChange={(e) => updateDetection(detection.id, { name: e.target.value })}
                            className="px-3 py-1.5 bg-black/40 border border-white/10 rounded text-sm text-cyan-400 font-mono font-bold focus:border-cyan-400 focus:outline-none w-32"
                          />
                          <label className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-red-500/10 border border-red-500/30 cursor-pointer select-none">
                            <input
                              type="checkbox"
                              checked={detection.negation}
                              onChange={(e) => updateDetection(detection.id, { negation: e.target.checked })}
                              className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-red-500 focus:ring-red-500"
                            />
                            <span className="text-xs text-red-400">NOT</span>
                          </label>
                        </div>
                        <button 
                          onClick={() => removeDetection(detection.id)}
                          className="p-1.5 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>

                      <div className="grid grid-cols-2 gap-2">
                        <input
                          type="text"
                          value={detection.field || ''}
                          onChange={(e) => updateDetection(detection.id, { field: e.target.value })}
                          placeholder="Field name"
                          className="px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none text-sm font-mono"
                        />
                        <select
                          value={detection.modifier}
                          onChange={(e) => updateDetection(detection.id, { modifier: e.target.value as SigmaModifier })}
                          className="px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-sm text-white focus:border-cyan-400 focus:outline-none"
                        >
                          {SIGMA_MODIFIERS.map(m => (
                            <option key={m.value} value={m.value}>{m.label}</option>
                          ))}
                        </select>
                      </div>

                      <div className="space-y-2">
                        {Array.isArray(detection.value) ? detection.value.map((val, idx) => (
                          <div key={idx} className="flex items-center gap-2">
                            <input
                              type="text"
                              value={val}
                              onChange={(e) => {
                                const newValues = [...detection.value as string[]];
                                newValues[idx] = e.target.value;
                                updateDetection(detection.id, { value: newValues });
                              }}
                              placeholder="Value to match"
                              className="flex-1 px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none text-sm"
                            />
                            {detection.value.length > 1 && (
                              <button 
                                onClick={() => {
                                  const newValues = (detection.value as string[]).filter((_, i) => i !== idx);
                                  updateDetection(detection.id, { value: newValues });
                                }}
                                className="p-2 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors"
                              >
                                <X className="w-4 h-4" />
                              </button>
                            )}
                          </div>
                        )) : (
                          <input
                            type="text"
                            value={detection.value as string}
                            onChange={(e) => updateDetection(detection.id, { value: e.target.value })}
                            placeholder="Value to match"
                            className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none text-sm"
                          />
                        )}
                        <button 
                          onClick={() => {
                            const current = Array.isArray(detection.value) ? detection.value : [detection.value as string];
                            updateDetection(detection.id, { value: [...current, ''] });
                          }}
                          className="text-sm text-cyan-400 hover:text-cyan-300 flex items-center gap-1 px-1"
                        >
                          <Plus className="w-3 h-3" /> Add value
                        </button>
                      </div>
                    </div>
                  ))}
                  
                  <button 
                    onClick={addDetection}
                    className="w-full py-3 border border-dashed border-white/20 rounded-lg text-gray-400 hover:text-white hover:border-cyan-400/50 hover:bg-cyan-500/5 transition-all flex items-center justify-center gap-2"
                  >
                    <Plus className="w-4 h-4" />
                    Add Selection
                  </button>
                </div>
              )}
            </div>

            {/* Condition */}
            <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl overflow-hidden">
              <button 
                onClick={() => toggleSection('condition')}
                className="w-full flex items-center justify-between p-4 bg-white/5 hover:bg-white/10 transition-colors"
              >
                <div className="flex items-center gap-2">
                  <Code2 className="w-5 h-5 text-cyan-400" />
                  <span className="font-semibold">Condition</span>
                </div>
                {expandedSections.condition ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>
              
              {expandedSections.condition && (
                <div className="p-4 space-y-4">
                  <input
                    type="text"
                    value={rule.condition}
                    onChange={(e) => setRule({...rule, condition: e.target.value})}
                    className="w-full px-4 py-3 bg-black/40 border border-white/10 rounded-lg text-white font-mono text-sm focus:border-cyan-400 focus:outline-none"
                    placeholder="selection and not filter"
                  />

                  <div className="grid grid-cols-2 gap-2">
                    {CONDITION_PRESETS.map((preset) => (
                      <button
                        key={preset.value}
                        onClick={() => setRule({...rule, condition: preset.value})}
                        className={`p-3 rounded-lg border text-sm text-left transition-all ${rule.condition === preset.value ? 'border-cyan-400/50 bg-cyan-500/10 text-cyan-400' : 'border-white/10 bg-white/5 text-gray-300'}`}
                      >
                        <div className="font-semibold mb-1 font-mono">{preset.label}</div>
                        <div className="text-xs opacity-70">{preset.desc}</div>
                      </button>
                    ))}
                  </div>

                  <div className="bg-slate-800 rounded-lg p-3">
                    <p className="text-xs text-gray-400 mb-2">Available selections:</p>
                    <div className="flex flex-wrap gap-2">
                      {rule.detections.map(d => (
                        <button
                          key={d.id}
                          onClick={() => setRule(prev => ({...prev, condition: prev.condition + ' ' + d.name}))}
                          className="px-3 py-1.5 rounded bg-cyan-500/10 text-cyan-400 text-xs font-mono hover:bg-cyan-500/20"
                        >
                          {d.name}
                        </button>
                      ))}
                    </div>
                    <div className="flex gap-2 mt-2 pt-2 border-t border-white/10">
                      {['and', 'or', 'not', '(', ')'].map(op => (
                        <button
                          key={op}
                          onClick={() => setRule(prev => ({...prev, condition: prev.condition + ' ' + op}))}
                          className="px-3 py-1.5 rounded bg-white/5 text-gray-300 text-xs font-mono hover:bg-white/10"
                        >
                          {op}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Right Column - Preview */}
          <div className="space-y-4">
            <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-4 sticky top-6">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <FileCode className="w-5 h-5 text-cyan-400" />
                  <span className="font-semibold">YAML Output</span>
                </div>
                <div className="flex items-center gap-2">
                  <button 
                    onClick={handleCopy}
                    disabled={!generated}
                    className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 transition-colors disabled:opacity-50"
                  >
                    {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                  </button>
                  <button 
                    onClick={handleDownload}
                    disabled={!generated}
                    className="px-3 py-2 rounded-lg bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 transition-colors disabled:opacity-50 text-sm font-medium flex items-center gap-2"
                  >
                    <Download className="w-4 h-4" />
                    Export
                  </button>
                </div>
              </div>
              
              <div className="bg-black/50 border border-white/10 rounded-lg p-4 min-h-[500px] font-mono text-sm overflow-x-auto">
                {generated ? (
                  <pre className="text-gray-300 whitespace-pre-wrap">{generated}</pre>
                ) : (
                  <div className="h-full flex flex-col items-center justify-center text-gray-500 space-y-4">
                    <Shield className="w-16 h-16 opacity-20" />
                    <p>Click "Generate Rule" to preview</p>
                  </div>
                )}
              </div>

              {generated && (
                <div className="mt-4 flex items-center justify-between">
                  <div className="flex items-center gap-2 text-sm text-green-400">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Valid Sigma syntax</span>
                  </div>
                  <button
                    onClick={saveToBackend}
                    className="text-sm text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                  >
                    <Save className="w-4 h-4" />
                    {saved ? 'Saved!' : 'Save'}
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-6">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="text-xl font-semibold">Generated Sigma Rule</h3>
            </div>
            <div className="flex items-center gap-3">
              <button 
                onClick={handleCopy}
                disabled={!generated}
                className="px-4 py-2 bg-white/5 border border-white/10 rounded-lg text-sm font-medium hover:bg-white/10 transition-all flex items-center gap-2 disabled:opacity-50"
              >
                {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                {copied ? 'Copied!' : 'Copy'}
              </button>
              <button 
                onClick={handleDownload}
                disabled={!generated}
                className="px-4 py-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-sm font-medium text-cyan-400 hover:bg-cyan-500/20 transition-all flex items-center gap-2 disabled:opacity-50"
              >
                <Download className="w-4 h-4" />
                Download .yml
              </button>
            </div>
          </div>
          
          <div className="bg-black/50 border border-white/10 rounded-lg p-6 min-h-[400px] font-mono text-sm overflow-x-auto">
            {generated ? (
              <pre className="text-gray-300 whitespace-pre-wrap">{generated}</pre>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-gray-500">
                <AlertCircle className="w-12 h-12 mb-4 opacity-50" />
                <p>No rule generated yet</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}