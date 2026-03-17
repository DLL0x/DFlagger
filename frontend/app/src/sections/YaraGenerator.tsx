import { useState, useCallback, useEffect } from 'react';
import { 
  Shield, 
  Play, 
  Copy, 
  Check, 
  Download, 
  Plus, 
  X, 
  Trash2, 
  FileText,
  Binary,
  Hash,
  Globe,
  AlertCircle,
  CheckCircle2,
  Info,
  Save,
  ChevronDown,
  ChevronUp,
  BookOpen,
  Code2,
  Search,
  FolderOpen
} from 'lucide-react';
import { trackRuleCreated, trackRuleDeleted } from '../utils/activityTracker';

interface YaraString {
  id: string;
  name: string;
  value: string;
  type: 'text' | 'hex' | 'regex';
  modifiers: {
    wide: boolean;
    ascii: boolean;
    nocase: boolean;
    fullword: boolean;
    private: boolean;
    xor?: boolean;
    base64?: boolean;
  };
}

interface YaraImport {
  id: string;
  name: string;
}

interface YaraRule {
  name: string;
  description: string;
  author: string;
  date: string;
  version: string;
  reference: string;
  source: string;
  hash: string;
  level: 'informational' | 'low' | 'medium' | 'high' | 'critical';
  tags: string[];
  imports: YaraImport[];
  strings: YaraString[];
  condition: string;
  customCondition: boolean;
}

const PREDEFINED_IMPORTS = [
  'pe', 'elf', 'cuckoo', 'magic', 'hash', 'math', 'dotnet', 'androguard'
];

const CONDITION_PRESETS = [
  { value: 'any of them', label: 'Any of them (OR)', description: 'Match if any string is found' },
  { value: 'all of them', label: 'All of them (AND)', description: 'Match if all strings are found' },
  { value: 'none of them', label: 'None of them (NOT)', description: 'Match if no strings are found' },
  { value: 'custom', label: 'Custom Condition', description: 'Write your own condition logic' },
];

const RULE_TEMPLATES = [
  {
    id: 'malware-generic',
    name: 'Generic Malware Detection',
    description: 'Basic template for malware detection',
    rule: {
      name: 'MALWARE_Generic_Detection',
      description: 'Detects generic malware indicators',
      author: 'Security Analyst',
      level: 'high' as const,
      strings: [
        { id: '1', name: '$s1', value: 'malicious_payload', type: 'text', modifiers: { wide: true, ascii: true, nocase: true, fullword: true, private: false } },
        { id: '2', name: '$s2', value: 'C:\\\\Users\\\\Admin\\\\AppData\\\\Roaming', type: 'text', modifiers: { wide: true, ascii: true, nocase: false, fullword: false, private: false } },
      ],
      condition: 'any of them'
    }
  },
  {
    id: 'ransomware',
    name: 'Ransomware Indicators',
    description: 'Common ransomware patterns',
    rule: {
      name: 'RANSOMWARE_Patterns',
      description: 'Detects ransomware-related strings',
      author: 'Security Analyst',
      level: 'critical' as const,
      strings: [
        { id: '1', name: '$r1', value: 'YOUR_FILES_HAVE_BEEN_ENCRYPTED', type: 'text', modifiers: { wide: true, ascii: true, nocase: true, fullword: true, private: false } },
        { id: '2', name: '$r2', value: 'bitcoin', type: 'text', modifiers: { wide: false, ascii: true, nocase: true, fullword: true, private: false } },
        { id: '3', name: '$r3', value: '.encrypted', type: 'text', modifiers: { wide: true, ascii: true, nocase: true, fullword: false, private: false } },
      ],
      condition: '2 of them'
    }
  },
  {
    id: 'apt-backdoor',
    name: 'APT Backdoor',
    description: 'Advanced persistent threat indicators',
    rule: {
      name: 'APT_Backdoor_Detection',
      description: 'Detects APT backdoor communication',
      author: 'Threat Hunter',
      level: 'critical' as const,
      strings: [
        { id: '1', name: '$api1', value: 'InternetConnectA', type: 'text', modifiers: { ascii: true, wide: false, nocase: true, fullword: true, private: false } },
        { id: '2', name: '$api2', value: 'HttpSendRequestA', type: 'text', modifiers: { ascii: true, wide: false, nocase: true, fullword: true, private: false } },
        { id: '3', name: '$mutex', value: 'Global\\Unique_Mutex_2024', type: 'text', modifiers: { wide: true, ascii: true, nocase: false, fullword: true, private: false } },
      ],
      condition: 'all of them'
    }
  }
];

export default function YaraGenerator() {
  const [rule, setRule] = useState<YaraRule>({
    name: 'MALWARE_Detection_Rule',
    description: 'Detects suspicious malware behavior and indicators',
    author: 'Security Analyst',
    date: new Date().toISOString().split('T')[0],
    version: '1.0',
    reference: '',
    source: '',
    hash: '',
    level: 'high',
    tags: ['malware', 'suspicious'],
    imports: [],
    strings: [
      { 
        id: '1', 
        name: '$s1', 
        value: 'suspicious_string_here', 
        type: 'text', 
        modifiers: { wide: true, ascii: true, nocase: true, fullword: false, private: false } 
      },
    ],
    condition: 'any of them',
    customCondition: false
  });

  const [generated, setGenerated] = useState('');
  const [copied, setCopied] = useState(false);
  const [saved, setSaved] = useState(false);
  const [activeTab, setActiveTab] = useState<'builder' | 'preview' | 'templates' | 'saved'>('builder');
  const [expandedSections, setExpandedSections] = useState({
    metadata: true,
    imports: false,
    strings: true,
    condition: true
  });
  const [selectedTemplate, setSelectedTemplate] = useState<string | null>(null);
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  
  // Saved rules from backend
  const [savedRules, setSavedRules] = useState<Array<{id: string; title: string; description: string; level: string; createdAt: string}>>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const toggleSection = (section: keyof typeof expandedSections) => {
    setExpandedSections(prev => ({ ...prev, [section]: !prev[section] }));
  };

  // Fetch saved rules from backend
  const fetchSavedRules = async () => {
    setIsLoading(true);
    try {
      const response = await fetch('http://localhost:4000/api/yara');
      const data = await response.json();
      setSavedRules(data.rules || []);
    } catch (err) {
      console.error('Failed to fetch saved rules:', err);
    } finally {
      setIsLoading(false);
    }
  };

  // Load a saved rule
  const loadSavedRule = async (ruleId: string) => {
    try {
      const response = await fetch(`http://localhost:4000/api/yara/${ruleId}`);
      const data = await response.json();
      if (data) {
        // Populate basic fields from the saved rule
        // Note: data.rule contains the generated YARA text, not the form data
        // So we populate what we can from the record
        setRule({
          name: data.title || 'Loaded_Rule',
          description: data.description || '',
          author: data.author || 'Security Analyst',
          date: new Date().toISOString().split('T')[0],
          version: '1.0',
          reference: data.reference || '',
          source: '',
          hash: data.hash || '',
          level: data.level || 'high',
          tags: data.tags || [],
          imports: [],
          strings: [{ 
            id: '1', 
            name: '$s1', 
            value: 'suspicious_string_here', 
            type: 'text' as const, 
            modifiers: { wide: true, ascii: true, nocase: true, fullword: false, private: false } 
          }],
          condition: 'any of them',
          customCondition: false
        });
        setActiveTab('builder');
      }
    } catch (err) {
      console.error('Failed to load rule:', err);
      alert('Failed to load rule');
    }
  };

  // Delete a saved rule
  const deleteSavedRule = async (ruleId: string, ruleTitle?: string) => {
    if (!confirm('Are you sure you want to delete this rule?')) return;
    try {
      await fetch(`http://localhost:4000/api/yara/${ruleId}`, { method: 'DELETE' });
      // Track activity
      await trackRuleDeleted('yara', ruleTitle || 'Unknown Rule');
      await fetchSavedRules();
    } catch (err) {
      console.error('Failed to delete rule:', err);
    }
  };

  // Fetch saved rules on mount
  useEffect(() => {
    fetchSavedRules();
  }, []);

  const generateYara = useCallback(() => {
    const errors: string[] = [];
    
    // Validation
    if (!rule.name.match(/^[a-zA-Z_][a-zA-Z0-9_]*$/)) {
      errors.push('Rule name must start with letter/underscore and contain only alphanumeric characters');
    }
    if (rule.strings.some(s => !s.value.trim())) {
      errors.push('All strings must have a value');
    }
    if (rule.strings.some(s => !s.name.match(/^\$[a-zA-Z0-9_]+$/))) {
      errors.push('String names must start with $ followed by alphanumeric/underscore');
    }

    setValidationErrors(errors);
    if (errors.length > 0) return;

    // Build imports
    const importsSection = rule.imports.length > 0 
      ? rule.imports.map(imp => `import "${imp.name}"`).join('\n') + '\n\n'
      : '';

    // Build meta
    const metaSection = `meta:
        description = "${rule.description}"
        author = "${rule.author}"
        date = "${rule.date}"
        version = "${rule.version}"
        ${rule.reference ? `reference = "${rule.reference}"` : ''}
        ${rule.source ? `source = "${rule.source}"` : ''}
        ${rule.hash ? `hash = "${rule.hash}"` : ''}
        level = "${rule.level}"
        tags = "${rule.tags.join(', ')}"`;

    // Build strings
    const stringsSection = rule.strings.length > 0 
      ? `strings:
${rule.strings.map(s => {
  const mods = [];
  if (s.modifiers.wide) mods.push('wide');
  if (s.modifiers.ascii) mods.push('ascii');
  if (s.modifiers.nocase) mods.push('nocase');
  if (s.modifiers.fullword) mods.push('fullword');
  if (s.modifiers.private) mods.push('private');
  if (s.modifiers.xor) mods.push('xor');
  if (s.modifiers.base64) mods.push('base64');
  
  const modString = mods.length > 0 ? ' ' + mods.join(' ') : '';
  
  if (s.type === 'hex') {
    return `        ${s.name} = { ${s.value} }${modString}`;
  } else if (s.type === 'regex') {
    return `        ${s.name} = /${s.value}/${modString}`;
  } else {
    return `        ${s.name} = "${s.value}"${modString}`;
  }
}).join('\n')}`
      : '';

    // Build condition
    const conditionSection = `condition:
        ${rule.condition}`;

    // Combine
    const yara = `${importsSection}rule ${rule.name}
{
    ${metaSection}

    ${stringsSection}

    ${conditionSection}
}`;

    setGenerated(yara);
    setActiveTab('preview');
  }, [rule]);

  const handleCopy = () => {
    navigator.clipboard.writeText(generated);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([generated], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${rule.name}.yar`;
    a.click();
    URL.revokeObjectURL(url);
    
    // Also save to backend
    saveToBackend();
  };

  const saveToBackend = async () => {
    try {
      const response = await fetch("http://localhost:4000/api/yara", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: rule.name,
          description: rule.description,
          rule: generated,
          level: rule.level,
          tags: rule.tags,
          author: rule.author
        })
      });
      const data = await response.json();
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
      // Track activity
      await trackRuleCreated('yara', rule.name, data.id);
      // Refresh saved rules list
      await fetchSavedRules();
    } catch (err) {
      console.error("Failed to save YARA rule", err);
    }
  };

  const addString = () => {
    const count = rule.strings.length + 1;
    const name = `$s${count}`;
    setRule(prev => ({
      ...prev,
      strings: [...prev.strings, { 
        id: Date.now().toString(), 
        name, 
        value: '', 
        type: 'text', 
        modifiers: { wide: true, ascii: true, nocase: false, fullword: false, private: false } 
      }]
    }));
  };

  const updateString = (id: string, updates: Partial<YaraString>) => {
    setRule(prev => ({
      ...prev,
      strings: prev.strings.map(s => s.id === id ? { ...s, ...updates } : s)
    }));
  };

  const updateModifier = (id: string, modifier: keyof YaraString['modifiers'], value: boolean) => {
    setRule(prev => ({
      ...prev,
      strings: prev.strings.map(s => 
        s.id === id 
          ? { ...s, modifiers: { ...s.modifiers, [modifier]: value } }
          : s
      )
    }));
  };

  const removeString = (id: string) => {
    setRule(prev => ({
      ...prev,
      strings: prev.strings.filter(s => s.id !== id)
    }));
  };

  const addImport = (name: string) => {
    if (!rule.imports.find(i => i.name === name)) {
      setRule(prev => ({
        ...prev,
        imports: [...prev.imports, { id: Date.now().toString(), name }]
      }));
    }
  };

  const removeImport = (id: string) => {
    setRule(prev => ({
      ...prev,
      imports: prev.imports.filter(i => i.id !== id)
    }));
  };

  const loadTemplate = (templateId: string) => {
    const template = RULE_TEMPLATES.find(t => t.id === templateId);
    if (template) {
      setRule(prev => ({
        ...prev,
        ...template.rule,
        strings: template.rule.strings.map((s, idx) => ({ 
          ...s, 
          id: String(Date.now() + idx),
          type: s.type as 'text' | 'hex' | 'regex'
        })),
        date: new Date().toISOString().split('T')[0]
      }));
      setSelectedTemplate(templateId);
      setActiveTab('builder');
    }
  };

  // Condition generator for future use
  /*
  const generateCondition = (type: string) => {
    switch(type) {
      case 'any': return 'any of them';
      case 'all': return 'all of them';
      case 'none': return 'none of them';
      case 'count': return '2 of them';
      default: return rule.condition;
    }
  };
  */

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent">
            YARA Rule Generator
          </h1>
          <p className="text-gray-400 text-sm mt-1">Create professional YARA rules with best practices</p>
        </div>
        
        <div className="flex items-center gap-3">
          <button 
            onClick={() => setActiveTab('templates')}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${activeTab === 'templates' ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/50' : 'bg-white/5 border border-white/10 hover:bg-white/10'}`}
          >
            <BookOpen className="w-4 h-4" />
            Templates
          </button>
          
          <button 
            onClick={generateYara}
            className="px-4 py-2 bg-gradient-to-r from-cyan-400 to-cyan-600 rounded-lg text-black font-medium hover:shadow-lg hover:shadow-cyan-500/25 transition-all flex items-center gap-2"
          >
            <Play className="w-4 h-4" />
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
        {['builder', 'preview', 'templates', 'saved'].map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab as any)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors capitalize ${
              activeTab === tab
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            {tab === 'saved' ? `Saved (${savedRules.length})` : tab}
          </button>
        ))}
      </div>

      {activeTab === 'templates' ? (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {RULE_TEMPLATES.map((template) => (
            <div 
              key={template.id}
              onClick={() => loadTemplate(template.id)}
              className={`p-6 bg-slate-900/60 backdrop-blur-xl border rounded-xl cursor-pointer transition-all hover:-translate-y-1 ${selectedTemplate === template.id ? 'border-cyan-400/50 bg-cyan-500/10' : 'border-white/10 hover:border-cyan-400/30'}`}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="p-2 rounded-lg bg-cyan-500/10">
                  <Shield className="w-5 h-5 text-cyan-400" />
                </div>
                <span className="text-xs text-gray-500">{template.rule.strings.length} strings</span>
              </div>
              <h3 className="font-semibold text-lg mb-2">{template.name}</h3>
              <p className="text-sm text-gray-400 mb-4">{template.description}</p>
              <div className="flex items-center gap-2">
                <span className={`px-2 py-1 rounded text-xs ${template.rule.level === 'critical' ? 'bg-red-500/10 text-red-400' : 'bg-orange-500/10 text-orange-400'}`}>
                  {template.rule.level}
                </span>
                <span className="text-xs text-gray-500">Condition: {template.rule.condition}</span>
              </div>
            </div>
          ))}
          
          <div className="p-6 bg-slate-900/30 border border-dashed border-white/10 rounded-xl flex flex-col items-center justify-center text-center">
            <Plus className="w-8 h-8 text-gray-600 mb-2" />
            <p className="text-sm text-gray-500">Start from scratch</p>
            <button 
              onClick={() => setActiveTab('builder')}
              className="mt-2 text-cyan-400 text-sm hover:underline"
            >
              Create empty rule
            </button>
          </div>
        </div>
      ) : activeTab === 'saved' ? (
        <div className="space-y-4">
          {/* Search Bar */}
          <div className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="text"
                placeholder="Search saved rules..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-3 bg-slate-900/60 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none"
              />
            </div>
            <button
              onClick={fetchSavedRules}
              className="px-4 py-2 bg-white/5 border border-white/10 rounded-xl hover:bg-white/10 transition-colors flex items-center gap-2"
            >
              <FolderOpen className="w-5 h-5" />
              Refresh
            </button>
          </div>

          {/* Saved Rules List */}
          {isLoading ? (
            <div className="text-center py-12">
              <div className="animate-spin w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full mx-auto mb-4" />
              <p className="text-gray-400">Loading saved rules...</p>
            </div>
          ) : savedRules.length === 0 ? (
            <div className="text-center py-12 bg-slate-900/30 border border-white/10 rounded-xl">
              <Shield className="w-12 h-12 text-gray-600 mx-auto mb-4" />
              <p className="text-gray-400">No saved rules yet</p>
              <p className="text-sm text-gray-500 mt-1">Create and save rules to see them here</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {savedRules
                .filter(r => 
                  r.title?.toLowerCase().includes(searchQuery.toLowerCase()) ||
                  r.description?.toLowerCase().includes(searchQuery.toLowerCase())
                )
                .map((savedRule) => (
                <div 
                  key={savedRule.id}
                  className="p-5 bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl transition-all hover:border-cyan-400/30"
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-cyan-500/10">
                        <Binary className="w-5 h-5 text-cyan-400" />
                      </div>
                      <div>
                        <h3 className="font-semibold text-white">{savedRule.title}</h3>
                        <p className="text-xs text-gray-500">
                          {new Date(savedRule.createdAt).toLocaleDateString()}
                        </p>
                      </div>
                    </div>
                    <span className={`px-2 py-1 rounded text-xs ${
                      savedRule.level === 'critical' ? 'bg-red-500/10 text-red-400' :
                      savedRule.level === 'high' ? 'bg-orange-500/10 text-orange-400' :
                      savedRule.level === 'medium' ? 'bg-yellow-500/10 text-yellow-400' :
                      'bg-blue-500/10 text-blue-400'
                    }`}>
                      {savedRule.level}
                    </span>
                  </div>
                  <p className="text-sm text-gray-400 mb-4 line-clamp-2">{savedRule.description}</p>
                  <div className="flex gap-2">
                    <button
                      onClick={() => loadSavedRule(savedRule.id)}
                      className="flex-1 px-3 py-2 bg-cyan-500/10 text-cyan-400 rounded-lg text-sm hover:bg-cyan-500/20 transition-colors flex items-center justify-center gap-2"
                    >
                      <FolderOpen className="w-4 h-4" />
                      Load
                    </button>
                    <button
                      onClick={() => deleteSavedRule(savedRule.id, savedRule.title)}
                      className="px-3 py-2 bg-red-500/10 text-red-400 rounded-lg text-sm hover:bg-red-500/20 transition-colors"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      ) : activeTab === 'builder' ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Left Column - Builder */}
          <div className="space-y-4">
            {/* Metadata Section */}
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
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm text-gray-400 mb-1">Rule Name *</label>
                      <input
                        type="text"
                        value={rule.name}
                        onChange={(e) => setRule({...rule, name: e.target.value})}
                        placeholder="MALWARE_Detection"
                        className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none font-mono text-sm"
                      />
                      <p className="text-xs text-gray-500 mt-1">Alphanumeric and underscores only</p>
                    </div>
                    <div>
                      <label className="block text-sm text-gray-400 mb-1">Severity Level</label>
                      <select
                        value={rule.level}
                        onChange={(e) => setRule({...rule, level: e.target.value as any})}
                        className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:border-cyan-400 focus:outline-none"
                      >
                        <option value="informational">Informational</option>
                        <option value="low">Low</option>
                        <option value="medium">Medium</option>
                        <option value="high">High</option>
                        <option value="critical">Critical</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Description</label>
                    <textarea
                      value={rule.description}
                      onChange={(e) => setRule({...rule, description: e.target.value})}
                      placeholder="Describe what this rule detects..."
                      rows={2}
                      className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none text-sm"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm text-gray-400 mb-1">Author</label>
                      <input
                        type="text"
                        value={rule.author}
                        onChange={(e) => setRule({...rule, author: e.target.value})}
                        className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:border-cyan-400 focus:outline-none text-sm"
                      />
                    </div>
                    <div>
                      <label className="block text-sm text-gray-400 mb-1">Version</label>
                      <input
                        type="text"
                        value={rule.version}
                        onChange={(e) => setRule({...rule, version: e.target.value})}
                        placeholder="1.0"
                        className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:border-cyan-400 focus:outline-none text-sm"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Reference URL</label>
                    <input
                      type="text"
                      value={rule.reference}
                      onChange={(e) => setRule({...rule, reference: e.target.value})}
                      placeholder="https://..."
                      className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none text-sm"
                    />
                  </div>

                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Tags (comma separated)</label>
                    <input
                      type="text"
                      value={rule.tags.join(', ')}
                      onChange={(e) => setRule({...rule, tags: e.target.value.split(',').map(t => t.trim()).filter(Boolean)})}
                      placeholder="malware, trojan, apt"
                      className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none text-sm"
                    />
                  </div>
                </div>
              )}
            </div>

            {/* Imports Section */}
            <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl overflow-hidden">
              <button 
                onClick={() => toggleSection('imports')}
                className="w-full flex items-center justify-between p-4 bg-white/5 hover:bg-white/10 transition-colors"
              >
                <div className="flex items-center gap-2">
                  <Globe className="w-5 h-5 text-cyan-400" />
                  <span className="font-semibold">Imports</span>
                  {rule.imports.length > 0 && (
                    <span className="px-2 py-0.5 bg-cyan-500/20 text-cyan-400 text-xs rounded-full">
                      {rule.imports.length}
                    </span>
                  )}
                </div>
                {expandedSections.imports ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>
              
              {expandedSections.imports && (
                <div className="p-4 space-y-3">
                  <div className="flex flex-wrap gap-2">
                    {PREDEFINED_IMPORTS.map(imp => (
                      <button
                        key={imp}
                        onClick={() => addImport(imp)}
                        disabled={rule.imports.find(i => i.name === imp) !== undefined}
                        className="px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-sm text-gray-300 hover:bg-cyan-500/20 hover:border-cyan-500/30 hover:text-cyan-400 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        + {imp}
                      </button>
                    ))}
                  </div>
                  
                  {rule.imports.length > 0 && (
                    <div className="flex flex-wrap gap-2 mt-3">
                      {rule.imports.map(imp => (
                        <span key={imp.id} className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-sm">
                          {imp.name}
                          <button 
                            onClick={() => removeImport(imp.id)}
                            className="hover:text-red-400"
                          >
                            <X className="w-3 h-3" />
                          </button>
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Strings Section */}
            <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl overflow-hidden">
              <button 
                onClick={() => toggleSection('strings')}
                className="w-full flex items-center justify-between p-4 bg-white/5 hover:bg-white/10 transition-colors"
              >
                <div className="flex items-center gap-2">
                  <Hash className="w-5 h-5 text-cyan-400" />
                  <span className="font-semibold">Strings</span>
                  <span className="px-2 py-0.5 bg-cyan-500/20 text-cyan-400 text-xs rounded-full">
                    {rule.strings.length}
                  </span>
                </div>
                {expandedSections.strings ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>
              
              {expandedSections.strings && (
                <div className="p-4 space-y-4">
                  {rule.strings.map((str) => (
                    <div key={str.id} className="bg-black/30 border border-white/5 rounded-lg p-4 space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 flex-1">
                          <span className="text-cyan-400 font-mono text-sm font-bold">{str.name}</span>
                          <select
                            value={str.type}
                            onChange={(e) => updateString(str.id, { type: e.target.value as any })}
                            className="px-2 py-1 bg-black/40 border border-white/10 rounded text-sm text-white focus:border-cyan-400 focus:outline-none"
                          >
                            <option value="text">Text</option>
                            <option value="hex">Hex</option>
                            <option value="regex">Regex</option>
                          </select>
                        </div>
                        <button 
                          onClick={() => removeString(str.id)}
                          className="p-1.5 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>

                      <div>
                        <textarea
                          value={str.value}
                          onChange={(e) => updateString(str.id, { value: e.target.value })}
                          placeholder={str.type === 'hex' ? '4D 5A 90 00 ...' : str.type === 'regex' ? 'malware[0-9]+' : 'suspicious_string'}
                          rows={2}
                          className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none font-mono text-sm"
                        />
                      </div>

                      <div className="flex flex-wrap gap-2">
                        {[
                          { key: 'wide', label: 'wide', tooltip: 'Match wide (UTF-16) strings' },
                          { key: 'ascii', label: 'ascii', tooltip: 'Match ASCII strings' },
                          { key: 'nocase', label: 'nocase', tooltip: 'Case insensitive matching' },
                          { key: 'fullword', label: 'fullword', tooltip: 'Match full words only' },
                          { key: 'private', label: 'private', tooltip: 'Not shown in output' },
                        ].map((mod) => (
                          <label key={mod.key} className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 cursor-pointer hover:bg-white/10 transition-colors select-none" title={mod.tooltip}>
                            <input
                              type="checkbox"
                              checked={str.modifiers[mod.key as keyof typeof str.modifiers] || false}
                              onChange={(e) => updateModifier(str.id, mod.key as any, e.target.checked)}
                              className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-cyan-500 focus:ring-cyan-500"
                            />
                            <span className="text-xs text-gray-300">{mod.label}</span>
                          </label>
                        ))}
                      </div>
                    </div>
                  ))}
                  
                  <button 
                    onClick={addString}
                    className="w-full py-3 border border-dashed border-white/20 rounded-lg text-gray-400 hover:text-white hover:border-cyan-400/50 hover:bg-cyan-500/5 transition-all flex items-center justify-center gap-2"
                  >
                    <Plus className="w-4 h-4" />
                    Add String
                  </button>
                </div>
              )}
            </div>

            {/* Condition Section */}
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
                  <div className="grid grid-cols-2 gap-3">
                    {CONDITION_PRESETS.map((preset) => (
                      <button
                        key={preset.value}
                        onClick={() => setRule({...rule, condition: preset.value, customCondition: preset.value === 'custom'})}
                        className={`p-3 rounded-lg border text-left transition-all ${rule.condition === preset.value ? 'border-cyan-400/50 bg-cyan-500/10' : 'border-white/10 bg-white/5 hover:border-white/30'}`}
                      >
                        <div className="flex items-center gap-2 mb-1">
                          <div className={`w-4 h-4 rounded-full border flex items-center justify-center ${rule.condition === preset.value ? 'border-cyan-400 bg-cyan-400' : 'border-gray-500'}`}>
                            {rule.condition === preset.value && <Check className="w-3 h-3 text-black" />}
                          </div>
                          <span className="font-medium text-sm">{preset.label}</span>
                        </div>
                        <p className="text-xs text-gray-400 pl-6">{preset.description}</p>
                      </button>
                    ))}
                  </div>

                  {rule.customCondition && (
                    <div className="mt-4">
                      <label className="block text-sm text-gray-400 mb-2">Custom Condition Logic</label>
                      <textarea
                        value={rule.condition === 'custom' ? '' : rule.condition}
                        onChange={(e) => setRule({...rule, condition: e.target.value})}
                        placeholder="e.g., any of ($s*) or $x"
                        rows={3}
                        className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none font-mono text-sm"
                      />
                      <p className="text-xs text-gray-500 mt-2">
                        Available variables: {rule.strings.map(s => s.name).join(', ')} or use wildcards like $s*
                      </p>
                    </div>
                  )}

                  <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3 flex items-start gap-2">
                    <Info className="w-4 h-4 text-amber-400 mt-0.5 flex-shrink-0" />
                    <div className="text-sm text-amber-200">
                      <span className="font-semibold">Tip:</span> Use <code className="bg-black/30 px-1 rounded">2 of them</code> to match any 2 strings, or <code className="bg-black/30 px-1 rounded">$a and $b</code> for specific combinations.
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
                <h3 className="font-semibold flex items-center gap-2">
                  <Binary className="w-4 h-4 text-cyan-400" />
                  Live Preview
                </h3>
                <div className="flex items-center gap-2">
                  <button 
                    onClick={handleCopy}
                    disabled={!generated}
                    className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 transition-colors disabled:opacity-50"
                    title="Copy to clipboard"
                  >
                    {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                  </button>
                  <button 
                    onClick={handleDownload}
                    disabled={!generated}
                    className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 transition-colors disabled:opacity-50"
                    title="Download .yar file"
                  >
                    <Download className="w-4 h-4" />
                  </button>
                  <button 
                    onClick={saveToBackend}
                    disabled={!generated}
                    className="px-3 py-2 rounded-lg bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 transition-colors disabled:opacity-50 text-sm font-medium flex items-center gap-2"
                  >
                    <Save className="w-4 h-4" />
                    {saved ? 'Saved!' : 'Save'}
                  </button>
                </div>
              </div>
              
              <div className="bg-black/50 border border-white/10 rounded-lg p-4 min-h-[500px] font-mono text-sm overflow-x-auto">
                {generated ? (
                  <pre className="text-gray-300 whitespace-pre-wrap break-all">{generated}</pre>
                ) : (
                  <div className="h-full flex flex-col items-center justify-center text-gray-500 space-y-4">
                    <Shield className="w-16 h-16 opacity-20" />
                    <p>Click "Generate Rule" to see preview</p>
                    <div className="text-xs text-center max-w-xs">
                      Define your metadata, strings, and condition to generate a valid YARA rule
                    </div>
                  </div>
                )}
              </div>

              {generated && (
                <div className="mt-4 flex items-center gap-2 text-sm text-green-400">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Rule syntax is valid</span>
                </div>
              )}
            </div>

            {/* Quick Help */}
            <div className="bg-slate-900/40 backdrop-blur-xl border border-white/10 rounded-xl p-4">
              <h4 className="font-semibold mb-3 flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-cyan-400" />
                Quick Reference
              </h4>
              <div className="space-y-2 text-sm text-gray-400">
                <div className="flex justify-between">
                  <span>String count:</span>
                  <span className="text-white">{rule.strings.length}</span>
                </div>
                <div className="flex justify-between">
                  <span>Imports:</span>
                  <span className="text-white">{rule.imports.length}</span>
                </div>
                <div className="flex justify-between">
                  <span>Condition:</span>
                  <span className="text-cyan-400">{rule.condition}</span>
                </div>
                <div className="pt-2 border-t border-white/10 mt-2">
                  <p className="text-xs mb-2">String name prefixes:</p>
                  <div className="flex gap-2 text-xs">
                    <span className="px-2 py-1 bg-white/5 rounded">$s = string</span>
                    <span className="px-2 py-1 bg-white/5 rounded">$h = hex</span>
                    <span className="px-2 py-1 bg-white/5 rounded">$r = regex</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : (
        /* Preview Tab */
        <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-6">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="text-xl font-semibold">Generated YARA Rule</h3>
              <p className="text-sm text-gray-400 mt-1">Review and export your rule</p>
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
                Download .yar
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
                <button 
                  onClick={() => setActiveTab('builder')}
                  className="mt-4 text-cyan-400 hover:underline"
                >
                  Go to Builder
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}