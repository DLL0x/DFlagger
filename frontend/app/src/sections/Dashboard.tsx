import { useEffect, useState, useCallback } from 'react';
import {
  Shield,
  AlertTriangle,
  Activity,
  TrendingUp,
  Server,
  RefreshCw,
  Download,
  Settings,
  MoreVertical,
  LayoutDashboard,
  FileText,
  Code,
  Target,
  BarChart3,
  History,
  X,
  Eye,
  EyeOff,
  ChevronRight,
  Globe,
  FileSearch,
  FileCode,
  Clock,
  AlertOctagon
} from 'lucide-react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import { Line, Bar, Doughnut } from 'react-chartjs-2';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

// Types matching your App structure
export type Section = 'dashboard' | 'usecases' | 'lolglobs' | 'logparser' | 'querybuilder' | 'yaragenerator' | 'sigmabuilder' | 'mitreattack' | 'benchmarks' | 'activities' | 'settings';

interface DashboardProps {
  user: { username: string; email: string };
  setSection?: (section: Section) => void;
}

interface Alert {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  source: string;
  time: string;
  status: 'new' | 'investigating' | 'resolved';
}

interface Widget {
  id: string;
  title: string;
  type: 'stats' | 'chart' | 'alerts' | 'activity' | 'quicknav';
  visible: boolean;
  position: number;
  endpoint?: string;
}

interface DashboardStats {
  totalUseCases: number;
  yaraRules: number;
  sigmaRules: number;
  activeMonitors: number;
  systemHealth: number;
  uptime: string;
  lolglobsCount: number;
  mitreMappings: number;
  logParserFiles: number;
  queryBuilderQueries: number;
}

interface ActivityItem {
  id: string;
  type: 'detection' | 'alert' | 'rule' | 'user' | 'system';
  title: string;
  description: string;
  user: string;
  timestamp: string;
  section: Section;
}

// API Configuration
const API_BASE_URL = 'http://localhost:4000/api';

// Navigation Items matching your App.tsx
const NAV_ITEMS = [
  { id: 'usecases' as Section, label: 'Use Case Builder', icon: FileSearch, color: 'text-purple-400', description: 'Create detection logic' },
  { id: 'lolglobs' as Section, label: 'LOLGlobs', icon: Globe, color: 'text-green-400', description: 'Living Off The Land' },
  { id: 'logparser' as Section, label: 'Log Parser', icon: FileText, color: 'text-yellow-400', description: 'Parse & analyze logs' },
  { id: 'querybuilder' as Section, label: 'Query Builder', icon: Code, color: 'text-orange-400', description: 'Build SIEM queries' },
  { id: 'yaragenerator' as Section, label: 'YARA Generator', icon: Shield, color: 'text-red-400', description: 'Malware signatures' },
  { id: 'sigmabuilder' as Section, label: 'Sigma Builder', icon: FileCode, color: 'text-pink-400', description: 'Generic detection rules' },
  { id: 'mitreattack' as Section, label: 'MITRE ATT&CK', icon: Target, color: 'text-indigo-400', description: 'Threat framework' },
  { id: 'benchmarks' as Section, label: 'Benchmarks', icon: BarChart3, color: 'text-blue-400', description: 'Performance metrics' },
  { id: 'activities' as Section, label: 'Activities', icon: Activity, color: 'text-teal-400', description: 'Audit & logs' },
];

export default function Dashboard({ user, setSection }: DashboardProps) {
  // State
  const [currentTime, setCurrentTime] = useState(new Date());
  const [customizeMode, setCustomizeMode] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // Data States
  const [stats, setStats] = useState<DashboardStats>({
    totalUseCases: 0,
    yaraRules: 0,
    sigmaRules: 0,
    lolglobsCount: 0,
    mitreMappings: 0,
    logParserFiles: 0,
    queryBuilderQueries: 0,
    activeMonitors: 0,
    systemHealth: 100,
    uptime: '10d 12h'
  });
  
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [activities, setActivities] = useState<ActivityItem[]>([]);
  const [threatData, setThreatData] = useState<any>(null);
  const [sectionStats, setSectionStats] = useState<Record<string, any>>({});

  // Widget Configuration
  const [widgets, setWidgets] = useState<Widget[]>([
    { id: 'stats', title: 'Overview Stats', type: 'stats', visible: true, position: 1 },
    { id: 'quicknav', title: 'Quick Navigation', type: 'quicknav', visible: true, position: 2 },
    { id: 'threat-timeline', title: 'Threat Timeline', type: 'chart', visible: true, position: 3, endpoint: '/analytics/threats' },
    { id: 'severity', title: 'Severity Distribution', type: 'chart', visible: true, position: 4, endpoint: '/analytics/severity' },
    { id: 'detections', title: 'Top Detections', type: 'chart', visible: true, position: 5, endpoint: '/analytics/detections' },
    { id: 'alerts', title: 'Recent Alerts', type: 'alerts', visible: true, position: 6, endpoint: '/alerts/recent' },
    { id: 'activity', title: 'Recent Activity', type: 'activity', visible: true, position: 7, endpoint: '/activities/recent' },
  ]);

  // Clock
  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  // API Fetch Helper
  const fetchData = useCallback(async (endpoint: string, options?: RequestInit) => {
    try {
      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token') || ''}`,
        },
        ...options,
      });
      
      if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
      return await response.json();
    } catch (err) {
      console.error(`Error fetching ${endpoint}:`, err);
      throw err;
    }
  }, []);

  // Load Dashboard Data
  const loadDashboardData = useCallback(async () => {
    setLoading(true);
    setError(null);
    
    try {
      // Fetch all data in parallel
      const [statsRes, alertsRes, activitiesRes, threatRes] = await Promise.allSettled([
        fetchData('/dashboard/stats'),
        fetchData('/alerts/recent'),
        fetchData('/activities/recent'),
        fetchData('/analytics/threats'),
      ]);

      if (statsRes.status === 'fulfilled') {
        setStats(prev => ({ ...prev, ...statsRes.value }));
      }
      if (alertsRes.status === 'fulfilled') {
        setAlerts(alertsRes.value);
      }
      if (activitiesRes.status === 'fulfilled') {
        setActivities(activitiesRes.value);
      }
      if (threatRes.status === 'fulfilled') {
        setThreatData(threatRes.value);
      }

      // Fetch section-specific stats for quick nav
      const sectionEndpoints = [
        { id: 'usecases', path: '/usecases/stats' },
        { id: 'lolglobs', path: '/lolglobs/stats' },
        { id: 'yaragenerator', path: '/yara/stats' },
        { id: 'sigmabuilder', path: '/sigma/stats' },
        { id: 'mitreattack', path: '/mitre/stats' },
        { id: 'logparser', path: '/logparser/stats' },
        { id: 'querybuilder', path: '/querybuilder/stats' },
      ];

      const sectionPromises = sectionEndpoints.map(sec => 
        fetchData(sec.path).then(data => ({ id: sec.id, data })).catch(() => null)
      );
      
      const sectionResults = await Promise.all(sectionPromises);
      const sectionDataMap: Record<string, any> = {};
      sectionResults.forEach(result => {
        if (result) sectionDataMap[result.id] = result.data;
      });
      setSectionStats(sectionDataMap);

    } catch (err) {
      setError('Failed to load dashboard data. Using fallback data.');
      loadFallbackData();
    } finally {
      setLoading(false);
    }
  }, [fetchData]);

  // Fallback Data
  const loadFallbackData = () => {
    setStats({
      totalUseCases: 24,
      yaraRules: 156,
      sigmaRules: 89,
      lolglobsCount: 45,
      mitreMappings: 120,
      logParserFiles: 12,
      queryBuilderQueries: 34,
      activeMonitors: 8,
      systemHealth: 98,
      uptime: '10d 12h'
    });
    
    setAlerts([
      { id: 'ALT-001', severity: 'critical', title: 'Suspicious PowerShell Execution', source: 'Windows Defender', time: '2 min ago', status: 'new' },
      { id: 'ALT-002', severity: 'high', title: 'Multiple Failed Login Attempts', source: 'Active Directory', time: '5 min ago', status: 'investigating' },
      { id: 'ALT-003', severity: 'medium', title: 'Unusual Network Traffic Detected', source: 'Firewall', time: '12 min ago', status: 'new' },
      { id: 'ALT-004', severity: 'low', title: 'Policy Violation: USB Device', source: 'DLP System', time: '25 min ago', status: 'resolved' },
    ]);

    setActivities([
      { id: '1', type: 'rule', title: 'Created new Use Case', description: 'PowerShell Obfuscation Detection', user: user.username, timestamp: '5 min ago', section: 'usecases' },
      { id: '2', type: 'detection', title: 'Generated YARA rule', description: 'Cobalt Strike beacon signature', user: user.username, timestamp: '15 min ago', section: 'yaragenerator' },
      { id: '3', type: 'alert', title: 'Updated MITRE mapping', description: 'T1055 Process Injection techniques', user: user.username, timestamp: '1 hour ago', section: 'mitreattack' },
      { id: '4', type: 'system', title: 'Parsed log file', description: 'windows_security.evtx processed', user: user.username, timestamp: '2 hours ago', section: 'logparser' },
      { id: '5', type: 'user', title: 'Built Sigma rule', description: 'Detection for DNS tunneling', user: user.username, timestamp: '3 hours ago', section: 'sigmabuilder' },
    ]);
  };

  useEffect(() => {
    loadDashboardData();
    const interval = setInterval(loadDashboardData, 30000);
    return () => clearInterval(interval);
  }, [loadDashboardData]);

  // Widget Management
  const toggleWidget = (widgetId: string) => {
    setWidgets(prev => prev.map(w => 
      w.id === widgetId ? { ...w, visible: !w.visible } : w
    ));
  };

  const moveWidget = (widgetId: string, direction: 'up' | 'down') => {
    setWidgets(prev => {
      const index = prev.findIndex(w => w.id === widgetId);
      if (index === -1) return prev;
      const newIndex = direction === 'up' ? index - 1 : index + 1;
      if (newIndex < 0 || newIndex >= prev.length) return prev;
      
      const newWidgets = [...prev];
      [newWidgets[index], newWidgets[newIndex]] = [newWidgets[newIndex], newWidgets[index]];
      return newWidgets.map((w, i) => ({ ...w, position: i + 1 }));
    });
  };

  // Chart Data
  const threatTimelineData = threatData || {
    labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', 'Now'],
    datasets: [
      {
        label: 'Critical',
        data: [2, 1, 4, 3, 5, 2, 3],
        borderColor: '#ef4444',
        backgroundColor: 'rgba(239, 68, 68, 0.1)',
        fill: true,
        tension: 0.4,
      },
      {
        label: 'High',
        data: [5, 3, 7, 6, 8, 4, 6],
        borderColor: '#f97316',
        backgroundColor: 'rgba(249, 115, 22, 0.1)',
        fill: true,
        tension: 0.4,
      },
    ],
  };

  const severityData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{
      data: [12, 28, 45, 35],
      backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6'],
      borderWidth: 0,
    }],
  };

  const topDetectionsData = {
    labels: ['PowerShell', 'WMI', 'Registry', 'Network', 'Process', 'File'],
    datasets: [{
      label: 'Detections',
      data: [45, 32, 28, 38, 42, 25],
      backgroundColor: 'rgba(34, 211, 238, 0.6)',
      borderColor: '#22d3ee',
      borderWidth: 1,
      borderRadius: 4,
    }],
  };

  // Styles
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400 bg-red-400/10 border-red-400/20';
      case 'high': return 'text-orange-400 bg-orange-400/10 border-orange-400/20';
      case 'medium': return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/20';
      case 'low': return 'text-blue-400 bg-blue-400/10 border-blue-400/20';
      default: return 'text-gray-400 bg-gray-400/10';
    }
  };

  const getStatusDot = (status: string) => {
    switch (status) {
      case 'new': return 'w-2 h-2 rounded-full bg-red-500 animate-pulse';
      case 'investigating': return 'w-2 h-2 rounded-full bg-yellow-500';
      case 'resolved': return 'w-2 h-2 rounded-full bg-green-500';
      default: return 'w-2 h-2 rounded-full bg-gray-500';
    }
  };

  const getActivityIcon = (type: string) => {
    switch (type) {
      case 'detection': return <Target className="w-4 h-4" />;
      case 'alert': return <AlertOctagon className="w-4 h-4" />;
      case 'rule': return <Shield className="w-4 h-4" />;
      case 'user': return <Activity className="w-4 h-4" />;
      case 'system': return <Server className="w-4 h-4" />;
      default: return <Activity className="w-4 h-4" />;
    }
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: { color: '#a1a1aa', font: { size: 11 } },
      },
    },
    scales: {
      x: {
        grid: { color: 'rgba(255, 255, 255, 0.05)' },
        ticks: { color: '#71717a', font: { size: 10 } },
      },
      y: {
        grid: { color: 'rgba(255, 255, 255, 0.05)' },
        ticks: { color: '#71717a', font: { size: 10 } },
      },
    },
  };

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right' as const,
        labels: { color: '#a1a1aa', font: { size: 11 }, padding: 15 },
      },
    },
    cutout: '65%',
  };

  // Navigation Handler
  const navigateToSection = (section: Section) => {
    if (setSection) {
      setSection(section);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent">
            Security Dashboard
          </h1>
          <p className="text-gray-400 text-sm mt-1 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            Live monitoring • {currentTime.toLocaleString()} • {user.email}
          </p>
        </div>
        
        <div className="flex items-center gap-3">
          <button 
            onClick={() => setCustomizeMode(!customizeMode)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${customizeMode ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/50' : 'bg-white/5 border border-white/10 hover:bg-white/10'}`}
          >
            <Settings className="w-4 h-4" />
            {customizeMode ? 'Done' : 'Customize'}
          </button>
          
          <button 
            onClick={loadDashboardData}
            className="px-4 py-2 bg-white/5 border border-white/10 rounded-lg text-sm font-medium hover:bg-white/10 transition-all flex items-center gap-2 disabled:opacity-50"
            disabled={loading}
          >
            <RefreshCw className={`w-4 h-4 ${loading && 'animate-spin'}`} />
            {loading ? 'Syncing...' : 'Refresh'}
          </button>
          
          <button className="px-4 py-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-sm font-medium text-cyan-400 hover:bg-cyan-500/20 transition-all flex items-center gap-2">
            <Download className="w-4 h-4" />
            Export
          </button>
        </div>
      </header>

      {/* Error Banner */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 flex items-center justify-between animate-fade-in">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            <span className="text-red-200">{error}</span>
          </div>
          <button 
            onClick={() => setError(null)}
            className="text-red-400 hover:text-red-300"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
      )}

      {/* Customization Panel */}
      {customizeMode && (
        <div className="bg-slate-900/60 backdrop-blur-xl border border-cyan-500/30 rounded-xl p-6 animate-fade-in">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold text-cyan-400 flex items-center gap-2">
              <LayoutDashboard className="w-5 h-5" />
              Customize Dashboard Layout
            </h3>
            <button 
              onClick={() => setCustomizeMode(false)}
              className="text-gray-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
          
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
            {widgets.map((widget) => (
              <div 
                key={widget.id}
                className={`p-3 rounded-lg border transition-all ${widget.visible ? 'bg-cyan-500/10 border-cyan-500/30' : 'bg-white/5 border-white/10'}`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium">{widget.title}</span>
                  <button 
                    onClick={() => toggleWidget(widget.id)}
                    className={widget.visible ? 'text-cyan-400' : 'text-gray-500'}
                  >
                    {widget.visible ? <Eye className="w-4 h-4" /> : <EyeOff className="w-4 h-4" />}
                  </button>
                </div>
                <div className="flex gap-1">
                  <button 
                    onClick={() => moveWidget(widget.id, 'up')}
                    className="flex-1 py-1 text-xs bg-white/5 hover:bg-white/10 rounded disabled:opacity-30"
                    disabled={widget.position === 1}
                  >
                    ↑
                  </button>
                  <button 
                    onClick={() => moveWidget(widget.id, 'down')}
                    className="flex-1 py-1 text-xs bg-white/5 hover:bg-white/10 rounded disabled:opacity-30"
                    disabled={widget.position === widgets.length}
                  >
                    ↓
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Stats Grid - 6 Columns */}
      {widgets.find(w => w.id === 'stats')?.visible && (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          {[
            { 
              label: 'Use Cases', 
              value: stats.totalUseCases, 
              trend: '+12%', 
              icon: FileSearch, 
              color: 'purple',
              section: 'usecases' as Section
            },
            { 
              label: 'YARA Rules', 
              value: stats.yaraRules, 
              trend: '+5', 
              icon: Shield, 
              color: 'red',
              section: 'yaragenerator' as Section
            },
            { 
              label: 'Sigma Rules', 
              value: stats.sigmaRules, 
              trend: '+3', 
              icon: FileCode, 
              color: 'pink',
              section: 'sigmabuilder' as Section
            },
            { 
              label: 'LOLGlobs', 
              value: stats.lolglobsCount, 
              trend: '+8', 
              icon: Globe, 
              color: 'green',
              section: 'lolglobs' as Section
            },
            { 
              label: 'MITRE Maps', 
              value: stats.mitreMappings, 
              trend: '+15', 
              icon: Target, 
              color: 'indigo',
              section: 'mitreattack' as Section
            },
            { 
              label: 'System Health', 
              value: `${stats.systemHealth}%`, 
              trend: stats.uptime, 
              icon: Activity, 
              color: 'cyan',
              section: 'benchmarks' as Section
            },
          ].map((stat, idx) => (
            <div 
              key={idx}
              onClick={() => navigateToSection(stat.section)}
              className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-4 hover:-translate-y-1 hover:shadow-xl hover:border-cyan-500/30 transition-all cursor-pointer group"
            >
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-gray-400 text-xs mb-1">{stat.label}</p>
                  <p className="text-xl font-bold group-hover:text-cyan-400 transition-colors">{stat.value}</p>
                  <p className="text-[10px] mt-1 text-green-400 flex items-center gap-1">
                    <TrendingUp className="w-3 h-3" /> {stat.trend}
                  </p>
                </div>
                <div className={`p-2 rounded-lg bg-${stat.color}-500/10 text-${stat.color}-400 group-hover:scale-110 transition-transform`}>
                  <stat.icon className="w-5 h-5" />
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Quick Navigation Cards */}
      {widgets.find(w => w.id === 'quicknav')?.visible && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {NAV_ITEMS.map((item) => (
            <button
              key={item.id}
              onClick={() => navigateToSection(item.id)}
              className="p-4 bg-slate-900/40 border border-white/10 rounded-xl hover:bg-slate-800/60 hover:border-cyan-500/30 transition-all group text-left relative overflow-hidden"
            >
              <div className={`absolute top-0 right-0 w-20 h-20 bg-${item.color.replace('text-', '')}/5 rounded-full -mr-10 -mt-10 transition-transform group-hover:scale-150`} />
              <item.icon className={`w-6 h-6 ${item.color} mb-3 group-hover:scale-110 transition-transform`} />
              <h4 className="font-semibold text-sm text-gray-200 group-hover:text-white">{item.label}</h4>
              <p className="text-xs text-gray-500 mt-1">{item.description}</p>
              {sectionStats[item.id]?.count !== undefined && (
                <div className="mt-3 flex items-center gap-2">
                  <span className="text-lg font-bold text-white">{sectionStats[item.id].count}</span>
                  <span className="text-xs text-gray-400">items</span>
                </div>
              )}
            </button>
          ))}
        </div>
      )}

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Timeline */}
        {widgets.find(w => w.id === 'threat-timeline')?.visible && (
          <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-5 lg:col-span-2 hover:border-cyan-500/30 transition-all">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                Threat Timeline (24h)
              </h3>
              <div className="flex gap-2">
                <select className="bg-slate-800 border border-white/10 rounded-lg text-xs px-3 py-1 outline-none focus:border-cyan-500">
                  <option>Last 24h</option>
                  <option>Last 7d</option>
                  <option>Last 30d</option>
                </select>
                <button className="text-gray-400 hover:text-white">
                  <MoreVertical className="w-4 h-4" />
                </button>
              </div>
            </div>
            <div className="h-64">
              <Line data={threatTimelineData} options={chartOptions} />
            </div>
          </div>
        )}

        {/* Severity Distribution */}
        {widgets.find(w => w.id === 'severity')?.visible && (
          <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-5 hover:border-cyan-500/30 transition-all">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold flex items-center gap-2">
                <Shield className="w-4 h-4 text-cyan-400" />
                Severity Distribution
              </h3>
              <button className="text-gray-400 hover:text-white">
                <MoreVertical className="w-4 h-4" />
              </button>
            </div>
            <div className="h-64">
              <Doughnut data={severityData} options={doughnutOptions} />
            </div>
          </div>
        )}
      </div>

      {/* Bottom Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Detections */}
        {widgets.find(w => w.id === 'detections')?.visible && (
          <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-5 hover:border-cyan-500/30 transition-all">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-cyan-400" />
                Top Detection Categories
              </h3>
              <button className="text-gray-400 hover:text-white">
                <MoreVertical className="w-4 h-4" />
              </button>
            </div>
            <div className="h-56">
              <Bar data={topDetectionsData} options={chartOptions} />
            </div>
          </div>
        )}

        {/* Recent Alerts */}
        {widgets.find(w => w.id === 'alerts')?.visible && (
          <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-5 hover:border-cyan-500/30 transition-all">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-cyan-400" />
                Recent Alerts
              </h3>
              <button 
                onClick={() => navigateToSection('activities')}
                className="text-cyan-400 text-sm hover:underline flex items-center gap-1"
              >
                View All <ChevronRight className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 max-h-56 overflow-y-auto pr-1">
              {alerts.length > 0 ? alerts.map((alert) => (
                <div 
                  key={alert.id} 
                  className="flex items-center justify-between p-3 rounded-lg bg-white/5 hover:bg-white/10 transition-colors border border-transparent hover:border-cyan-500/30 group cursor-pointer"
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`px-2 py-0.5 text-xs rounded-full border capitalize ${getSeverityColor(alert.severity)}`}>
                        {alert.severity}
                      </span>
                      <span className="text-xs text-gray-500 font-mono">{alert.id}</span>
                    </div>
                    <p className="font-medium text-sm text-gray-200 group-hover:text-white truncate">{alert.title}</p>
                    <p className="text-xs text-gray-400">{alert.source} • {alert.time}</p>
                  </div>
                  <div className="flex items-center gap-3 ml-3">
                    <span className={getStatusDot(alert.status)} title={alert.status} />
                    <button 
                      onClick={(e) => {
                        e.stopPropagation();
                        navigateToSection('activities');
                      }}
                      className="text-cyan-400 hover:text-cyan-300 text-sm opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap"
                    >
                      Investigate
                    </button>
                  </div>
                </div>
              )) : (
                <div className="text-center py-8 text-gray-500">
                  <Shield className="w-12 h-12 mx-auto mb-3 opacity-20" />
                  <p>No active alerts</p>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Activity Feed */}
      {widgets.find(w => w.id === 'activity')?.visible && (
        <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-5 hover:border-cyan-500/30 transition-all">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold flex items-center gap-2">
              <History className="w-4 h-4 text-cyan-400" />
              Recent Activity Across All Sections
            </h3>
            <button 
              onClick={() => navigateToSection('activities')}
              className="text-cyan-400 text-sm hover:underline"
            >
              View Full Activity Log
            </button>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {activities.length > 0 ? activities.map((activity) => {
              const section = NAV_ITEMS.find(s => s.id === activity.section);
              return (
                <div 
                  key={activity.id} 
                  onClick={() => navigateToSection(activity.section)}
                  className="flex items-start gap-3 p-3 rounded-lg bg-white/5 hover:bg-white/10 transition-all cursor-pointer group border border-transparent hover:border-cyan-500/30"
                >
                  <div className={`p-2 rounded-lg bg-slate-800 ${section?.color || 'text-gray-400'} group-hover:scale-110 transition-transform`}>
                    {getActivityIcon(activity.type)}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-200 group-hover:text-white truncate">{activity.title}</p>
                    <p className="text-xs text-gray-400 mt-1">{activity.description}</p>
                    <p className="text-xs text-gray-500 mt-1 flex items-center gap-1">
                      <Clock className="w-3 h-3" /> {activity.timestamp}
                    </p>
                  </div>
                </div>
              );
            }) : (
              <div className="col-span-4 text-center py-8 text-gray-500">
                <History className="w-12 h-12 mx-auto mb-3 opacity-20" />
                <p>No recent activity</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}