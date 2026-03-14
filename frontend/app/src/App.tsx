import { useState, useEffect } from 'react';
import {
  LayoutDashboard,
  FileSearch,
  Globe,
  FileText,
  Code,
  Shield,
  Target,
  BarChart3,
  Activity,
  Settings,
  LogOut,
  Bell,
  Menu,
  X,
  FileCode
} from 'lucide-react';
import Login from './sections/Login';
import Dashboard from './sections/Dashboard';
import UseCaseBuilder from './sections/UseCaseBuilder';
import LOLGlobs from './sections/LOLGlobs';
import LogParser from './sections/LogParser';
import QueryBuilder from './sections/QueryBuilder';
import YaraGenerator from './sections/YaraGenerator';
import SigmaBuilder from './sections/SigmaBuilder';
import MitreAttack from './sections/MitreAttack';
import Benchmarks from './sections/Benchmarks';
import Activities from './sections/Activities';
import SettingsPanel from './sections/Settings';

export type Section = 'dashboard' | 'usecases' | 'lolglobs' | 'logparser' | 'querybuilder' | 'yaragenerator' | 'sigmabuilder' | 'mitreattack' | 'benchmarks' | 'activities' | 'settings';

interface User {
  username: string;
  email: string;
}

const navItems: { id: Section; label: string; icon: React.ElementType }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'usecases', label: 'Use Case Builder', icon: FileSearch },
  { id: 'lolglobs', label: 'LOLGlobs', icon: Globe },
  { id: 'logparser', label: 'Log Parser', icon: FileText },
  { id: 'querybuilder', label: 'Query Builder', icon: Code },
  { id: 'yaragenerator', label: 'YARA Generator', icon: Shield },
  { id: 'sigmabuilder', label: 'Sigma Builder', icon: FileCode },
  { id: 'mitreattack', label: 'MITRE ATT&CK', icon: Target },
  { id: 'benchmarks', label: 'Benchmarks', icon: BarChart3 },
  { id: 'activities', label: 'Activities', icon: Activity },
  { id: 'settings', label: 'Settings', icon: Settings },
];

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [user, setUser] = useState<User | null>(null);
  const [currentSection, setCurrentSection] = useState<Section>('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [notifications] = useState(3);

  useEffect(() => {
    const savedUser = localStorage.getItem('dflagger_user');
    if (savedUser) {
      setUser(JSON.parse(savedUser));
      setIsLoggedIn(true);
    }
  }, []);

  const handleLogin = (userData: User) => {
    setUser(userData);
    setIsLoggedIn(true);
    localStorage.setItem('dflagger_user', JSON.stringify(userData));
  };

  const handleLogout = () => {
    setUser(null);
    setIsLoggedIn(false);
    localStorage.removeItem('dflagger_user');
  };

  const renderSection = () => {
    switch (currentSection) {
      case 'dashboard':
        return <Dashboard user={user || { username: 'Admin', email: 'admin@dflagger.local' }} />;
      case 'usecases':
        return <UseCaseBuilder />;
      case 'lolglobs':
        return <LOLGlobs />;
      case 'logparser':
        return <LogParser />;
      case 'querybuilder':
        return <QueryBuilder />;
      case 'yaragenerator':
        return <YaraGenerator />;
      case 'sigmabuilder':
        return <SigmaBuilder />;
      case 'mitreattack':
        return <MitreAttack />;
      case 'benchmarks':
        return <Benchmarks />;
      case 'activities':
        return <Activities />;
      case 'settings':
        return <SettingsPanel />;
      default:
        return <Dashboard user={user || { username: 'Admin', email: 'admin@dflagger.local' }} />;
    }
  };

  if (!isLoggedIn) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-gray-100 flex">
      {/* Sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 bg-[#0f0f14] border-r border-white/5 transition-all duration-300 ${
          sidebarOpen ? 'w-64' : 'w-16'
        }`}
      >
        {/* Logo */}
        <div className="h-16 flex items-center px-4 border-b border-white/5">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
              <Shield className="w-5 h-5 text-white" />
            </div>
            {sidebarOpen && (
              <div>
                <h1 className="font-bold text-lg tracking-tight">DFlagger</h1>
                <p className="text-xs text-gray-500">Threat Detection</p>
              </div>
            )}
          </div>
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="ml-auto text-gray-400 hover:text-white"
          >
            {sidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>

        {/* Navigation */}
        <nav className="p-3 space-y-1 overflow-y-auto h-[calc(100vh-4rem)]">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                onClick={() => setCurrentSection(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200 ${
                  currentSection === item.id
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                    : 'text-gray-400 hover:bg-white/5 hover:text-gray-200'
                }`}
              >
                <Icon className="w-5 h-5 flex-shrink-0" />
                {sidebarOpen && <span className="text-sm font-medium">{item.label}</span>}
              </button>
            );
          })}
        </nav>
      </aside>

      {/* Main Content */}
      <main
        className={`flex-1 transition-all duration-300 ${
          sidebarOpen ? 'ml-64' : 'ml-16'
        }`}
      >
        {/* Header */}
        <header className="h-16 bg-[#0f0f14]/80 backdrop-blur-xl border-b border-white/5 flex items-center justify-between px-6 sticky top-0 z-40">
          <div>
            <h2 className="text-lg font-semibold">
              {navItems.find((item) => item.id === currentSection)?.label}
            </h2>
          </div>

          <div className="flex items-center gap-4">
            {/* Notifications */}
            <button className="relative p-2 text-gray-400 hover:text-white transition-colors">
              <Bell className="w-5 h-5" />
              {notifications > 0 && (
                <span className="absolute top-1 right-1 w-4 h-4 bg-red-500 rounded-full text-xs flex items-center justify-center">
                  {notifications}
                </span>
              )}
            </button>

            {/* User */}
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
                <span className="text-sm font-medium">
                  {user?.username?.charAt(0).toUpperCase() || 'A'}
                </span>
              </div>
              {sidebarOpen && (
                <div className="hidden sm:block">
                  <p className="text-sm font-medium">{user?.username || 'Admin'}</p>
                  <p className="text-xs text-gray-500">{user?.email || 'admin@dflagger.local'}</p>
                </div>
              )}
            </div>

            {/* Logout */}
            <button
              onClick={handleLogout}
              className="p-2 text-gray-400 hover:text-red-400 transition-colors"
            >
              <LogOut className="w-5 h-5" />
            </button>
          </div>
        </header>

        {/* Page Content */}
        <div className="p-6">{renderSection()}</div>
      </main>
    </div>
  );
}

export default App;
