import { useState, useEffect, useCallback } from 'react';
import {
  Activity,
  Search,
  User,
  FileSearch,
  Shield,
  AlertTriangle,
  Clock,
  Download,
  RefreshCw,
  ChevronRight,
  Calendar,
  Filter,
  Eye,
  Server,
  Terminal,
  Settings,
  LogIn,
  LogOut,
  FileDown,
  AlertOctagon,
  X,
  Loader2,
  ChevronLeft,
  Database
} from 'lucide-react';

interface ActivityItem {
  id: string;
  type: 'detection' | 'alert' | 'use_case' | 'user' | 'system' | 'auth' | 'mitre' | 'benchmark' | 'export' | 'settings' | 'query' | 'incident';
  title: string;
  description: string;
  user: string;
  userId?: string;
  timestamp: string;
  ipAddress?: string;
  userAgent?: string;
  severity?: 'low' | 'medium' | 'high' | 'critical' | 'info';
  status?: 'success' | 'warning' | 'error' | 'pending';
  metadata?: {
    resourceId?: string;
    resourceType?: string;
    changes?: any;
    details?: any;
  };
}

interface ApiResponse {
  activities: ActivityItem[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

const API_BASE_URL = 'http://localhost:4000/api';

const getTypeIcon = (type: string) => {
  switch (type) {
    case 'detection':
      return <FileSearch className="w-4 h-4" />;
    case 'alert':
      return <AlertTriangle className="w-4 h-4" />;
    case 'use_case':
      return <Shield className="w-4 h-4" />;
    case 'user':
      return <User className="w-4 h-4" />;
    case 'system':
      return <Server className="w-4 h-4" />;
    case 'auth':
      return <LogIn className="w-4 h-4" />;
    case 'mitre':
      return <Terminal className="w-4 h-4" />;
    case 'benchmark':
      return <Shield className="w-4 h-4" />;
    case 'export':
      return <FileDown className="w-4 h-4" />;
    case 'settings':
      return <Settings className="w-4 h-4" />;
    case 'query':
      return <Database className="w-4 h-4" />;
    case 'incident':
      return <AlertOctagon className="w-4 h-4" />;
    default:
      return <Activity className="w-4 h-4" />;
  }
};

const getTypeColor = (type: string) => {
  switch (type) {
    case 'detection':
      return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
    case 'alert':
      return 'bg-red-500/10 text-red-400 border-red-500/20';
    case 'use_case':
      return 'bg-purple-500/10 text-purple-400 border-purple-500/20';
    case 'user':
      return 'bg-green-500/10 text-green-400 border-green-500/20';
    case 'system':
      return 'bg-gray-500/10 text-gray-400 border-gray-500/20';
    case 'auth':
      return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20';
    case 'mitre':
      return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
    case 'benchmark':
      return 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20';
    case 'export':
      return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
    case 'settings':
      return 'bg-pink-500/10 text-pink-400 border-pink-500/20';
    case 'query':
      return 'bg-teal-500/10 text-teal-400 border-teal-500/20';
    case 'incident':
      return 'bg-red-600/10 text-red-500 border-red-600/20';
    default:
      return 'bg-gray-500/10 text-gray-400 border-gray-500/20';
  }
};

const getSeverityColor = (severity?: string) => {
  switch (severity) {
    case 'critical':
      return 'text-red-500 bg-red-500/10';
    case 'high':
      return 'text-orange-400 bg-orange-400/10';
    case 'medium':
      return 'text-yellow-400 bg-yellow-400/10';
    case 'low':
      return 'text-green-400 bg-green-400/10';
    default:
      return 'text-gray-400 bg-gray-400/10';
  }
};

export default function Activities() {
  const [activities, setActivities] = useState<ActivityItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<string>('all');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [dateRange, setDateRange] = useState({ start: '', end: '' });
  const [selectedActivity, setSelectedActivity] = useState<ActivityItem | null>(null);
  const [pagination, setPagination] = useState({
    page: 1,
    limit: 20,
    total: 0,
    totalPages: 1
  });
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());

  // Fetch activities from backend
  const fetchActivities = useCallback(async (page = 1, append = false) => {
    try {
      setLoading(true);
      setError(null);

      const queryParams = new URLSearchParams({
        page: page.toString(),
        limit: pagination.limit.toString(),
        ...(searchQuery && { search: searchQuery }),
        ...(filterType !== 'all' && { type: filterType }),
        ...(filterSeverity !== 'all' && { severity: filterSeverity }),
        ...(dateRange.start && { startDate: dateRange.start }),
        ...(dateRange.end && { endDate: dateRange.end })
      });

      const response = await fetch(`${API_BASE_URL}/activities?${queryParams}`, {
        headers: {
          'Content-Type': 'application/json',
          // Add auth token if available
          'Authorization': `Bearer ${localStorage.getItem('token') || ''}`
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data: ApiResponse = await response.json();
      
      if (append) {
        setActivities(prev => [...prev, ...data.activities]);
      } else {
        setActivities(data.activities);
      }
      
      setPagination(data.pagination);
      setLastRefresh(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch activities');
      console.error('Error fetching activities:', err);
    } finally {
      setLoading(false);
    }
  }, [searchQuery, filterType, filterSeverity, dateRange, pagination.limit]);

  // Initial load and polling
  useEffect(() => {
    fetchActivities(1, false);
    
    // Set up polling every 30 seconds if auto-refresh is enabled
    let interval: NodeJS.Timeout;
    if (autoRefresh) {
      interval = setInterval(() => {
        fetchActivities(1, false);
      }, 30000);
    }
    
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [fetchActivities, autoRefresh]);

  // Handle search with debounce
  useEffect(() => {
    const timer = setTimeout(() => {
      fetchActivities(1, false);
    }, 500);
    return () => clearTimeout(timer);
  }, [searchQuery, filterType, filterSeverity, dateRange]);

  // Export to CSV
  const handleExport = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/activities/export?${new URLSearchParams({
        ...(searchQuery && { search: searchQuery }),
        ...(filterType !== 'all' && { type: filterType }),
        ...(filterSeverity !== 'all' && { severity: filterSeverity }),
        ...(dateRange.start && { startDate: dateRange.start }),
        ...(dateRange.end && { endDate: dateRange.end })
      })}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token') || ''}`
        }
      });
      
      if (!response.ok) throw new Error('Export failed');
      
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `audit-log-${new Date().toISOString().split('T')[0]}.csv`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      console.error('Export error:', err);
      alert('Failed to export activities');
    }
  };

  // Load more (pagination)
  const loadMore = () => {
    if (pagination.page < pagination.totalPages) {
      fetchActivities(pagination.page + 1, true);
    }
  };

  const activityTypes = [
    { value: 'all', label: 'All Types' },
    { value: 'detection', label: 'Detections' },
    { value: 'alert', label: 'Alerts' },
    { value: 'use_case', label: 'Use Cases' },
    { value: 'incident', label: 'Incidents' },
    { value: 'mitre', label: 'MITRE ATT&CK' },
    { value: 'benchmark', label: 'Security Controls' },
    { value: 'auth', label: 'Authentication' },
    { value: 'user', label: 'User Actions' },
    { value: 'export', label: 'Exports' },
    { value: 'settings', label: 'Settings' },
    { value: 'system', label: 'System' },
    { value: 'query', label: 'Queries' }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold">Audit Log</h2>
          <p className="text-gray-400 mt-1">
            Complete application activity trail • Last updated: {lastRefresh.toLocaleTimeString()}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`btn-secondary flex items-center gap-2 ${autoRefresh ? 'text-green-400' : ''}`}
          >
            <RefreshCw className={`w-4 h-4 ${autoRefresh ? 'animate-spin' : ''}`} />
            {autoRefresh ? 'Auto-refresh On' : 'Auto-refresh Off'}
          </button>
          <button 
            onClick={() => fetchActivities(1, false)}
            className="btn-secondary flex items-center gap-2"
            disabled={loading}
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button 
            onClick={handleExport}
            className="btn-secondary flex items-center gap-2"
          >
            <Download className="w-4 h-4" />
            Export CSV
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="glass-card p-4 space-y-4">
        <div className="flex flex-col lg:flex-row gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search activities, descriptions, users, or IP addresses..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="input-field w-full pl-10"
            />
          </div>
          <div className="flex gap-2 flex-wrap">
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="input-field"
            >
              {activityTypes.map(type => (
                <option key={type.value} value={type.value}>{type.label}</option>
              ))}
            </select>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="input-field"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>
        </div>
        
        {/* Date Range */}
        <div className="flex gap-4 items-center border-t border-white/5 pt-4">
          <Calendar className="w-4 h-4 text-gray-400" />
          <span className="text-sm text-gray-400">Date Range:</span>
          <input
            type="datetime-local"
            value={dateRange.start}
            onChange={(e) => setDateRange({ ...dateRange, start: e.target.value })}
            className="input-field text-sm"
          />
          <span className="text-gray-500">to</span>
          <input
            type="datetime-local"
            value={dateRange.end}
            onChange={(e) => setDateRange({ ...dateRange, end: e.target.value })}
            className="input-field text-sm"
          />
          {(dateRange.start || dateRange.end) && (
            <button 
              onClick={() => setDateRange({ start: '', end: '' })}
              className="text-xs text-cyan-400 hover:text-cyan-300"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 flex items-center gap-3 text-red-400">
          <AlertTriangle className="w-5 h-5" />
          <span>Error loading activities: {error}</span>
          <button 
            onClick={() => fetchActivities(1, false)}
            className="ml-auto text-sm underline hover:no-underline"
          >
            Retry
          </button>
        </div>
      )}

      {/* Activity List */}
      <div className="glass-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th className="w-32">Type</th>
                <th>Activity</th>
                <th>Description</th>
                <th>User</th>
                <th>Severity</th>
                <th>Time</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {activities.length === 0 && !loading ? (
                <tr>
                  <td colSpan={7} className="text-center py-8 text-gray-500">
                    No activities found matching your criteria
                  </td>
                </tr>
              ) : (
                activities.map((activity) => (
                  <tr key={activity.id} className="hover:bg-white/5 transition-colors">
                    <td>
                      <div className={`inline-flex items-center gap-2 px-2 py-1 rounded-lg border ${getTypeColor(activity.type)}`}>
                        {getTypeIcon(activity.type)}
                        <span className="text-xs capitalize">{activity.type.replace('_', ' ')}</span>
                      </div>
                    </td>
                    <td className="font-medium">{activity.title}</td>
                    <td className="text-gray-400 max-w-xs truncate" title={activity.description}>
                      {activity.description}
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <div className="w-6 h-6 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
                          <span className="text-xs">{activity.user.charAt(0).toUpperCase()}</span>
                        </div>
                        <div className="flex flex-col">
                          <span className="text-sm">{activity.user}</span>
                          {activity.ipAddress && (
                            <span className="text-xs text-gray-500">{activity.ipAddress}</span>
                          )}
                        </div>
                      </div>
                    </td>
                    <td>
                      {activity.severity && (
                        <span className={`badge ${getSeverityColor(activity.severity)}`}>
                          {activity.severity}
                        </span>
                      )}
                    </td>
                    <td>
                      <div className="flex items-center gap-2 text-gray-400">
                        <Clock className="w-3 h-3" />
                        <span className="text-sm">
                          {new Date(activity.timestamp).toLocaleString()}
                        </span>
                      </div>
                    </td>
                    <td>
                      <button 
                        onClick={() => setSelectedActivity(activity)}
                        className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                      >
                        <Eye className="w-4 h-4" />
                        View
                      </button>
                    </td>
                  </tr>
                ))
              )}
              {loading && (
                <tr>
                  <td colSpan={7} className="text-center py-4">
                    <Loader2 className="w-6 h-6 animate-spin mx-auto text-cyan-400" />
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-400">
          Showing {activities.length} of {pagination.total} activities
        </p>
        <div className="flex gap-2">
          <button 
            className="btn-secondary"
            disabled={pagination.page <= 1 || loading}
            onClick={() => fetchActivities(pagination.page - 1, false)}
          >
            <ChevronLeft className="w-4 h-4" />
            Previous
          </button>
          <span className="px-4 py-2 text-sm text-gray-400">
            Page {pagination.page} of {pagination.totalPages}
          </span>
          <button 
            className="btn-secondary"
            disabled={pagination.page >= pagination.totalPages || loading}
            onClick={() => loadMore()}
          >
            Next
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Activity Detail Modal */}
      {selectedActivity && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="glass-card w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between p-6 border-b border-white/5">
              <div>
                <div className="flex items-center gap-3 mb-2">
                  <div className={`inline-flex items-center gap-2 px-2 py-1 rounded-lg border ${getTypeColor(selectedActivity.type)}`}>
                    {getTypeIcon(selectedActivity.type)}
                    <span className="text-xs capitalize">{selectedActivity.type.replace('_', ' ')}</span>
                  </div>
                  {selectedActivity.severity && (
                    <span className={`badge ${getSeverityColor(selectedActivity.severity)}`}>
                      {selectedActivity.severity}
                    </span>
                  )}
                </div>
                <h3 className="text-xl font-bold">{selectedActivity.title}</h3>
              </div>
              <button
                onClick={() => setSelectedActivity(null)}
                className="text-gray-400 hover:text-white"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            <div className="p-6 space-y-6">
              {/* Description */}
              <div>
                <h4 className="font-semibold mb-2 text-gray-300">Description</h4>
                <p className="text-gray-400">{selectedActivity.description}</p>
              </div>

              {/* Technical Details */}
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-white/5 rounded-lg p-4 border border-white/5">
                  <h4 className="text-sm font-semibold text-gray-400 mb-1">User</h4>
                  <p className="text-sm font-medium">{selectedActivity.user}</p>
                  {selectedActivity.userId && (
                    <p className="text-xs text-gray-500 mt-1">ID: {selectedActivity.userId}</p>
                  )}
                </div>
                <div className="bg-white/5 rounded-lg p-4 border border-white/5">
                  <h4 className="text-sm font-semibold text-gray-400 mb-1">Timestamp</h4>
                  <p className="text-sm font-medium">
                    {new Date(selectedActivity.timestamp).toLocaleString()}
                  </p>
                  <p className="text-xs text-gray-500 mt-1">
                    {new Date(selectedActivity.timestamp).toISOString()}
                  </p>
                </div>
                {selectedActivity.ipAddress && (
                  <div className="bg-white/5 rounded-lg p-4 border border-white/5">
                    <h4 className="text-sm font-semibold text-gray-400 mb-1">IP Address</h4>
                    <p className="text-sm font-medium font-mono">{selectedActivity.ipAddress}</p>
                  </div>
                )}
                {selectedActivity.status && (
                  <div className="bg-white/5 rounded-lg p-4 border border-white/5">
                    <h4 className="text-sm font-semibold text-gray-400 mb-1">Status</h4>
                    <span className={`inline-flex items-center gap-1 text-sm ${
                      selectedActivity.status === 'success' ? 'text-green-400' :
                      selectedActivity.status === 'error' ? 'text-red-400' :
                      selectedActivity.status === 'warning' ? 'text-yellow-400' :
                      'text-gray-400'
                    }`}>
                      <span className={`w-2 h-2 rounded-full ${
                        selectedActivity.status === 'success' ? 'bg-green-400' :
                        selectedActivity.status === 'error' ? 'bg-red-400' :
                        selectedActivity.status === 'warning' ? 'bg-yellow-400' :
                        'bg-gray-400'
                      }`} />
                      {selectedActivity.status.charAt(0).toUpperCase() + selectedActivity.status.slice(1)}
                    </span>
                  </div>
                )}
              </div>

              {/* Metadata */}
              {selectedActivity.metadata && (
                <div>
                  <h4 className="font-semibold mb-2 text-gray-300">Additional Metadata</h4>
                  <div className="bg-black/30 rounded-lg p-4 border border-white/5">
                    <pre className="text-xs text-gray-400 overflow-x-auto">
                      {JSON.stringify(selectedActivity.metadata, null, 2)}
                    </pre>
                  </div>
                </div>
              )}

              {/* User Agent */}
              {selectedActivity.userAgent && (
                <div>
                  <h4 className="font-semibold mb-2 text-gray-300">User Agent</h4>
                  <p className="text-sm text-gray-400 font-mono bg-black/30 p-2 rounded">
                    {selectedActivity.userAgent}
                  </p>
                </div>
              )}
            </div>

            <div className="flex items-center justify-end gap-3 p-6 border-t border-white/5">
              <button
                onClick={() => setSelectedActivity(null)}
                className="btn-primary"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}