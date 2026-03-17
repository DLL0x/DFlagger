import { useState, useEffect } from 'react';
import {
  User,
  Bell,
  Shield,
  Database,
  Key,
  Moon,
  Sun,
  Save,
  CheckCircle,
  Users,
  Lock,
  FileText,
  Clock,
  Globe,
  Server,
  AlertTriangle,
  Plus,
  Trash2,
  Edit2,
  X,
  RefreshCw,
  Eye,
  ShieldAlert,
  Archive,
  Settings as SettingsIcon,
  Activity,
  LogOut
} from 'lucide-react';

interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  status: 'active' | 'inactive' | 'suspended';
  lastLogin: string;
  mfaEnabled: boolean;
  createdAt: string;
  avatar?: string;
}

interface Role {
  id: string;
  name: string;
  description: string;
  permissions: string[];
  userCount: number;
  isSystem: boolean;
}

interface SecurityPolicy {
  passwordMinLength: number;
  passwordComplexity: boolean;
  passwordExpiryDays: number;
  mfaRequired: boolean;
  mfaMethods: string[];
  sessionTimeout: number;
  maxLoginAttempts: number;
  lockoutDuration: number;
  ipAllowlist: string[];
  enforceSSO: boolean;
}

interface DataRetention {
  auditLogs: number;
  userActivities: number;
  detectionLogs: number;
  alertHistory: number;
  backupRetention: number;
  autoPurge: boolean;
}

interface SystemConfig {
  maintenanceMode: boolean;
  debugMode: boolean;
  maxFileUploadSize: number;
  allowedFileTypes: string[];
  rateLimit: number;
  timezone: string;
  dateFormat: string;
}

const API_BASE_URL = 'http://localhost:4000/api';

export default function SettingsPanel() {
  const [activeSection, setActiveSection] = useState('profile');
  const [saved, setSaved] = useState(false);
  const [darkMode, setDarkMode] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // User Management State
  const [users, setUsers] = useState<User[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [showUserModal, setShowUserModal] = useState(false);
  const [showRoleModal, setShowRoleModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [selectedRole, setSelectedRole] = useState<Role | null>(null);
  
  // Security Policies
  const [securityPolicy, setSecurityPolicy] = useState<SecurityPolicy>({
    passwordMinLength: 12,
    passwordComplexity: true,
    passwordExpiryDays: 90,
    mfaRequired: true,
    mfaMethods: ['totp', 'sms', 'email'],
    sessionTimeout: 30,
    maxLoginAttempts: 5,
    lockoutDuration: 30,
    ipAllowlist: [],
    enforceSSO: false
  });
  
  // Data Retention
  const [dataRetention, setDataRetention] = useState<DataRetention>({
    auditLogs: 365,
    userActivities: 180,
    detectionLogs: 90,
    alertHistory: 365,
    backupRetention: 30,
    autoPurge: true
  });
  
  // System Config
  const [systemConfig, setSystemConfig] = useState<SystemConfig>({
    maintenanceMode: false,
    debugMode: false,
    maxFileUploadSize: 10,
    allowedFileTypes: ['.json', '.csv', '.xml', '.log'],
    rateLimit: 1000,
    timezone: 'UTC',
    dateFormat: 'YYYY-MM-DD HH:mm:ss'
  });

  // Profile Form State
  const [profileForm, setProfileForm] = useState({
    name: 'Administrator',
    email: 'admin@dflagger.local',
    title: '',
    department: 'Security Operations Center (SOC)',
    phone: '',
    timezone: 'UTC'
  });

  // Password Change State
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [passwordSuccess, setPasswordSuccess] = useState(false);

  // Load initial data
  useEffect(() => {
    fetchUsers();
    fetchRoles();
    fetchSecuritySettings();
    loadCurrentUser();
  }, []);

  // Load current user from localStorage
  const loadCurrentUser = () => {
    const savedUser = localStorage.getItem('dflagger_user');
    if (savedUser) {
      const userData = JSON.parse(savedUser);
      setProfileForm({
        name: userData.name || userData.username || 'Administrator',
        email: userData.email || 'admin@dflagger.local',
        title: userData.title || '',
        department: userData.department || 'Security Operations Center (SOC)',
        phone: userData.phone || '',
        timezone: userData.timezone || 'UTC'
      });
    }
  };

  const fetchUsers = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/settings/admin/users`);
      if (response.ok) {
        const data = await response.json();
        setUsers(data.users || []);
      }
    } catch (err) {
      console.error('Failed to fetch users:', err);
    }
  };

  const fetchRoles = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/settings/admin/roles`);
      if (response.ok) {
        const data = await response.json();
        setRoles(data.roles || []);
      }
    } catch (err) {
      console.error('Failed to fetch roles:', err);
    }
  };

  const fetchSecuritySettings = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/settings/admin/security-settings`);
      if (response.ok) {
        const data = await response.json();
        if (data.security) setSecurityPolicy(data.security);
        if (data.retention) setDataRetention(data.retention);
        if (data.system) setSystemConfig(data.system);
      }
    } catch (err) {
      console.error('Failed to fetch settings:', err);
    }
  };

  // Save profile changes
  const saveProfile = async () => {
    setLoading(true);
    try {
      // Update localStorage
      const savedUser = localStorage.getItem('dflagger_user');
      if (savedUser) {
        const userData = JSON.parse(savedUser);
        const updatedUser = {
          ...userData,
          name: profileForm.name,
          email: profileForm.email,
          title: profileForm.title,
          department: profileForm.department,
          phone: profileForm.phone,
          timezone: profileForm.timezone
        };
        localStorage.setItem('dflagger_user', JSON.stringify(updatedUser));
      }
      
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (err) {
      setError('Failed to save profile');
    } finally {
      setLoading(false);
    }
  };

  // Change password
  const changePassword = async () => {
    setPasswordError(null);
    setPasswordSuccess(false);
    
    // Validation
    if (!passwordForm.currentPassword) {
      setPasswordError('Current password is required');
      return;
    }
    if (!passwordForm.newPassword) {
      setPasswordError('New password is required');
      return;
    }
    if (passwordForm.newPassword.length < 8) {
      setPasswordError('Password must be at least 8 characters');
      return;
    }
    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      setPasswordError('New passwords do not match');
      return;
    }
    
    setLoading(true);
    try {
      const savedUser = localStorage.getItem('dflagger_user');
      const userData = savedUser ? JSON.parse(savedUser) : null;
      
      const response = await fetch(`${API_BASE_URL}/settings/change-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: userData?.email || profileForm.email,
          currentPassword: passwordForm.currentPassword,
          newPassword: passwordForm.newPassword
        })
      });
      
      if (response.ok) {
        setPasswordSuccess(true);
        setPasswordForm({ currentPassword: '', newPassword: '', confirmPassword: '' });
        setTimeout(() => setPasswordSuccess(false), 3000);
      } else {
        const data = await response.json();
        setPasswordError(data.error || 'Failed to change password');
      }
    } catch (err) {
      setPasswordError('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async (section: string, data: any) => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/settings/${section}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      
      if (response.ok) {
        setSaved(true);
        setTimeout(() => setSaved(false), 2000);
      } else {
        throw new Error('Failed to save settings');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Save failed');
    } finally {
      setLoading(false);
    }
  };

  const settingSections = [
    { id: 'profile', name: 'Profile', icon: User },
    { id: 'users', name: 'User Management', icon: Users },
    { id: 'roles', name: 'Roles & Permissions', icon: Shield },
    { id: 'security', name: 'Security Policies', icon: Lock },
    { id: 'compliance', name: 'Compliance & Audit', icon: FileText },
    { id: 'data', name: 'Data Management', icon: Database },
    { id: 'integrations', name: 'Integrations', icon: Server },
    { id: 'api', name: 'API & Access', icon: Key },
    { id: 'system', name: 'System Settings', icon: SettingsIcon },
    { id: 'appearance', name: 'Appearance', icon: Sun }
  ];

  const availablePermissions = [
    'users:read', 'users:write', 'users:delete',
    'roles:read', 'roles:write', 'roles:delete',
    'detections:read', 'detections:write', 'detections:delete',
    'alerts:read', 'alerts:write', 'alerts:manage',
    'mitre:read', 'benchmarks:read',
    'settings:read', 'settings:write',
    'audit:read', 'system:manage'
  ];

  const getRolePermissions = (roleId: string) => {
    const role = roles.find(r => r.id === roleId);
    return role?.permissions || [];
  };

  // Render different sections
  const renderSection = () => {
    switch (activeSection) {
      case 'profile':
        return (
          <div className="space-y-8">
            {/* Profile Info */}
            <div>
              <h3 className="text-lg font-semibold mb-4">Profile Settings</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Full Name *</label>
                  <input 
                    type="text" 
                    value={profileForm.name}
                    onChange={(e) => setProfileForm({...profileForm, name: e.target.value})}
                    className="input-field w-full" 
                  />
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Email *</label>
                  <input 
                    type="email" 
                    value={profileForm.email}
                    onChange={(e) => setProfileForm({...profileForm, email: e.target.value})}
                    className="input-field w-full" 
                  />
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Job Title</label>
                  <input 
                    type="text" 
                    value={profileForm.title}
                    onChange={(e) => setProfileForm({...profileForm, title: e.target.value})}
                    placeholder="Security Administrator" 
                    className="input-field w-full" 
                  />
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Department</label>
                  <select 
                    value={profileForm.department}
                    onChange={(e) => setProfileForm({...profileForm, department: e.target.value})}
                    className="input-field w-full"
                  >
                    <option>Security Operations Center (SOC)</option>
                    <option>Incident Response</option>
                    <option>Threat Intelligence</option>
                    <option>Governance, Risk & Compliance</option>
                    <option>IT Administration</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Phone Number</label>
                  <input 
                    type="tel" 
                    value={profileForm.phone}
                    onChange={(e) => setProfileForm({...profileForm, phone: e.target.value})}
                    placeholder="+1 (555) 123-4567" 
                    className="input-field w-full" 
                  />
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Timezone</label>
                  <select 
                    value={profileForm.timezone}
                    onChange={(e) => setProfileForm({...profileForm, timezone: e.target.value})}
                    className="input-field w-full"
                  >
                    <option value="UTC">UTC</option>
                    <option value="EST">Eastern Time (EST/EDT)</option>
                    <option value="CST">Central Time (CST/CDT)</option>
                    <option value="MST">Mountain Time (MST/MDT)</option>
                    <option value="PST">Pacific Time (PST/PDT)</option>
                    <option value="GMT">Greenwich Mean Time (GMT)</option>
                    <option value="CET">Central European Time (CET/CEST)</option>
                  </select>
                </div>
              </div>
              <div className="mt-6">
                <button 
                  onClick={saveProfile}
                  disabled={loading}
                  className="btn-primary flex items-center gap-2"
                >
                  {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                  Save Profile
                </button>
              </div>
            </div>

            {/* Password Change */}
            <div className="border-t border-white/10 pt-6">
              <h4 className="font-medium mb-4 flex items-center gap-2">
                <Key className="w-4 h-4 text-cyan-400" />
                Change Password
              </h4>
              <div className="bg-slate-900/50 border border-white/10 rounded-lg p-4 space-y-4 max-w-md">
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Current Password</label>
                  <input 
                    type="password" 
                    value={passwordForm.currentPassword}
                    onChange={(e) => setPasswordForm({...passwordForm, currentPassword: e.target.value})}
                    className="input-field w-full" 
                    placeholder="Enter current password"
                  />
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-1">New Password</label>
                  <input 
                    type="password" 
                    value={passwordForm.newPassword}
                    onChange={(e) => setPasswordForm({...passwordForm, newPassword: e.target.value})}
                    className="input-field w-full" 
                    placeholder="Enter new password (min 8 chars)"
                  />
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Confirm New Password</label>
                  <input 
                    type="password" 
                    value={passwordForm.confirmPassword}
                    onChange={(e) => setPasswordForm({...passwordForm, confirmPassword: e.target.value})}
                    className="input-field w-full" 
                    placeholder="Confirm new password"
                  />
                </div>
                
                {passwordError && (
                  <div className="p-3 bg-red-500/10 border border-red-500/20 rounded text-red-400 text-sm">
                    {passwordError}
                  </div>
                )}
                
                {passwordSuccess && (
                  <div className="p-3 bg-green-500/10 border border-green-500/20 rounded text-green-400 text-sm flex items-center gap-2">
                    <CheckCircle className="w-4 h-4" />
                    Password changed successfully!
                  </div>
                )}
                
                <button 
                  onClick={changePassword}
                  disabled={loading}
                  className="btn-primary w-full flex items-center justify-center gap-2"
                >
                  {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Key className="w-4 h-4" />}
                  Change Password
                </button>
              </div>
            </div>

            <div className="border-t border-white/5 pt-6">
              <h4 className="font-medium mb-4 text-red-400">Danger Zone</h4>
              <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-medium">Delete Account</p>
                    <p className="text-sm text-gray-400">Permanently delete your account and all data</p>
                  </div>
                  <button className="btn-secondary text-red-400 border-red-500/30 hover:bg-red-500/10">
                    Delete Account
                  </button>
                </div>
              </div>
            </div>
          </div>
        );

      case 'users':
        return (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold">User Management</h3>
                <p className="text-sm text-gray-400">Manage users, permissions, and access levels</p>
              </div>
              <button 
                onClick={() => { setSelectedUser(null); setShowUserModal(true); }}
                className="btn-primary flex items-center gap-2"
              >
                <Plus className="w-4 h-4" />
                Invite User
              </button>
            </div>

            <div className="glass-card overflow-hidden">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Last Login</th>
                    <th>MFA</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user) => (
                    <tr key={user.id}>
                      <td>
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-sm font-bold">
                            {user.name.charAt(0)}
                          </div>
                          <div>
                            <p className="font-medium">{user.name}</p>
                            <p className="text-xs text-gray-500">{user.email}</p>
                          </div>
                        </div>
                      </td>
                      <td>
                        <span className="badge badge-info">{user.role}</span>
                      </td>
                      <td>
                        <span className={`badge ${
                          user.status === 'active' ? 'badge-success' :
                          user.status === 'suspended' ? 'badge-warning' :
                          'badge-secondary'
                        }`}>
                          {user.status}
                        </span>
                      </td>
                      <td className="text-sm text-gray-400">
                        {user.lastLogin ? new Date(user.lastLogin).toLocaleDateString() : 'Never'}
                      </td>
                      <td>
                        {user.mfaEnabled ? (
                          <Shield className="w-4 h-4 text-green-400" />
                        ) : (
                          <span className="text-xs text-gray-500">Disabled</span>
                        )}
                      </td>
                      <td>
                        <div className="flex gap-2">
                          <button 
                            onClick={() => { setSelectedUser(user); setShowUserModal(true); }}
                            className="p-1 hover:bg-white/10 rounded"
                          >
                            <Edit2 className="w-4 h-4 text-cyan-400" />
                          </button>
                          <button className="p-1 hover:bg-white/10 rounded">
                            <LogOut className="w-4 h-4 text-yellow-400" />
                          </button>
                          <button className="p-1 hover:bg-white/10 rounded">
                            <Trash2 className="w-4 h-4 text-red-400" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* User Modal */}
            {showUserModal && (
              <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
                <div className="glass-card w-full max-w-md">
                  <div className="flex items-center justify-between p-6 border-b border-white/5">
                    <h3 className="text-lg font-semibold">
                      {selectedUser ? 'Edit User' : 'Invite New User'}
                    </h3>
                    <button onClick={() => setShowUserModal(false)} className="text-gray-400 hover:text-white">
                      <X className="w-5 h-5" />
                    </button>
                  </div>
                  <div className="p-6 space-y-4">
                    <div>
                      <label className="block text-sm text-gray-400 mb-1">Email *</label>
                      <input 
                        type="email" 
                        defaultValue={selectedUser?.email}
                        className="input-field w-full" 
                        placeholder="user@company.com"
                      />
                    </div>
                    <div>
                      <label className="block text-sm text-gray-400 mb-1">Full Name *</label>
                      <input 
                        type="text" 
                        defaultValue={selectedUser?.name}
                        className="input-field w-full" 
                        placeholder="John Doe"
                      />
                    </div>
                    <div>
                      <label className="block text-sm text-gray-400 mb-1">Role *</label>
                      <select className="input-field w-full" defaultValue={selectedUser?.role}>
                        {roles.map(role => (
                          <option key={role.id} value={role.id}>{role.name}</option>
                        ))}
                      </select>
                    </div>
                    <div className="flex items-center gap-2 p-3 bg-white/5 rounded-lg">
                      <input type="checkbox" id="mfa-required" className="rounded bg-white/10 border-white/20" />
                      <label htmlFor="mfa-required" className="text-sm">Require MFA for this user</label>
                    </div>
                    <div className="flex items-center gap-2 p-3 bg-white/5 rounded-lg">
                      <input type="checkbox" id="send-email" className="rounded bg-white/10 border-white/20" defaultChecked />
                      <label htmlFor="send-email" className="text-sm">Send invitation email</label>
                    </div>
                  </div>
                  <div className="flex items-center justify-end gap-3 p-6 border-t border-white/5">
                    <button onClick={() => setShowUserModal(false)} className="btn-secondary">Cancel</button>
                    <button className="btn-primary">
                      {selectedUser ? 'Save Changes' : 'Send Invitation'}
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        );

      case 'roles':
        return (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold">Roles & Permissions</h3>
                <p className="text-sm text-gray-400">Configure RBAC and access controls</p>
              </div>
              <button 
                onClick={() => { setSelectedRole(null); setShowRoleModal(true); }}
                className="btn-primary flex items-center gap-2"
              >
                <Plus className="w-4 h-4" />
                Create Role
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {roles.map((role) => (
                <div key={role.id} className="glass-card p-4">
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <h4 className="font-semibold">{role.name}</h4>
                      <p className="text-sm text-gray-400">{role.description}</p>
                    </div>
                    {!role.isSystem && (
                      <div className="flex gap-1">
                        <button 
                          onClick={() => { setSelectedRole(role); setShowRoleModal(true); }}
                          className="p-1 hover:bg-white/10 rounded"
                        >
                          <Edit2 className="w-4 h-4 text-cyan-400" />
                        </button>
                        <button className="p-1 hover:bg-white/10 rounded">
                          <Trash2 className="w-4 h-4 text-red-400" />
                        </button>
                      </div>
                    )}
                  </div>
                  
                  <div className="flex items-center gap-4 text-sm text-gray-400 mb-3">
                    <span className="flex items-center gap-1">
                      <Users className="w-4 h-4" />
                      {role.userCount} users
                    </span>
                    <span className="flex items-center gap-1">
                      <Shield className="w-4 h-4" />
                      {role.permissions.length} permissions
                    </span>
                  </div>

                  <div className="flex flex-wrap gap-1">
                    {role.permissions.slice(0, 5).map((perm) => (
                      <span key={perm} className="text-xs px-2 py-1 bg-white/5 rounded border border-white/10">
                        {perm}
                      </span>
                    ))}
                    {role.permissions.length > 5 && (
                      <span className="text-xs px-2 py-1 text-gray-500">
                        +{role.permissions.length - 5} more
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>

            {/* Role Modal */}
            {showRoleModal && (
              <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
                <div className="glass-card w-full max-w-2xl max-h-[90vh] overflow-y-auto">
                  <div className="flex items-center justify-between p-6 border-b border-white/5">
                    <h3 className="text-lg font-semibold">
                      {selectedRole ? 'Edit Role' : 'Create Role'}
                    </h3>
                    <button onClick={() => setShowRoleModal(false)} className="text-gray-400 hover:text-white">
                      <X className="w-5 h-5" />
                    </button>
                  </div>
                  <div className="p-6 space-y-4">
                    <div>
                      <label className="block text-sm text-gray-400 mb-1">Role Name *</label>
                      <input 
                        type="text" 
                        defaultValue={selectedRole?.name}
                        className="input-field w-full" 
                        placeholder="e.g., Security Analyst"
                      />
                    </div>
                    <div>
                      <label className="block text-sm text-gray-400 mb-1">Description</label>
                      <textarea 
                        defaultValue={selectedRole?.description}
                        className="input-field w-full h-20" 
                        placeholder="Describe the role responsibilities..."
                      />
                    </div>
                    
                    <div>
                      <label className="block text-sm text-gray-400 mb-2">Permissions</label>
                      <div className="space-y-2 max-h-64 overflow-y-auto p-3 bg-white/5 rounded-lg border border-white/5">
                        {availablePermissions.map((permission) => (
                          <label key={permission} className="flex items-center gap-2 p-2 hover:bg-white/5 rounded cursor-pointer">
                            <input 
                              type="checkbox" 
                              defaultChecked={selectedRole?.permissions.includes(permission)}
                              className="rounded bg-white/10 border-white/20"
                            />
                            <span className="text-sm font-mono">{permission}</span>
                          </label>
                        ))}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center justify-end gap-3 p-6 border-t border-white/5">
                    <button onClick={() => setShowRoleModal(false)} className="btn-secondary">Cancel</button>
                    <button className="btn-primary">
                      {selectedRole ? 'Save Changes' : 'Create Role'}
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        );

      case 'security':
        return (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold mb-4">Security Policies</h3>
              
              {/* Password Policy */}
              <div className="glass-card p-4 mb-4">
                <h4 className="font-medium mb-4 flex items-center gap-2">
                  <Lock className="w-4 h-4 text-cyan-400" />
                  Password Policy
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Minimum Password Length</label>
                    <input 
                      type="number" 
                      min="8" 
                      max="128"
                      value={securityPolicy.passwordMinLength}
                      onChange={(e) => setSecurityPolicy({...securityPolicy, passwordMinLength: parseInt(e.target.value)})}
                      className="input-field w-full"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Password Expiry (days)</label>
                    <input 
                      type="number"
                      value={securityPolicy.passwordExpiryDays}
                      onChange={(e) => setSecurityPolicy({...securityPolicy, passwordExpiryDays: parseInt(e.target.value)})}
                      className="input-field w-full"
                    />
                    <p className="text-xs text-gray-500 mt-1">0 = never expire</p>
                  </div>
                </div>
                <div className="mt-4 space-y-2">
                  <label className="flex items-center gap-2">
                    <input 
                      type="checkbox" 
                      checked={securityPolicy.passwordComplexity}
                      onChange={(e) => setSecurityPolicy({...securityPolicy, passwordComplexity: e.target.checked})}
                      className="rounded bg-white/10 border-white/20"
                    />
                    <span className="text-sm">Require complex passwords (uppercase, lowercase, numbers, symbols)</span>
                  </label>
                  <label className="flex items-center gap-2">
                    <input 
                      type="checkbox" 
                      checked={securityPolicy.mfaRequired}
                      onChange={(e) => setSecurityPolicy({...securityPolicy, mfaRequired: e.target.checked})}
                      className="rounded bg-white/10 border-white/20"
                    />
                    <span className="text-sm">Require MFA for all users</span>
                  </label>
                  <label className="flex items-center gap-2">
                    <input 
                      type="checkbox" 
                      checked={securityPolicy.enforceSSO}
                      onChange={(e) => setSecurityPolicy({...securityPolicy, enforceSSO: e.target.checked})}
                      className="rounded bg-white/10 border-white/20"
                    />
                    <span className="text-sm">Enforce SSO (disable password login)</span>
                  </label>
                </div>
              </div>

              {/* Session Management */}
              <div className="glass-card p-4 mb-4">
                <h4 className="font-medium mb-4 flex items-center gap-2">
                  <Clock className="w-4 h-4 text-cyan-400" />
                  Session Management
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Session Timeout (minutes)</label>
                    <input 
                      type="number"
                      value={securityPolicy.sessionTimeout}
                      onChange={(e) => setSecurityPolicy({...securityPolicy, sessionTimeout: parseInt(e.target.value)})}
                      className="input-field w-full"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Max Login Attempts</label>
                    <input 
                      type="number"
                      value={securityPolicy.maxLoginAttempts}
                      onChange={(e) => setSecurityPolicy({...securityPolicy, maxLoginAttempts: parseInt(e.target.value)})}
                      className="input-field w-full"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Lockout Duration (minutes)</label>
                    <input 
                      type="number"
                      value={securityPolicy.lockoutDuration}
                      onChange={(e) => setSecurityPolicy({...securityPolicy, lockoutDuration: parseInt(e.target.value)})}
                      className="input-field w-full"
                    />
                  </div>
                </div>
              </div>

              {/* IP Allowlist */}
              <div className="glass-card p-4">
                <h4 className="font-medium mb-4 flex items-center gap-2">
                  <Globe className="w-4 h-4 text-cyan-400" />
                  IP Allowlist
                </h4>
                <p className="text-sm text-gray-400 mb-3">
                  Restrict access to specific IP addresses or ranges (CIDR notation supported)
                </p>
                <div className="space-y-2">
                  {securityPolicy.ipAllowlist.map((ip, index) => (
                    <div key={index} className="flex gap-2">
                      <input type="text" value={ip} className="input-field flex-1" readOnly />
                      <button 
                        onClick={() => {
                          const newList = securityPolicy.ipAllowlist.filter((_, i) => i !== index);
                          setSecurityPolicy({...securityPolicy, ipAllowlist: newList});
                        }}
                        className="btn-secondary text-red-400"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  ))}
                  <div className="flex gap-2">
                    <input 
                      type="text" 
                      placeholder="192.168.1.0/24 or 10.0.0.1" 
                      className="input-field flex-1"
                      id="new-ip"
                    />
                    <button 
                      onClick={() => {
                        const input = document.getElementById('new-ip') as HTMLInputElement;
                        if (input.value) {
                          setSecurityPolicy({
                            ...securityPolicy, 
                            ipAllowlist: [...securityPolicy.ipAllowlist, input.value]
                          });
                          input.value = '';
                        }
                      }}
                      className="btn-secondary"
                    >
                      <Plus className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        );

      case 'compliance':
        return (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold mb-4">Compliance & Audit Settings</h3>
              
              {/* Audit Configuration */}
              <div className="glass-card p-4 mb-4">
                <h4 className="font-medium mb-4 flex items-center gap-2">
                  <FileText className="w-4 h-4 text-cyan-400" />
                  Audit Logging
                </h4>
                <div className="space-y-3">
                  <label className="flex items-center justify-between p-3 bg-white/5 rounded-lg">
                    <div>
                      <p className="font-medium">Log All User Actions</p>
                      <p className="text-sm text-gray-400">Record every CRUD operation</p>
                    </div>
                    <input type="checkbox" defaultChecked className="rounded bg-white/10 border-white/20" />
                  </label>
                  <label className="flex items-center justify-between p-3 bg-white/5 rounded-lg">
                    <div>
                      <p className="font-medium">Log Data Exports</p>
                      <p className="text-sm text-gray-400">Track all data export activities</p>
                    </div>
                    <input type="checkbox" defaultChecked className="rounded bg-white/10 border-white/20" />
                  </label>
                  <label className="flex items-center justify-between p-3 bg-white/5 rounded-lg">
                    <div>
                      <p className="font-medium">Log Failed Login Attempts</p>
                      <p className="text-sm text-gray-400">Record authentication failures</p>
                    </div>
                    <input type="checkbox" defaultChecked className="rounded bg-white/10 border-white/20" />
                  </label>
                  <label className="flex items-center justify-between p-3 bg-white/5 rounded-lg">
                    <div>
                      <p className="font-medium">Log Configuration Changes</p>
                      <p className="text-sm text-gray-400">Track settings modifications</p>
                    </div>
                    <input type="checkbox" defaultChecked className="rounded bg-white/10 border-white/20" />
                  </label>
                </div>
              </div>

              {/* Compliance Standards */}
              <div className="glass-card p-4">
                <h4 className="font-medium mb-4 flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-cyan-400" />
                  Compliance Frameworks
                </h4>
                <div className="space-y-3">
                  {['GDPR', 'HIPAA', 'SOC 2', 'ISO 27001', 'PCI DSS', 'NIST CSF'].map((standard) => (
                    <div key={standard} className="flex items-center justify-between p-3 bg-white/5 rounded-lg">
                      <div className="flex items-center gap-3">
                        <Shield className="w-5 h-5 text-cyan-400" />
                        <span className="font-medium">{standard}</span>
                      </div>
                      <label className="relative inline-flex items-center cursor-pointer">
                        <input type="checkbox" className="sr-only peer" />
                        <div className="w-11 h-6 bg-white/10 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-500"></div>
                      </label>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        );

      case 'data':
        return (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold mb-4">Data Management</h3>
              
              {/* Retention Policies */}
              <div className="glass-card p-4 mb-4">
                <h4 className="font-medium mb-4 flex items-center gap-2">
                  <Archive className="w-4 h-4 text-cyan-400" />
                  Data Retention Policies (days)
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Audit Logs</label>
                    <input 
                      type="number"
                      value={dataRetention.auditLogs}
                      onChange={(e) => setDataRetention({...dataRetention, auditLogs: parseInt(e.target.value)})}
                      className="input-field w-full"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">User Activities</label>
                    <input 
                      type="number"
                      value={dataRetention.userActivities}
                      onChange={(e) => setDataRetention({...dataRetention, userActivities: parseInt(e.target.value)})}
                      className="input-field w-full"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Detection Logs</label>
                    <input 
                      type="number"
                      value={dataRetention.detectionLogs}
                      onChange={(e) => setDataRetention({...dataRetention, detectionLogs: parseInt(e.target.value)})}
                      className="input-field w-full"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Alert History</label>
                    <input 
                      type="number"
                      value={dataRetention.alertHistory}
                      onChange={(e) => setDataRetention({...dataRetention, alertHistory: parseInt(e.target.value)})}
                      className="input-field w-full"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Backup Retention</label>
                    <input 
                      type="number"
                      value={dataRetention.backupRetention}
                      onChange={(e) => setDataRetention({...dataRetention, backupRetention: parseInt(e.target.value)})}
                      className="input-field w-full"
                    />
                  </div>
                </div>
                <div className="mt-4 p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
                  <label className="flex items-center gap-2">
                    <input 
                      type="checkbox" 
                      checked={dataRetention.autoPurge}
                      onChange={(e) => setDataRetention({...dataRetention, autoPurge: e.target.checked})}
                      className="rounded bg-white/10 border-white/20"
                    />
                    <span className="text-sm text-yellow-200">Enable automatic purging of expired data</span>
                  </label>
                </div>
              </div>

              {/* Backup Settings */}
              <div className="glass-card p-4">
                <h4 className="font-medium mb-4 flex items-center gap-2">
                  <Database className="w-4 h-4 text-cyan-400" />
                  Backup Configuration
                </h4>
                <div className="space-y-4">
                  <div className="flex items-center justify-between p-3 bg-white/5 rounded-lg">
                    <div>
                      <p className="font-medium">Automatic Backups</p>
                      <p className="text-sm text-gray-400">Daily backups at 2:00 AM UTC</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input type="checkbox" defaultChecked className="sr-only peer" />
                      <div className="w-11 h-6 bg-white/10 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-500"></div>
                    </label>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm text-gray-400 mb-1">Backup Frequency</label>
                      <select className="input-field w-full">
                        <option>Every 6 hours</option>
                        <option>Every 12 hours</option>
                        <option>Daily</option>
                        <option>Weekly</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-sm text-gray-400 mb-1">Backup Location</label>
                      <select className="input-field w-full">
                        <option>Local Storage</option>
                        <option>AWS S3</option>
                        <option>Azure Blob</option>
                        <option>GCP Storage</option>
                      </select>
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <button className="btn-secondary flex items-center gap-2">
                      <RefreshCw className="w-4 h-4" />
                      Backup Now
                    </button>
                    <button className="btn-secondary">
                      Download Latest Backup
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        );

      case 'integrations':
        return (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold mb-4">Integrations</h3>
              
              {/* SIEM Integrations */}
              <div className="glass-card p-4 mb-4">
                <h4 className="font-medium mb-4">SIEM Platforms</h4>
                <div className="space-y-3">
                  {[
                    { name: 'Splunk', status: 'connected', icon: 'S', desc: 'Universal forwarder configured' },
                    { name: 'Microsoft Sentinel', status: 'connected', icon: 'Se', desc: 'Log Analytics workspace' },
                    { name: 'IBM QRadar', status: 'disconnected', icon: 'Q', desc: 'Not configured' },
                    { name: 'Elastic Stack', status: 'disconnected', icon: 'E', desc: 'Not configured' },
                    { name: 'Chronicle', status: 'connected', icon: 'C', desc: 'Active' }
                  ].map((integration) => (
                    <div key={integration.name} className="flex items-center justify-between p-4 bg-white/5 rounded-lg">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center font-bold">
                          {integration.icon}
                        </div>
                        <div>
                          <p className="font-medium">{integration.name}</p>
                          <p className={`text-sm ${integration.status === 'connected' ? 'text-green-400' : 'text-gray-400'}`}>
                            {integration.desc}
                          </p>
                        </div>
                      </div>
                      <button className={integration.status === 'connected' ? 'btn-secondary text-red-400' : 'btn-primary'}>
                        {integration.status === 'connected' ? 'Disconnect' : 'Connect'}
                      </button>
                    </div>
                  ))}
                </div>
              </div>

              {/* Identity Providers */}
              <div className="glass-card p-4 mb-4">
                <h4 className="font-medium mb-4">Identity Providers (SSO)</h4>
                <div className="space-y-3">
                  {['Azure AD', 'Okta', 'Google Workspace', 'OneLogin'].map((idp) => (
                    <div key={idp} className="flex items-center justify-between p-4 bg-white/5 rounded-lg">
                      <div className="flex items-center gap-3">
                        <Shield className="w-8 h-8 text-cyan-400" />
                        <span className="font-medium">{idp}</span>
                      </div>
                      <button className="btn-secondary">Configure</button>
                    </div>
                  ))}
                </div>
              </div>

              {/* Ticketing Systems */}
              <div className="glass-card p-4">
                <h4 className="font-medium mb-4">Ticketing & SOAR</h4>
                <div className="space-y-3">
                  {['ServiceNow', 'Jira', 'TheHive', 'Phantom'].map((tool) => (
                    <div key={tool} className="flex items-center justify-between p-4 bg-white/5 rounded-lg">
                      <div className="flex items-center gap-3">
                        <Activity className="w-8 h-8 text-cyan-400" />
                        <span className="font-medium">{tool}</span>
                      </div>
                      <button className="btn-secondary">Configure</button>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        );

      case 'api':
        return (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold mb-4">API & Access Management</h3>
              
              {/* API Keys */}
              <div className="glass-card p-4 mb-4">
                <h4 className="font-medium mb-4">API Keys</h4>
                <div className="space-y-4">
                  <div className="p-4 bg-white/5 rounded-lg border border-white/10">
                    <div className="flex items-center justify-between mb-2">
                      <div>
                        <p className="font-medium">Production API Key</p>
                        <p className="text-xs text-gray-400">Created: 2024-01-15 • Last used: 2 hours ago</p>
                      </div>
                      <span className="badge badge-success">Active</span>
                    </div>
                    <div className="flex gap-2">
                      <input
                        type="password"
                        value="df_live_xxxxxxxxxxxxxxxxxxxx"
                        readOnly
                        className="input-field flex-1 font-mono text-sm"
                      />
                      <button className="btn-secondary">
                        <Eye className="w-4 h-4" />
                      </button>
                      <button className="btn-secondary">Copy</button>
                      <button className="btn-secondary text-red-400">Revoke</button>
                    </div>
                  </div>

                  <div className="p-4 bg-white/5 rounded-lg border border-white/10">
                    <div className="flex items-center justify-between mb-2">
                      <div>
                        <p className="font-medium">Test API Key</p>
                        <p className="text-xs text-gray-400">Created: 2024-01-15 • Never used</p>
                      </div>
                      <span className="badge badge-success">Active</span>
                    </div>
                    <div className="flex gap-2">
                      <input
                        type="password"
                        value="df_test_xxxxxxxxxxxxxxxxxxxx"
                        readOnly
                        className="input-field flex-1 font-mono text-sm"
                      />
                      <button className="btn-secondary">
                        <Eye className="w-4 h-4" />
                      </button>
                      <button className="btn-secondary">Copy</button>
                      <button className="btn-secondary text-red-400">Revoke</button>
                    </div>
                  </div>

                  <button className="btn-primary flex items-center gap-2">
                    <Plus className="w-4 h-4" />
                    Generate New API Key
                  </button>
                </div>
              </div>

              {/* CORS & Rate Limiting */}
              <div className="glass-card p-4">
                <h4 className="font-medium mb-4">Access Control</h4>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Allowed Origins (CORS)</label>
                    <textarea 
                      className="input-field w-full h-20 text-sm" 
                      placeholder="https://app.company.com&#10;https://admin.company.com"
                      defaultValue="https://app.company.com"
                    />
                    <p className="text-xs text-gray-500 mt-1">One per line. Use * for wildcard (not recommended).</p>
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Rate Limit (requests per minute)</label>
                    <input 
                      type="number" 
                      defaultValue="1000"
                      className="input-field w-full"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">IP Whitelist</label>
                    <textarea 
                      className="input-field w-full h-20 text-sm" 
                      placeholder="192.168.1.100&#10;10.0.0.0/24"
                    />
                  </div>
                </div>
              </div>
            </div>
          </div>
        );

      case 'system':
        return (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold mb-4">System Settings</h3>
              
              {/* System Status */}
              <div className="glass-card p-4 mb-4">
                <h4 className="font-medium mb-4">System Information</h4>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="p-3 bg-white/5 rounded-lg">
                    <p className="text-xs text-gray-400">Version</p>
                    <p className="font-mono text-sm">v2.4.1</p>
                  </div>
                  <div className="p-3 bg-white/5 rounded-lg">
                    <p className="text-xs text-gray-400">Database</p>
                    <p className="font-mono text-sm">PostgreSQL 14</p>
                  </div>
                  <div className="p-3 bg-white/5 rounded-lg">
                    <p className="text-xs text-gray-400">Cache</p>
                    <p className="font-mono text-sm">Redis 7.0</p>
                  </div>
                  <div className="p-3 bg-white/5 rounded-lg">
                    <p className="text-xs text-gray-400">Uptime</p>
                    <p className="font-mono text-sm">45 days</p>
                  </div>
                </div>
              </div>

              {/* Maintenance Mode */}
              <div className="glass-card p-4 mb-4">
                <h4 className="font-medium mb-4 flex items-center gap-2">
                  <Server className="w-4 h-4 text-cyan-400" />
                  Maintenance & Operations
                </h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between p-3 bg-white/5 rounded-lg">
                    <div>
                      <p className="font-medium">Maintenance Mode</p>
                      <p className="text-sm text-gray-400">Disable access for all non-admin users</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input 
                        type="checkbox" 
                        checked={systemConfig.maintenanceMode}
                        onChange={(e) => setSystemConfig({...systemConfig, maintenanceMode: e.target.checked})}
                        className="sr-only peer"
                      />
                      <div className="w-11 h-6 bg-white/10 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-yellow-500"></div>
                    </label>
                  </div>
                  
                  <div className="flex items-center justify-between p-3 bg-white/5 rounded-lg">
                    <div>
                      <p className="font-medium">Debug Mode</p>
                      <p className="text-sm text-gray-400">Enable detailed error logging (not recommended for production)</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input 
                        type="checkbox" 
                        checked={systemConfig.debugMode}
                        onChange={(e) => setSystemConfig({...systemConfig, debugMode: e.target.checked})}
                        className="sr-only peer"
                      />
                      <div className="w-11 h-6 bg-white/10 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-500"></div>
                    </label>
                  </div>
                </div>
              </div>

              {/* File Upload Settings */}
              <div className="glass-card p-4">
                <h4 className="font-medium mb-4">File Upload Configuration</h4>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Max File Size (MB)</label>
                    <input 
                      type="number"
                      value={systemConfig.maxFileUploadSize}
                      onChange={(e) => setSystemConfig({...systemConfig, maxFileUploadSize: parseInt(e.target.value)})}
                      className="input-field w-full"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Allowed File Types</label>
                    <div className="flex flex-wrap gap-2">
                      {systemConfig.allowedFileTypes.map((type) => (
                        <span key={type} className="px-2 py-1 bg-white/10 rounded text-sm flex items-center gap-1">
                          {type}
                          <button 
                            onClick={() => {
                              setSystemConfig({
                                ...systemConfig,
                                allowedFileTypes: systemConfig.allowedFileTypes.filter(t => t !== type)
                              });
                            }}
                            className="hover:text-red-400"
                          >
                            <X className="w-3 h-3" />
                          </button>
                        </span>
                      ))}
                      <input 
                        type="text" 
                        placeholder=".ext" 
                        className="input-field w-20 text-sm"
                        onKeyPress={(e) => {
                          if (e.key === 'Enter') {
                            setSystemConfig({
                              ...systemConfig,
                              allowedFileTypes: [...systemConfig.allowedFileTypes, e.currentTarget.value]
                            });
                            e.currentTarget.value = '';
                          }
                        }}
                      />
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        );

      case 'notifications':
        return (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold mb-4">Notification Preferences</h3>
              <div className="space-y-4">
                {[
                  { id: 'email-alerts', label: 'Critical Security Alerts', desc: 'Immediate email for high/critical severity' },
                  { id: 'detection-triggers', label: 'Detection Triggers', desc: 'When use cases match MITRE techniques' },
                  { id: 'system-updates', label: 'System Updates', desc: 'Platform updates and maintenance windows' },
                  { id: 'weekly-reports', label: 'Weekly Executive Summary', desc: 'Digest of detections and metrics' },
                  { id: 'compliance', label: 'Compliance Violations', desc: 'When security controls fail compliance checks' }
                ].map((item) => (
                  <div key={item.id} className="flex items-center justify-between p-4 bg-white/5 rounded-lg">
                    <div>
                      <p className="font-medium">{item.label}</p>
                      <p className="text-sm text-gray-400">{item.desc}</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input type="checkbox" className="sr-only peer" defaultChecked />
                      <div className="w-11 h-6 bg-white/10 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-500"></div>
                    </label>
                  </div>
                ))}
              </div>

              <div className="mt-6 p-4 bg-cyan-500/10 border border-cyan-500/20 rounded-lg">
                <h4 className="font-medium mb-2 flex items-center gap-2">
                  <Bell className="w-4 h-4 text-cyan-400" />
                  Notification Channels
                </h4>
                <div className="space-y-2">
                  <label className="flex items-center gap-2">
                    <input type="checkbox" defaultChecked className="rounded bg-white/10 border-white/20" />
                    <span className="text-sm">Email</span>
                  </label>
                  <label className="flex items-center gap-2">
                    <input type="checkbox" className="rounded bg-white/10 border-white/20" />
                    <span className="text-sm">Slack</span>
                  </label>
                  <label className="flex items-center gap-2">
                    <input type="checkbox" className="rounded bg-white/10 border-white/20" />
                    <span className="text-sm">Microsoft Teams</span>
                  </label>
                  <label className="flex items-center gap-2">
                    <input type="checkbox" className="rounded bg-white/10 border-white/20" />
                    <span className="text-sm">Webhook (Custom)</span>
                  </label>
                </div>
              </div>
            </div>
          </div>
        );

      case 'appearance':
        return (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold mb-4">Appearance</h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 bg-white/5 rounded-lg">
                  <div className="flex items-center gap-3">
                    {darkMode ? <Moon className="w-5 h-5" /> : <Sun className="w-5 h-5" />}
                    <div>
                      <p className="font-medium">Dark Mode</p>
                      <p className="text-sm text-gray-400">Toggle between light and dark themes</p>
                    </div>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      className="sr-only peer"
                      checked={darkMode}
                      onChange={(e) => setDarkMode(e.target.checked)}
                    />
                    <div className="w-11 h-6 bg-white/10 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-500"></div>
                  </label>
                </div>

                <div className="p-4 bg-white/5 rounded-lg">
                  <p className="font-medium mb-3">Language</p>
                  <select className="input-field w-full">
                    <option>English (US)</option>
                    <option>English (UK)</option>
                    <option>Spanish</option>
                    <option>French</option>
                    <option>German</option>
                    <option>Japanese</option>
                    <option>Chinese (Simplified)</option>
                  </select>
                </div>

                <div className="p-4 bg-white/5 rounded-lg">
                  <p className="font-medium mb-3">Date & Time Format</p>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm text-gray-400 mb-1">Date Format</label>
                      <select className="input-field w-full">
                        <option>YYYY-MM-DD</option>
                        <option>MM/DD/YYYY</option>
                        <option>DD/MM/YYYY</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-sm text-gray-400 mb-1">Time Format</label>
                      <select className="input-field w-full">
                        <option>24-hour</option>
                        <option>12-hour</option>
                      </select>
                    </div>
                  </div>
                </div>

                <div className="p-4 bg-white/5 rounded-lg">
                  <p className="font-medium mb-3">Density</p>
                  <div className="flex gap-2">
                    <button className="flex-1 p-2 bg-cyan-500/20 border border-cyan-500 rounded text-sm">Compact</button>
                    <button className="flex-1 p-2 bg-white/5 border border-white/10 rounded text-sm">Comfortable</button>
                    <button className="flex-1 p-2 bg-white/5 border border-white/10 rounded text-sm">Spacious</button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold">Settings</h2>
        <p className="text-gray-400 mt-1">Manage your account, security policies, and system configuration</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Sidebar */}
        <div className="lg:col-span-1">
          <div className="glass-card p-2 space-y-1">
            {settingSections.map((section) => {
              const Icon = section.icon;
              return (
                <button
                  key={section.id}
                  onClick={() => setActiveSection(section.id)}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all ${
                    activeSection === section.id
                      ? 'bg-cyan-500/10 text-cyan-400'
                      : 'text-gray-400 hover:bg-white/5 hover:text-gray-200'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                  <span className="text-sm font-medium">{section.name}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Content */}
        <div className="lg:col-span-3">
          <div className="glass-card p-6">
            {error && (
              <div className="mb-4 p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400 flex items-center gap-2">
                <AlertTriangle className="w-5 h-5" />
                {error}
              </div>
            )}
            
            {renderSection()}

            <div className="flex items-center justify-end gap-3 mt-6 pt-6 border-t border-white/5">
              {saved && (
                <span className="text-green-400 flex items-center gap-2">
                  <CheckCircle className="w-4 h-4" />
                  Settings saved successfully
                </span>
              )}
              <button 
                onClick={() => handleSave(activeSection, 
                  activeSection === 'security' ? securityPolicy :
                  activeSection === 'data' ? dataRetention :
                  activeSection === 'system' ? systemConfig :
                  {}
                )}
                disabled={loading}
                className="btn-primary flex items-center gap-2"
              >
                {loading ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : (
                  <Save className="w-4 h-4" />
                )}
                Save Changes
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}