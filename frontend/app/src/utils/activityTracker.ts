// Activity Tracker Utility
// Records user actions to the audit log

const API_BASE_URL = 'http://localhost:4000/api';

export type ActivityType = 
  | 'detection' 
  | 'alert' 
  | 'use_case' 
  | 'user' 
  | 'system' 
  | 'auth' 
  | 'mitre' 
  | 'benchmark' 
  | 'export' 
  | 'settings' 
  | 'query' 
  | 'incident';

export type ActivitySeverity = 'low' | 'medium' | 'high' | 'critical' | 'info' | 'warning';
export type ActivityStatus = 'success' | 'warning' | 'error' | 'pending';

interface ActivityData {
  type: ActivityType;
  title: string;
  description: string;
  user?: string;
  userId?: string;
  severity?: ActivitySeverity;
  status?: ActivityStatus;
  section?: string;
  metadata?: {
    resourceId?: string;
    resourceType?: string;
    changes?: any;
    details?: any;
    count?: number;
    type?: string;
  };
}

/**
 * Track an activity in the audit log
 */
export const trackActivity = async (activity: ActivityData): Promise<void> => {
  try {
    await fetch(`${API_BASE_URL}/activities`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...activity,
        user: activity.user || getCurrentUser() || 'Anonymous',
        status: activity.status || 'success'
      })
    });
  } catch (err) {
    console.error('Failed to track activity:', err);
  }
};

/**
 * Get current user from localStorage or context
 */
const getCurrentUser = (): string | null => {
  try {
    const user = localStorage.getItem('user');
    if (user) {
      const parsed = JSON.parse(user);
      return parsed.name || parsed.email || 'User';
    }
  } catch {
    // ignore
  }
  return null;
};

/**
 * Track login activity
 */
export const trackLogin = (user: string, success: boolean = true): Promise<void> => {
  return trackActivity({
    type: 'auth',
    title: success ? 'User Login' : 'Failed Login Attempt',
    description: success ? `${user} logged in successfully` : `Failed login attempt for ${user}`,
    user,
    severity: success ? 'info' : 'high',
    status: success ? 'success' : 'error',
    section: 'auth'
  });
};

/**
 * Track logout activity
 */
export const trackLogout = (user: string): Promise<void> => {
  return trackActivity({
    type: 'auth',
    title: 'User Logout',
    description: `${user} logged out`,
    user,
    severity: 'info',
    status: 'success',
    section: 'auth'
  });
};

/**
 * Track rule creation
 */
export const trackRuleCreated = (
  ruleType: 'sigma' | 'yara' | 'use_case',
  ruleTitle: string,
  ruleId: string
): Promise<void> => {
  const typeMap: Record<string, ActivityType> = {
    sigma: 'detection',
    yara: 'detection',
    use_case: 'use_case'
  };
  
  return trackActivity({
    type: typeMap[ruleType],
    title: `${ruleType.toUpperCase()} Rule Created`,
    description: `Created "${ruleTitle}"`,
    severity: 'info',
    status: 'success',
    section: ruleType,
    metadata: {
      resourceId: ruleId,
      resourceType: ruleType
    }
  });
};

/**
 * Track rule update
 */
export const trackRuleUpdated = (
  ruleType: 'sigma' | 'yara' | 'use_case',
  ruleTitle: string,
  ruleId: string
): Promise<void> => {
  const typeMap: Record<string, ActivityType> = {
    sigma: 'detection',
    yara: 'detection',
    use_case: 'use_case'
  };
  
  return trackActivity({
    type: typeMap[ruleType],
    title: `${ruleType.toUpperCase()} Rule Updated`,
    description: `Updated "${ruleTitle}"`,
    severity: 'info',
    status: 'success',
    section: ruleType,
    metadata: {
      resourceId: ruleId,
      resourceType: ruleType
    }
  });
};

/**
 * Track rule deletion
 */
export const trackRuleDeleted = (
  ruleType: 'sigma' | 'yara' | 'use_case',
  ruleTitle: string
): Promise<void> => {
  const typeMap: Record<string, ActivityType> = {
    sigma: 'detection',
    yara: 'detection',
    use_case: 'use_case'
  };
  
  return trackActivity({
    type: typeMap[ruleType],
    title: `${ruleType.toUpperCase()} Rule Deleted`,
    description: `Deleted "${ruleTitle}"`,
    severity: 'warning',
    status: 'success',
    section: ruleType
  });
};

/**
 * Track settings change
 */
export const trackSettingsChanged = (
  settingName: string,
  changes: any
): Promise<void> => {
  return trackActivity({
    type: 'settings',
    title: 'Settings Updated',
    description: `Modified ${settingName}`,
    severity: 'info',
    status: 'success',
    section: 'settings',
    metadata: { changes }
  });
};

/**
 * Track export action
 */
export const trackExport = (
  exportType: string,
  count: number
): Promise<void> => {
  return trackActivity({
    type: 'export',
    title: 'Data Exported',
    description: `Exported ${count} ${exportType}(s)`,
    severity: 'info',
    status: 'success',
    section: 'export',
    metadata: { count, type: exportType }
  });
};

/**
 * Track user management action
 */
export const trackUserAction = (
  action: 'created' | 'updated' | 'deleted',
  userName: string
): Promise<void> => {
  return trackActivity({
    type: 'user',
    title: `User ${action.charAt(0).toUpperCase() + action.slice(1)}`,
    description: `${action.charAt(0).toUpperCase() + action.slice(1)} user "${userName}"`,
    severity: action === 'deleted' ? 'warning' : 'info',
    status: 'success',
    section: 'users'
  });
};

/**
 * Track system action
 */
export const trackSystemAction = (
  title: string,
  description: string,
  severity: ActivitySeverity = 'info'
): Promise<void> => {
  return trackActivity({
    type: 'system',
    title,
    description,
    severity,
    status: 'success',
    section: 'system'
  });
};
