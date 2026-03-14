import { useState } from 'react';
import {
  Target,
  Shield,
  AlertTriangle,
  Search,
  Filter,
  ExternalLink,
  ChevronRight,
  Info,
  Sword,
  Lock,
  Eye,
  Fingerprint,
  FileSearch,
  Radio,
  Database,
  Command
} from 'lucide-react';

interface Technique {
  id: string;
  name: string;
  tactic: string;
  description: string;
  platforms: string[];
  dataSources: string[];
  defenses: string[];
  detections: string[];
}

const techniques: Technique[] = [
  // INITIAL ACCESS
  {
    id: 'T1566',
    name: 'Phishing',
    tactic: 'Initial Access',
    description: 'Adversaries may send phishing messages to gain access to victim systems.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Application logs', 'Network traffic', 'Email gateway'],
    defenses: ['User training', 'Email filtering', 'Application whitelisting'],
    detections: ['Monitor suspicious email attachments', 'Analyze URLs in emails', 'Detect macro-enabled documents']
  },
  {
    id: 'T1566.001',
    name: 'Spearphishing Attachment',
    tactic: 'Initial Access',
    description: 'Adversaries may send spearphishing emails with malicious attachments.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Email logs', 'File monitoring', 'Process monitoring'],
    defenses: ['Email authentication', 'Attachment sandboxing', 'Disable macros'],
    detections: ['Detect suspicious attachment types', 'Monitor file execution from temp directories']
  },
  {
    id: 'T1566.002',
    name: 'Spearphishing Link',
    tactic: 'Initial Access',
    description: 'Adversaries may send spearphishing emails with malicious links.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Web logs', 'DNS logs', 'Email logs'],
    defenses: ['URL filtering', 'Web proxies', 'Link sandboxing'],
    detections: ['Monitor suspicious URL clicks', 'Detect credential harvesting sites']
  },
  {
    id: 'T1078',
    name: 'Valid Accounts',
    tactic: 'Initial Access',
    description: 'Adversaries may obtain and abuse credentials of existing accounts.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network', 'Cloud'],
    dataSources: ['Authentication logs', 'Account monitoring'],
    defenses: ['MFA', 'Password policies', 'Account monitoring'],
    detections: ['Monitor login anomalies', 'Detect privilege escalation', 'Geolocation analysis']
  },
  {
    id: 'T1078.001',
    name: 'Default Accounts',
    tactic: 'Initial Access',
    description: 'Adversaries may obtain and abuse default accounts.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network', 'Cloud'],
    dataSources: ['Authentication logs', 'Account management logs'],
    defenses: ['Change default passwords', 'Disable default accounts', 'MFA'],
    detections: ['Monitor default account usage', 'Detect unusual default account activity']
  },
  {
    id: 'T1078.003',
    name: 'Local Accounts',
    tactic: 'Initial Access',
    description: 'Adversaries may obtain and abuse local account credentials.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Authentication logs', 'Local security logs'],
    defenses: ['Local account restrictions', 'Credential Guard', 'Privileged Access Management'],
    detections: ['Monitor local account logons', 'Detect pass-the-hash attacks']
  },
  {
    id: 'T1078.004',
    name: 'Cloud Accounts',
    tactic: 'Initial Access',
    description: 'Adversaries may obtain and abuse cloud account credentials.',
    platforms: ['Azure AD', 'AWS', 'GCP', 'SaaS'],
    dataSources: ['Cloud logs', 'Identity logs', 'Audit logs'],
    defenses: ['Cloud MFA', 'Conditional access policies', 'Privileged Identity Management'],
    detections: ['Monitor anomalous cloud sign-ins', 'Detect impossible travel scenarios']
  },
  {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
    description: 'Adversaries may attempt to exploit a weakness in an internet-facing computer or program.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['Web server logs', 'Application logs', 'Network logs'],
    defenses: ['Patch management', 'WAF', 'Input validation', 'Network segmentation'],
    detections: ['Monitor for exploitation attempts', 'Detect unusual web requests', 'Analyze error rates']
  },
  {
    id: 'T1133',
    name: 'External Remote Services',
    tactic: 'Initial Access',
    description: 'Adversaries may leverage external-facing remote services to initially access a network.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['Authentication logs', 'VPN logs', 'Firewall logs'],
    defenses: ['MFA for VPN', 'Network segmentation', 'IP allowlisting', 'Account lockout'],
    detections: ['Monitor remote access patterns', 'Detect unusual login times', 'Geolocation anomalies']
  },
  {
    id: 'T1135',
    name: 'Server Software Component',
    tactic: 'Initial Access',
    description: 'Adversaries may abuse security weaknesses in server software components.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Application logs', 'System logs', 'File monitoring'],
    defenses: ['Secure configuration', 'Regular patching', 'Application hardening'],
    detections: ['Monitor web shells', 'Detect unauthorized component modifications']
  },
  {
    id: 'T1566.003',
    name: 'Spearphishing via Service',
    tactic: 'Initial Access',
    description: 'Adversaries may send spearphishing messages via third-party services.',
    platforms: ['Windows', 'Linux', 'macOS', 'SaaS'],
    dataSources: ['Application logs', 'Messaging logs'],
    defenses: ['User awareness', 'Application controls', 'Data loss prevention'],
    detections: ['Monitor for suspicious messaging activity', 'Detect anomalous communication patterns']
  },

  // EXECUTION
  {
    id: 'T1059',
    name: 'Command and Scripting Interpreter',
    tactic: 'Execution',
    description: 'Adversaries may abuse command and script interpreters to execute commands.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['Command monitoring', 'Process monitoring', 'Script logs'],
    defenses: ['Disable unnecessary interpreters', 'Application control', 'Execution policies'],
    detections: ['Monitor command execution', 'Detect encoded commands', 'Script block logging']
  },
  {
    id: 'T1059.001',
    name: 'PowerShell',
    tactic: 'Execution',
    description: 'Adversaries may abuse PowerShell commands and scripts for execution.',
    platforms: ['Windows', 'macOS'],
    dataSources: ['Script block logging', 'Module logging', 'Process monitoring'],
    defenses: ['Disable PowerShell', 'Constrained Language Mode', 'AMSI', 'Execution policy'],
    detections: ['Monitor encoded commands', 'Script block logging', 'Detect suspicious cmdlets']
  },
  {
    id: 'T1059.002',
    name: 'AppleScript',
    tactic: 'Execution',
    description: 'Adversaries may abuse AppleScript for execution on macOS systems.',
    platforms: ['macOS'],
    dataSources: ['Process monitoring', 'System logs'],
    defenses: ['Application control', 'User access controls'],
    detections: ['Monitor osascript execution', 'Detect suspicious AppleScript activity']
  },
  {
    id: 'T1059.003',
    name: 'Windows Command Shell',
    tactic: 'Execution',
    description: 'Adversaries may abuse cmd.exe to execute commands, scripts, or binaries.',
    platforms: ['Windows'],
    dataSources: ['Command monitoring', 'Process monitoring', 'Windows Event Logs'],
    defenses: ['Restrict command prompt', 'Application control', 'Disable cmd.exe'],
    detections: ['Monitor command line arguments', 'Detect suspicious batch execution']
  },
  {
    id: 'T1059.004',
    name: 'Unix Shell',
    tactic: 'Execution',
    description: 'Adversaries may abuse Unix shells to execute commands or binaries.',
    platforms: ['Linux', 'macOS'],
    dataSources: ['Command monitoring', 'Process monitoring', 'Auditd logs'],
    defenses: ['Restrict shell access', 'Sudoers configuration', 'Privileged command filtering'],
    detections: ['Monitor shell commands', 'Detect suspicious cron jobs', 'Analyze bash history']
  },
  {
    id: 'T1059.005',
    name: 'Visual Basic',
    tactic: 'Execution',
    description: 'Adversaries may abuse Visual Basic (VB) to execute malicious code.',
    platforms: ['Windows'],
    dataSources: ['Process monitoring', 'Script execution logs'],
    defenses: ['Disable VB execution', 'Application control', 'Macro restrictions'],
    detections: ['Monitor VB script execution', 'Detect suspicious macros']
  },
  {
    id: 'T1059.006',
    name: 'Python',
    tactic: 'Execution',
    description: 'Adversaries may abuse Python to execute malicious code.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Process monitoring', 'File monitoring'],
    defenses: ['Restrict Python execution', 'Application control', 'Code signing'],
    detections: ['Monitor Python execution', 'Detect suspicious imports', 'Analyze script content']
  },
  {
    id: 'T1047',
    name: 'Windows Management Instrumentation',
    tactic: 'Execution',
    description: 'Adversaries may abuse WMI to execute malicious commands and payloads.',
    platforms: ['Windows'],
    dataSources: ['WMI logs', 'Process monitoring', 'Sysmon'],
    defenses: ['WMI filtering', 'Disable WMI', 'Application control'],
    detections: ['Monitor WMI process creation', 'Detect remote WMI connections', 'Analyze WMI namespaces']
  },
  {
    id: 'T1053',
    name: 'Scheduled Task/Job',
    tactic: 'Execution',
    description: 'Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Task scheduler logs', 'File monitoring', 'Process monitoring'],
    defenses: ['Restrict task scheduler', 'Audit scheduled tasks', 'Disable unnecessary scheduling'],
    detections: ['Monitor new scheduled tasks', 'Detect suspicious task locations', 'Analyze task actions']
  },
  {
    id: 'T1053.005',
    name: 'Scheduled Task',
    tactic: 'Execution',
    description: 'Adversaries may abuse the Windows Task Scheduler to execute programs at system startup or on a scheduled basis.',
    platforms: ['Windows'],
    dataSources: ['Windows Event Logs', 'File monitoring', 'Registry monitoring'],
    defenses: ['Restrict task creation', 'Audit scheduled tasks', 'Remove unnecessary tasks'],
    detections: ['Monitor Task Scheduler event logs', 'Detect suspicious task configurations']
  },
  {
    id: 'T1053.003',
    name: 'Cron',
    tactic: 'Execution',
    description: 'Adversaries may abuse cron jobs to execute programs on a scheduled basis.',
    platforms: ['Linux', 'macOS'],
    dataSources: ['File monitoring', 'Process monitoring', 'Syslog'],
    defenses: ['Restrict cron access', 'Monitor cron directories', 'Audit cron jobs'],
    detections: ['Monitor crontab modifications', 'Detect suspicious cron entries']
  },
  {
    id: 'T1204',
    name: 'User Execution',
    tactic: 'Execution',
    description: 'Adversaries may rely upon specific user interaction to gain execution.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Process monitoring', 'Application logs'],
    defenses: ['User training', 'Application control', 'Mark of the Web'],
    detections: ['Monitor user execution of suspicious files', 'Detect malicious attachments']
  },
  {
    id: 'T1204.002',
    name: 'Malicious File',
    tactic: 'Execution',
    description: 'Adversaries may rely on user execution of a malicious file.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['File monitoring', 'Process monitoring', 'Email logs'],
    defenses: ['Application whitelisting', 'User training', 'Disable macros'],
    detections: ['Monitor file execution', 'Detect suspicious file extensions', 'Analyze file reputation']
  },
  {
    id: 'T1559',
    name: 'Inter-Process Communication',
    tactic: 'Execution',
    description: 'Adversaries may abuse inter-process communication (IPC) mechanisms for execution.',
    platforms: ['Windows', 'macOS'],
    dataSources: ['Process monitoring', 'API monitoring'],
    defenses: ['Restrict IPC mechanisms', 'Application control', 'Network segmentation'],
    detections: ['Monitor COM objects', 'Detect DDE exploitation', 'Analyze IPC patterns']
  },
  {
    id: 'T1106',
    name: 'Native API',
    tactic: 'Execution',
    description: 'Adversaries may interact with the native OS application programming interface (API).',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['API monitoring', 'Process monitoring'],
    defenses: ['Application control', 'User mode hooks', 'Kernel callbacks'],
    detections: ['Monitor suspicious API calls', 'Detect process hollowing', 'Analyze memory allocations']
  },

  // PERSISTENCE
  {
    id: 'T1547',
    name: 'Boot or Logon Autostart Execution',
    tactic: 'Persistence',
    description: 'Adversaries may configure system settings to automatically execute a program during system boot or logon.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Registry monitoring', 'File monitoring', 'Process monitoring'],
    defenses: ['Audit autostart locations', 'Restrict registry permissions', 'Application control'],
    detections: ['Monitor registry run keys', 'Detect new startup items', 'Analyze boot configuration']
  },
  {
    id: 'T1547.001',
    name: 'Registry Run Keys',
    tactic: 'Persistence',
    description: 'Adversaries may achieve persistence by modifying registry run keys.',
    platforms: ['Windows'],
    dataSources: ['Registry monitoring', 'Process monitoring', 'Windows Event Logs'],
    defenses: ['Restrict registry permissions', 'Monitor registry changes', 'Application control'],
    detections: ['Monitor Run and RunOnce keys', 'Detect suspicious registry modifications']
  },
  {
    id: 'T1547.002',
    name: 'Authentication Package',
    tactic: 'Persistence',
    description: 'Adversaries may abuse authentication packages to execute DLLs when the system boots.',
    platforms: ['Windows'],
    dataSources: ['Registry monitoring', 'File monitoring'],
    defenses: ['Restrict registry permissions', 'Code signing', 'Driver signature enforcement'],
    detections: ['Monitor authentication package registry keys', 'Detect suspicious DLL loading']
  },
  {
    id: 'T1136',
    name: 'Create Account',
    tactic: 'Persistence',
    description: 'Adversaries may create an account to maintain access to victim systems.',
    platforms: ['Windows', 'Linux', 'macOS', 'Cloud'],
    dataSources: ['Account management logs', 'Authentication logs'],
    defenses: ['Account lifecycle management', 'Audit account creation', 'MFA'],
    detections: ['Monitor new account creation', 'Detect suspicious account names', 'Analyze account privileges']
  },
  {
    id: 'T1136.001',
    name: 'Local Account',
    tactic: 'Persistence',
    description: 'Adversaries may create a local account to maintain access.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['System logs', 'Security logs', 'Audit logs'],
    defenses: ['Restrict account creation', 'User access control', 'Regular audits'],
    detections: ['Monitor local user creation', 'Detect hidden accounts', 'Analyze user privileges']
  },
  {
    id: 'T1136.002',
    name: 'Domain Account',
    tactic: 'Persistence',
    description: 'Adversaries may create a domain account to maintain access.',
    platforms: ['Windows', 'Azure AD'],
    dataSources: ['Active Directory logs', 'Authentication logs'],
    defenses: ['Privileged Access Management', 'Just-in-time access', 'Regular audits'],
    detections: ['Monitor AD account creation', 'Detect suspicious group memberships']
  },
  {
    id: 'T1543',
    name: 'Create or Modify System Process',
    tactic: 'Persistence',
    description: 'Adversaries may create or modify system-level processes to repeatedly execute malicious payloads.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Service control manager', 'System logs', 'Process monitoring'],
    defenses: ['Restrict service creation', 'Service permissions', 'Code signing'],
    detections: ['Monitor new services', 'Detect suspicious service binaries', 'Analyze service configurations']
  },
  {
    id: 'T1543.003',
    name: 'Windows Service',
    tactic: 'Persistence',
    description: 'Adversaries may create or modify Windows services to execute malicious payloads.',
    platforms: ['Windows'],
    dataSources: ['Windows Event Logs', 'Service control manager', 'Registry monitoring'],
    defenses: ['Service permissions', 'Restrict service creation', 'Application control'],
    detections: ['Monitor service creation events', 'Detect unusual service paths', 'Analyze service binaries']
  },
  {
    id: 'T1543.001',
    name: 'Launch Agent',
    tactic: 'Persistence',
    description: 'Adversaries may create a launch agent to execute malicious programs on macOS.',
    platforms: ['macOS'],
    dataSources: ['File monitoring', 'Process monitoring'],
    defenses: ['Restrict LaunchAgents directories', 'Application control'],
    detections: ['Monitor LaunchAgents folders', 'Detect suspicious plist files']
  },
  {
    id: 'T1053',
    name: 'Scheduled Task/Job',
    tactic: 'Persistence',
    description: 'Adversaries may abuse task scheduling functionality to facilitate recurring execution.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Task scheduler logs', 'File monitoring', 'Process monitoring'],
    defenses: ['Restrict task scheduler', 'Audit scheduled tasks', 'Remove unnecessary tasks'],
    detections: ['Monitor new scheduled tasks', 'Detect suspicious task locations', 'Analyze task actions']
  },
  {
    id: 'T1546',
    name: 'Event Triggered Execution',
    tactic: 'Persistence',
    description: 'Adversaries may establish persistence using system mechanisms that trigger execution.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Registry monitoring', 'File monitoring', 'Process monitoring'],
    defenses: ['Restrict event handler modifications', 'Application control', 'Behavioral prevention'],
    detections: ['Monitor event handlers', 'Detect suspicious triggers', 'Analyze execution chains']
  },
  {
    id: 'T1546.008',
    name: 'Accessibility Features',
    tactic: 'Persistence',
    description: 'Adversaries may establish persistence by modifying accessibility features.',
    platforms: ['Windows'],
    dataSources: ['Registry monitoring', 'File monitoring', 'Process monitoring'],
    defenses: ['Restrict accessibility binary modifications', 'Application control', 'File integrity monitoring'],
    detections: ['Monitor accessibility binary replacements', 'Detect debugger registry entries']
  },
  {
    id: 'T1505',
    name: 'Server Software Component',
    tactic: 'Persistence',
    description: 'Adversaries may abuse server software components to establish persistence.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['File monitoring', 'Process monitoring', 'Web logs'],
    defenses: ['Secure configuration', 'File integrity monitoring', 'Regular patching'],
    detections: ['Monitor web shells', 'Detect unauthorized component modifications', 'Analyze traffic patterns']
  },

  // PRIVILEGE ESCALATION
  {
    id: 'T1055',
    name: 'Process Injection',
    tactic: 'Privilege Escalation',
    description: 'Adversaries may inject code into processes to evade detection and elevate privileges.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['API monitoring', 'Process monitoring', 'Memory monitoring'],
    defenses: ['Application control', 'Behavioral prevention', 'Patch management'],
    detections: ['Monitor process hollowing', 'Detect unusual memory allocations', 'Analyze API calls']
  },
  {
    id: 'T1055.001',
    name: 'Dynamic-link Library Injection',
    tactic: 'Privilege Escalation',
    description: 'Adversaries may inject dynamic-link libraries (DLLs) into processes.',
    platforms: ['Windows'],
    dataSources: ['API monitoring', 'Process monitoring'],
    defenses: ['Application control', 'Code signing', 'User mode hooks'],
    detections: ['Monitor DLL loading', 'Detect suspicious LoadLibrary calls']
  },
  {
    id: 'T1055.012',
    name: 'Process Hollowing',
    tactic: 'Privilege Escalation',
    description: 'Adversaries may inject malicious code into suspended and hollowed processes.',
    platforms: ['Windows'],
    dataSources: ['API monitoring', 'Process monitoring', 'Memory monitoring'],
    defenses: ['Application control', 'Behavioral prevention'],
    detections: ['Monitor unmapping of process memory', 'Detect suspicious parent-child relationships']
  },
  {
    id: 'T1078',
    name: 'Valid Accounts',
    tactic: 'Privilege Escalation',
    description: 'Adversaries may obtain and abuse credentials of existing accounts to elevate privileges.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network', 'Cloud'],
    dataSources: ['Authentication logs', 'Account monitoring'],
    defenses: ['MFA', 'Privileged Access Management', 'Just-in-time access'],
    detections: ['Monitor privilege escalation', 'Detect unusual administrative access']
  },
  {
    id: 'T1548',
    name: 'Abuse Elevation Control Mechanism',
    tactic: 'Privilege Escalation',
    description: 'Adversaries may circumvent mechanisms designed to control elevation privileges.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['System logs', 'Process monitoring', 'Authorization logs'],
    defenses: ['User Account Control', 'Sudoers configuration', 'Remove setuid/setgid'],
    detections: ['Monitor UAC bypass attempts', 'Detect sudo misuse', 'Analyze elevation patterns']
  },
  {
    id: 'T1548.002',
    name: 'Bypass User Account Control',
    tactic: 'Privilege Escalation',
    description: 'Adversaries may bypass UAC mechanisms to elevate process privileges.',
    platforms: ['Windows'],
    dataSources: ['System logs', 'Process monitoring', 'Registry monitoring'],
    defenses: ['Highest UAC enforcement', 'Secure desktop mode', 'Remove administrators from local admin group'],
    detections: ['Monitor auto-elevation', 'Detect UAC bypass techniques', 'Analyze process integrity levels']
  },
  {
    id: 'T1134',
    name: 'Access Token Manipulation',
    tactic: 'Privilege Escalation',
    description: 'Adversaries may modify access tokens to operate under a different user or system security context.',
    platforms: ['Windows'],
    dataSources: ['API monitoring', 'Process monitoring', 'Authentication logs'],
    defenses: ['Restrict token permissions', 'User Account Control', 'Privileged Access Workstations'],
    detections: ['Monitor token duplication', 'Detect suspicious token privileges', 'Analyze process tokens']
  },
  {
    id: 'T1546',
    name: 'Event Triggered Execution',
    tactic: 'Privilege Escalation',
    description: 'Adversaries may establish persistence and elevate privileges using event triggers.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Registry monitoring', 'System logs', 'Process monitoring'],
    defenses: ['Restrict event handler modifications', 'Application control'],
    detections: ['Monitor event handlers', 'Detect privilege escalation via events']
  },
  {
    id: 'T1058',
    name: 'Service Registry Permissions Weakness',
    tactic: 'Privilege Escalation',
    description: 'Adversaries may exploit weak service registry permissions to elevate privileges.',
    platforms: ['Windows'],
    dataSources: ['Registry monitoring', 'Service control manager'],
    defenses: ['Secure service permissions', 'Access control lists', 'Regular audits'],
    detections: ['Monitor service registry modifications', 'Detect suspicious service binary paths']
  },

  // DEFENSE EVASION
  {
    id: 'T1055',
    name: 'Process Injection',
    tactic: 'Defense Evasion',
    description: 'Adversaries may inject code into processes to evade detection.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['API monitoring', 'Process monitoring', 'Memory monitoring'],
    defenses: ['Application control', 'Behavioral prevention', 'EDR'],
    detections: ['Monitor process hollowing', 'Detect unusual memory allocations']
  },
  {
    id: 'T1070',
    name: 'Indicator Removal',
    tactic: 'Defense Evasion',
    description: 'Adversaries may delete or modify artifacts generated on a host system to remove evidence.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['File monitoring', 'Command monitoring', 'Process monitoring'],
    defenses: ['Audit policies', 'Centralized logging', 'File integrity monitoring'],
    detections: ['Monitor log deletion', 'Detect timestamp modification', 'Analyze event clearing']
  },
  {
    id: 'T1070.004',
    name: 'File Deletion',
    tactic: 'Defense Evasion',
    description: 'Adversaries may delete files left behind by malicious activity.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['File monitoring', 'Command monitoring'],
    defenses: ['Audit policies', 'File integrity monitoring', 'Backup systems'],
    detections: ['Monitor file deletion', 'Detect secure deletion tools']
  },
  {
    id: 'T1070.001',
    name: 'Clear Windows Event Logs',
    tactic: 'Defense Evasion',
    description: 'Adversaries may clear Windows Event Logs to hide activity.',
    platforms: ['Windows'],
    dataSources: ['Windows Event Logs', 'Command monitoring'],
    defenses: ['Restrict event log management', 'Centralized logging', 'Protected event logging'],
    detections: ['Monitor event log clearing', 'Detect wevtutil usage', 'Alert on Event ID 1102']
  },
  {
    id: 'T1027',
    name: 'Obfuscated Files or Information',
    tactic: 'Defense Evasion',
    description: 'Adversaries may attempt to make an executable or file difficult to discover or analyze.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['File monitoring', 'Network traffic', 'Process monitoring'],
    defenses: ['Anti-malware', 'Network intrusion detection', 'Email filtering'],
    detections: ['Detect packed files', 'Analyze entropy', 'Monitor for encoded commands']
  },
  {
    id: 'T1027.002',
    name: 'Software Packing',
    tactic: 'Defense Evasion',
    description: 'Adversaries may perform software packing to conceal malicious code.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['File monitoring', 'Binary analysis'],
    defenses: ['Anti-malware', 'Application control', 'Code signing'],
    detections: ['Detect packers', 'Analyze file entropy', 'Monitor suspicious imports']
  },
  {
    id: 'T1218',
    name: 'Signed Binary Proxy Execution',
    tactic: 'Defense Evasion',
    description: 'Adversaries may execute malicious payloads by proxying execution through signed binaries.',
    platforms: ['Windows'],
    dataSources: ['Process monitoring', 'Command monitoring', 'Windows Event Logs'],
    defenses: ['Application control', 'Disable unnecessary binaries', 'Behavioral prevention'],
    detections: ['Monitor LOLBAS usage', 'Detect suspicious command arguments', 'Analyze parent-child relationships']
  },
  {
    id: 'T1218.011',
    name: 'Rundll32',
    tactic: 'Defense Evasion',
    description: 'Adversaries may abuse rundll32.exe to proxy execution of malicious code.',
    platforms: ['Windows'],
    dataSources: ['Process monitoring', 'Command monitoring'],
    defenses: ['Application control', 'Disable rundll32', 'Command line logging'],
    detections: ['Monitor rundll32 execution', 'Detect suspicious DLLs', 'Analyze command line arguments']
  },
  {
    id: 'T1218.010',
    name: 'Regsvr32',
    tactic: 'Defense Evasion',
    description: 'Adversaries may abuse Regsvr32 to proxy execution of malicious code.',
    platforms: ['Windows'],
    dataSources: ['Process monitoring', 'Network monitoring', 'Windows Event Logs'],
    defenses: ['Application control', 'Disable regsvr32', 'Internet Explorer security settings'],
    detections: ['Monitor regsvr32 usage', 'Detect network connections from regsvr32']
  },
  {
    id: 'T1036',
    name: 'Masquerading',
    tactic: 'Defense Evasion',
    description: 'Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['File monitoring', 'Process monitoring', 'Binary analysis'],
    defenses: ['Code signing', 'Application control', 'File integrity monitoring'],
    detections: ['Monitor file name anomalies', 'Detect path deviations', 'Analyze binary metadata']
  },
  {
    id: 'T1036.005',
    name: 'Match Legitimate Name or Location',
    tactic: 'Defense Evasion',
    description: 'Adversaries may match or approximate the name of legitimate files or resources.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['File monitoring', 'Process monitoring'],
    defenses: ['Application control', 'Code signing', 'File integrity monitoring'],
    detections: ['Monitor file system anomalies', 'Detect names similar to system files']
  },
  {
    id: 'T1006',
    name: 'Direct Volume Access',
    tactic: 'Defense Evasion',
    description: 'Adversaries may directly access a volume to bypass file access controls.',
    platforms: ['Windows', 'Linux'],
    dataSources: ['API monitoring', 'Raw access read'],
    defenses: ['Restrict raw access', 'Volume encryption', 'Endpoint protection'],
    detections: ['Monitor raw disk access', 'Detect volume shadow service abuse']
  },
  {
    id: 'T1055',
    name: 'Process Injection',
    tactic: 'Defense Evasion',
    description: 'Adversaries may inject code into processes to evade process-based defenses.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['API monitoring', 'Process monitoring'],
    defenses: ['Application control', 'Behavioral prevention', 'EDR'],
    detections: ['Monitor process memory modifications', 'Detect API hooking']
  },
  {
    id: 'T1562',
    name: 'Impair Defenses',
    tactic: 'Defense Evasion',
    description: 'Adversaries may maliciously modify components of a victim environment to evade detection.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['Process monitoring', 'System logs', 'Service monitoring'],
    defenses: ['Tamper protection', 'File integrity monitoring', 'Behavioral prevention'],
    detections: ['Monitor security service stopping', 'Detect configuration changes', 'Analyze driver loading']
  },
  {
    id: 'T1562.001',
    name: 'Disable or Modify Tools',
    tactic: 'Defense Evasion',
    description: 'Adversaries may disable or modify security tools to avoid detection.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Process monitoring', 'Service monitoring', 'Registry monitoring'],
    defenses: ['Tamper protection', 'Restricted admin accounts', 'Application control'],
    detections: ['Monitor service stopping', 'Detect configuration tampering', 'Alert on security tool modifications']
  },

  // CREDENTIAL ACCESS
  {
    id: 'T1003',
    name: 'OS Credential Dumping',
    tactic: 'Credential Access',
    description: 'Adversaries may attempt to dump credentials to obtain account login and credential material.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['API monitoring', 'Process monitoring', 'Security logs'],
    defenses: ['Credential Guard', 'LSASS protection', 'Restricted admin mode'],
    detections: ['Monitor credential dumping', 'Detect hash extraction', 'Analyze LSASS access']
  },
  {
    id: 'T1003.001',
    name: 'LSASS Memory',
    tactic: 'Credential Access',
    description: 'Adversaries may dump credentials from LSASS memory.',
    platforms: ['Windows'],
    dataSources: ['API monitoring', 'Process monitoring', 'Windows Event Logs'],
    defenses: ['Credential Guard', 'LSASS protection', 'WDAC'],
    detections: ['Monitor LSASS access', 'Detect credential dumping tools', 'Alert on suspicious process access']
  },
  {
    id: 'T1003.002',
    name: 'Security Account Manager',
    tactic: 'Credential Access',
    description: 'Adversaries may attempt to extract credential material from the Security Account Manager.',
    platforms: ['Windows'],
    dataSources: ['API monitoring', 'File monitoring', 'Registry monitoring'],
    defenses: ['Restrict registry access', 'System volume encryption', 'Backup protection'],
    detections: ['Monitor SAM access', 'Detect volume shadow copy operations', 'Alert on registry dumps']
  },
  {
    id: 'T1558',
    name: 'Steal or Forge Kerberos Tickets',
    tactic: 'Credential Access',
    description: 'Adversaries may steal or forge Kerberos tickets to enable Pass the Ticket.',
    platforms: ['Windows', 'macOS', 'Linux'],
    dataSources: ['Authentication logs', 'Network logs', 'API monitoring'],
    defenses: ['Privileged Access Management', 'AES encryption', 'Fast ticket expiration'],
    detections: ['Monitor Kerberos authentication', 'Detect golden ticket usage', 'Analyze TGT requests']
  },
  {
    id: 'T1558.001',
    name: 'Golden Ticket',
    tactic: 'Credential Access',
    description: 'Adversaries may forge a Kerberos ticket-granting ticket (TGT) to generate ticket-granting service tickets.',
    platforms: ['Windows'],
    dataSources: ['Authentication logs', 'Windows Event Logs'],
    defenses: ['KRBTGT password rotation', 'Privileged Access Management', 'AES only'],
    detections: ['Monitor TGT lifetimes', 'Detect anomalous TGTs', 'Analyze account usage patterns']
  },
  {
    id: 'T1110',
    name: 'Brute Force',
    tactic: 'Credential Access',
    description: 'Adversaries may use brute force techniques to gain access to accounts.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network', 'Cloud'],
    dataSources: ['Authentication logs', 'Network logs'],
    defenses: ['Account lockout', 'MFA', 'Password policies', 'CAPTCHA'],
    detections: ['Monitor failed logins', 'Detect password spraying', 'Analyze authentication patterns']
  },
  {
    id: 'T1110.001',
    name: 'Password Guessing',
    tactic: 'Credential Access',
    description: 'Adversaries with limited access may attempt to guess passwords.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network', 'Cloud'],
    dataSources: ['Authentication logs', 'Application logs'],
    defenses: ['Account lockout policies', 'Strong password requirements', 'MFA'],
    detections: ['Monitor failed authentication attempts', 'Detect low and slow guessing']
  },
  {
    id: 'T1110.003',
    name: 'Password Spraying',
    tactic: 'Credential Access',
    description: 'Adversaries may use a single password against many accounts to avoid account lockouts.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network', 'Cloud'],
    dataSources: ['Authentication logs', 'Network logs'],
    defenses: ['Account lockout', 'MFA', 'Password policies', 'Login anomaly detection'],
    detections: ['Monitor multiple failed logins across accounts', 'Detect unusual authentication patterns']
  },
  {
    id: 'T1552',
    name: 'Unsecured Credentials',
    tactic: 'Credential Access',
    description: 'Adversaries may search compromised systems to find and obtain insecurely stored credentials.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['File monitoring', 'Command monitoring', 'Process monitoring'],
    defenses: ['Password managers', 'Credential vaults', 'Secure credential storage'],
    detections: ['Monitor credential file access', 'Detect password searches', 'Analyze file access patterns']
  },
  {
    id: 'T1552.001',
    name: 'Credentials In Files',
    tactic: 'Credential Access',
    description: 'Adversaries may search local file systems and remote file shares for files containing passwords.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['File monitoring', 'Command monitoring'],
    defenses: ['Prevent plain text credentials', 'Credential vaults', 'DLP'],
    detections: ['Monitor file access to sensitive files', 'Detect credential file patterns']
  },
  {
    id: 'T1552.004',
    name: 'Private Keys',
    tactic: 'Credential Access',
    description: 'Adversaries may search for private key certificate files on compromised systems.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['File monitoring', 'Command monitoring'],
    defenses: ['Hardware security modules', 'Key vaults', 'Access controls'],
    detections: ['Monitor private key access', 'Detect SSH key harvesting']
  },
  {
    id: 'T1212',
    name: 'Exploitation for Credential Access',
    tactic: 'Credential Access',
    description: 'Adversaries may exploit software vulnerabilities to gain access to credentials.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['Application logs', 'System logs', 'Network logs'],
    defenses: ['Patch management', 'Exploit prevention', 'Vulnerability scanning'],
    detections: ['Monitor for exploitation attempts', 'Detect anomalous process behavior']
  },

  // DISCOVERY
  {
    id: 'T1083',
    name: 'File and Directory Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may enumerate files and directories or search specific locations.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['Process monitoring', 'Command monitoring', 'File monitoring'],
    defenses: ['File access controls', 'Least privilege', 'Data masking'],
    detections: ['Monitor file enumeration', 'Detect recursive directory searches', 'Analyze file access patterns']
  },
  {
    id: 'T1082',
    name: 'System Information Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may attempt to get detailed information about the operating system and hardware.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network', 'Cloud'],
    dataSources: ['Process monitoring', 'Command monitoring', 'System calls'],
    defenses: ['Restrict system information access', 'Limit command execution'],
    detections: ['Monitor system information queries', 'Detect reconnaissance commands']
  },
  {
    id: 'T1018',
    name: 'Remote System Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may attempt to get a listing of other systems on the network.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['Network logs', 'Process monitoring', 'Command monitoring'],
    defenses: ['Network segmentation', 'Broadcast traffic restriction', 'Host isolation'],
    detections: ['Monitor network scanning', 'Detect ping sweeps', 'Analyze network enumeration']
  },
  {
    id: 'T1057',
    name: 'Process Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may attempt to get information about running processes.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Process monitoring', 'API monitoring', 'Command monitoring'],
    defenses: ['Limit process information access', 'Privileged access management'],
    detections: ['Monitor process enumeration', 'Detect tasklist/ps usage', 'Analyze process queries']
  },
  {
    id: 'T1016',
    name: 'System Network Configuration Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may look for details about the network configuration of systems.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['Process monitoring', 'Command monitoring', 'Network logs'],
    defenses: ['Restrict network configuration access', 'Network segmentation'],
    detections: ['Monitor ipconfig/ifconfig usage', 'Detect route table enumeration', 'Analyze ARP tables']
  },
  {
    id: 'T1016.001',
    name: 'Internet Connection Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may check for internet connectivity on compromised systems.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Process monitoring', 'Network logs', 'Command monitoring'],
    defenses: ['Network segmentation', 'Proxy restrictions'],
    detections: ['Monitor network connectivity checks', 'Detect ping to external hosts']
  },
  {
    id: 'T1033',
    name: 'System Owner/User Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may attempt to identify the primary user, current user, or set of users on a system.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['Process monitoring', 'Command monitoring', 'System logs'],
    defenses: ['User access controls', 'Limit command execution'],
    detections: ['Monitor whoami usage', 'Detect user enumeration commands', 'Analyze account queries']
  },
  {
    id: 'T1087',
    name: 'Account Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may attempt to get a listing of accounts on a system or within an environment.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network', 'Cloud'],
    dataSources: ['Process monitoring', 'Command monitoring', 'Authentication logs'],
    defenses: ['Limit account enumeration permissions', 'Privileged Access Management'],
    detections: ['Monitor net user/enum usage', 'Detect directory enumeration', 'Analyze LDAP queries']
  },
  {
    id: 'T1087.001',
    name: 'Local Account',
    tactic: 'Discovery',
    description: 'Adversaries may attempt to enumerate local system accounts.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Process monitoring', 'Command monitoring', 'API monitoring'],
    defenses: ['Restrict local user enumeration', 'Audit account management'],
    detections: ['Monitor local account enumeration', 'Detect suspicious user queries']
  },
  {
    id: 'T1087.002',
    name: 'Domain Account',
    tactic: 'Discovery',
    description: 'Adversaries may attempt to enumerate domain accounts.',
    platforms: ['Windows', 'Azure AD'],
    dataSources: ['Process monitoring', 'Active Directory logs', 'Network logs'],
    defenses: ['Restrict LDAP access', 'Audit directory service access', 'Privileged Access Management'],
    detections: ['Monitor LDAP queries', 'Detect enumeration patterns', 'Analyze directory access']
  },
  {
    id: 'T1049',
    name: 'System Network Connections Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may attempt to get a listing of network connections to or from the compromised system.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Process monitoring', 'Command monitoring', 'Network logs'],
    defenses: ['Network segmentation', 'Host firewall', 'Connection filtering'],
    detections: ['Monitor netstat usage', 'Detect connection enumeration', 'Analyze network reconnaissance']
  },
  {
    id: 'T1007',
    name: 'System Service Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may try to get information about registered services.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Process monitoring', 'Command monitoring', 'System logs'],
    defenses: ['Restrict service enumeration', 'Audit system access'],
    detections: ['Monitor service enumeration', 'Detect sc/service usage', 'Analyze service queries']
  },
  {
    id: 'T1518',
    name: 'Software Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may attempt to get a listing of software and software versions installed on a system.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Process monitoring', 'Command monitoring', 'Registry monitoring'],
    defenses: ['Application control', 'Limit software inventory access'],
    detections: ['Monitor software enumeration', 'Detect WMI queries for software', 'Analyze registry queries']
  },

  // LATERAL MOVEMENT
  {
    id: 'T1021',
    name: 'Remote Services',
    tactic: 'Lateral Movement',
    description: 'Adversaries may use valid accounts to log into remote services.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['Authentication logs', 'Network logs', 'Process monitoring'],
    defenses: ['MFA', 'Jump servers', 'Privileged Access Management', 'Network segmentation'],
    detections: ['Monitor remote logins', 'Detect unusual remote services', 'Analyze lateral movement patterns']
  },
  {
    id: 'T1021.001',
    name: 'Remote Desktop Protocol',
    tactic: 'Lateral Movement',
    description: 'Adversaries may use RDP to move laterally within an environment.',
    platforms: ['Windows'],
    dataSources: ['Authentication logs', 'Network traffic', 'Windows Event Logs'],
    defenses: ['Network segmentation', 'RDP restrictions', 'MFA', 'Gateway restrictions'],
    detections: ['Monitor RDP connections', 'Detect unusual login times', 'Analyze source IP addresses']
  },
  {
    id: 'T1021.002',
    name: 'SMB/Windows Admin Shares',
    tactic: 'Lateral Movement',
    description: 'Adversaries may use SMB and Windows admin shares to move laterally.',
    platforms: ['Windows'],
    dataSources: ['File monitoring', 'Authentication logs', 'Network logs'],
    defenses: ['Disable Admin Shares', 'Host firewall', 'Network segmentation', 'Privileged Access Management'],
    detections: ['Monitor admin share access', 'Detect PsExec usage', 'Analyze file shares']
  },
  {
    id: 'T1021.004',
    name: 'SSH',
    tactic: 'Lateral Movement',
    description: 'Adversaries may use SSH to move laterally between systems.',
    platforms: ['Linux', 'macOS', 'Network'],
    dataSources: ['Authentication logs', 'Command monitoring', 'Network logs'],
    defenses: ['SSH key management', 'Jump hosts', 'MFA', 'Network segmentation'],
    detections: ['Monitor SSH connections', 'Detect SSH tunneling', 'Analyze key usage']
  },
  {
    id: 'T1021.005',
    name: 'VNC',
    tactic: 'Lateral Movement',
    description: 'Adversaries may use VNC to remotely control systems.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Process monitoring', 'Network logs', 'Authentication logs'],
    defenses: ['VNC encryption', 'Strong passwords', 'Network segmentation'],
    detections: ['Monitor VNC connections', 'Detect anomalous VNC usage']
  },
  {
    id: 'T1210',
    name: 'Exploitation of Remote Services',
    tactic: 'Lateral Movement',
    description: 'Adversaries may exploit remote services to gain unauthorized access.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['Application logs', 'Network logs', 'System logs'],
    defenses: ['Patch management', 'Network segmentation', 'Intrusion prevention'],
    detections: ['Monitor for exploitation attempts', 'Detect anomalous service behavior']
  },
  {
    id: 'T1550',
    name: 'Use Alternate Authentication Material',
    tactic: 'Lateral Movement',
    description: 'Adversaries may use alternate authentication material to move laterally.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['Authentication logs', 'Network logs', 'Process monitoring'],
    defenses: ['MFA', 'Credential Guard', 'Privileged Access Management'],
    detections: ['Monitor pass-the-hash', 'Detect ticket reuse', 'Analyze authentication anomalies']
  },
  {
    id: 'T1550.002',
    name: 'Use Alternate Authentication Material: Pass the Hash',
    tactic: 'Lateral Movement',
    description: 'Adversaries may pass the hash using captured password hashes.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Authentication logs', 'Network logs'],
    defenses: ['Credential Guard', 'LSASS protection', 'Restricted Admin Mode'],
    detections: ['Monitor NTLM authentications', 'Detect Pass the Hash patterns', 'Analyze logon types']
  },
  {
    id: 'T1550.003',
    name: 'Use Alternate Authentication Material: Pass the Ticket',
    tactic: 'Lateral Movement',
    description: 'Adversaries may pass Kerberos tickets to move laterally.',
    platforms: ['Windows', 'macOS', 'Linux'],
    dataSources: ['Authentication logs', 'Network logs'],
    defenses: ['Privileged Access Management', 'Fast ticket expiration', 'AES encryption'],
    detections: ['Monitor TGS requests', 'Detect unusual ticket usage', 'Analyze Kerberos traffic']
  },
  {
    id: 'T1570',
    name: 'Lateral Tool Transfer',
    tactic: 'Lateral Movement',
    description: 'Adversaries may transfer tools or files from an external system into a compromised environment.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['File monitoring', 'Network logs', 'Process monitoring'],
    defenses: ['Network segmentation', 'Host firewall', 'Application control'],
    detections: ['Monitor file transfers', 'Detect PsExec file drops', 'Analyze network file copies']
  },

  // COLLECTION
  {
    id: 'T1560',
    name: 'Archive Collected Data',
    tactic: 'Collection',
    description: 'Adversaries may compress and/or encrypt data that is collected prior to exfiltration.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['File monitoring', 'Process monitoring', 'Command monitoring'],
    defenses: ['Data loss prevention', 'Network monitoring', 'Behavioral prevention'],
    detections: ['Monitor compression utilities', 'Detect large archive creation', 'Analyze encryption activity']
  },
  {
    id: 'T1560.001',
    name: 'Archive via Utility',
    tactic: 'Collection',
    description: 'Adversaries may use utilities to compress and encrypt collected data.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Process monitoring', 'File monitoring'],
    defenses: ['Application control', 'DLP', 'Restrict compression tools'],
    detections: ['Monitor archive creation', 'Detect suspicious compression patterns']
  },
  {
    id: 'T1119',
    name: 'Automated Collection',
    tactic: 'Collection',
    description: 'Adversaries may automate collection of data using scripts and other automated mechanisms.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['File monitoring', 'Process monitoring', 'Script logs'],
    defenses: ['Data loss prevention', 'Application control', 'Behavioral prevention'],
    detections: ['Monitor automated file access', 'Detect scripted collection', 'Analyze file operations']
  },
  {
    id: 'T1113',
    name: 'Screen Capture',
    tactic: 'Collection',
    description: 'Adversaries may attempt to take screen captures to gather information.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['API monitoring', 'Process monitoring', 'Screen monitoring'],
    defenses: ['Application control', 'Screen privacy filters', 'Behavioral prevention'],
    detections: ['Monitor screen capture APIs', 'Detect screenshot tools', 'Analyze graphics device access']
  },
  {
    id: 'T1005',
    name: 'Data from Local System',
    tactic: 'Collection',
    description: 'Adversaries may search local system sources to find files of interest.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['File monitoring', 'Process monitoring', 'Command monitoring'],
    defenses: ['Data loss prevention', 'File access controls', 'Encryption'],
    detections: ['Monitor file access patterns', 'Detect sensitive file access', 'Analyze data staging']
  },
  {
    id: 'T1039',
    name: 'Data from Network Shared Drive',
    tactic: 'Collection',
    description: 'Adversaries may search network shares for files of interest.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['File monitoring', 'Share access logs', 'Network logs'],
    defenses: ['Network share permissions', 'Data classification', 'DLP'],
    detections: ['Monitor network share access', 'Detect bulk file copying', 'Analyze file share enumeration']
  },
  {
    id: 'T1213',
    name: 'Data from Information Repositories',
    tactic: 'Collection',
    description: 'Adversaries may leverage information repositories to mine valuable information.',
    platforms: ['Windows', 'Linux', 'macOS', 'SaaS', 'Cloud'],
    dataSources: ['Application logs', 'File monitoring', 'API monitoring'],
    defenses: ['Access controls', 'Data loss prevention', 'Audit logging'],
    detections: ['Monitor repository access', 'Detect bulk downloads', 'Analyze query patterns']
  },
  {
    id: 'T1123',
    name: 'Audio Capture',
    tactic: 'Collection',
    description: 'Adversaries may capture audio recordings from compromised systems.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['API monitoring', 'Process monitoring', 'Device monitoring'],
    defenses: ['Application control', 'Microphone access controls', 'Behavioral prevention'],
    detections: ['Monitor audio device access', 'Detect microphone activation', 'Analyze audio API calls']
  },
  {
    id: 'T1125',
    name: 'Video Capture',
    tactic: 'Collection',
    description: 'Adversaries may capture video recordings from compromised systems.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['API monitoring', 'Process monitoring', 'Device monitoring'],
    defenses: ['Application control', 'Camera access controls', 'Privacy settings'],
    detections: ['Monitor camera activation', 'Detect video recording APIs', 'Analyze device access']
  },

  // EXFILTRATION
  {
    id: 'T1041',
    name: 'Exfiltration Over C2 Channel',
    tactic: 'Exfiltration',
    description: 'Adversaries may exfiltrate data over their command and control channel.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Network traffic', 'Process monitoring'],
    defenses: ['Network monitoring', 'Data loss prevention', 'Network segmentation'],
    detections: ['Monitor outbound traffic', 'Detect large data transfers', 'Analyze protocol anomalies']
  },
  {
    id: 'T1048',
    name: 'Exfiltration Over Alternative Protocol',
    tactic: 'Exfiltration',
    description: 'Adversaries may exfiltrate data over alternative protocols.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['Network traffic', 'Command monitoring'],
    defenses: ['Network segmentation', 'Proxy filtering', 'Firewall rules'],
    detections: ['Monitor unusual protocols', 'Detect DNS tunneling', 'Analyze ICMP traffic']
  },
  {
    id: 'T1048.001',
    name: 'Exfiltration Over Symmetric Encrypted Non-C2 Protocol',
    tactic: 'Exfiltration',
    description: 'Adversaries may exfiltrate data over symmetrically encrypted non-C2 protocols.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Network traffic', 'Process monitoring'],
    defenses: ['SSL inspection', 'Network monitoring', 'DLP'],
    detections: ['Monitor encrypted traffic', 'Detect unusual TLS patterns', 'Analyze certificate anomalies']
  },
  {
    id: 'T1048.003',
    name: 'Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol',
    tactic: 'Exfiltration',
    description: 'Adversaries may exfiltrate data over unencrypted or obfuscated non-C2 protocols.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['Network traffic', 'Command monitoring'],
    defenses: ['Network monitoring', 'DLP', 'Protocol enforcement'],
    detections: ['Monitor clear text protocols', 'Detect obfuscated traffic', 'Analyze data encoding']
  },
  {
    id: 'T1567',
    name: 'Exfiltration Over Web Service',
    tactic: 'Exfiltration',
    description: 'Adversaries may exfiltrate data to a web service.',
    platforms: ['Windows', 'Linux', 'macOS', 'SaaS'],
    dataSources: ['Network traffic', 'Application logs'],
    defenses: ['Web proxy', 'Cloud access security broker', 'DLP'],
    detections: ['Monitor cloud uploads', 'Detect large web uploads', 'Analyze API usage']
  },
  {
    id: 'T1567.002',
    name: 'Exfiltration to Cloud Storage',
    tactic: 'Exfiltration',
    description: 'Adversaries may exfiltrate data to cloud storage services.',
    platforms: ['Windows', 'Linux', 'macOS', 'SaaS', 'Cloud'],
    dataSources: ['Network traffic', 'Cloud logs', 'Application logs'],
    defenses: ['CASB', 'DLP', 'Access controls', 'Shadow IT prevention'],
    detections: ['Monitor cloud storage uploads', 'Detect unusual data volumes', 'Analyze OAuth usage']
  },
  {
    id: 'T1020',
    name: 'Automated Exfiltration',
    tactic: 'Exfiltration',
    description: 'Adversaries may exfiltrate data using automated processing.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Network traffic', 'Process monitoring', 'Script logs'],
    defenses: ['Network monitoring', 'Behavioral prevention', 'DLP'],
    detections: ['Monitor automated uploads', 'Detect scripted transfers', 'Analyze recurring traffic']
  },
  {
    id: 'T1029',
    name: 'Scheduled Transfer',
    tactic: 'Exfiltration',
    description: 'Adversaries may schedule data exfiltration to occur at specific times.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Process monitoring', 'Network logs', 'Task scheduler'],
    defenses: ['Network monitoring', 'Behavioral prevention', 'Restrict scheduling'],
    detections: ['Monitor scheduled tasks', 'Detect unusual transfer times', 'Analyze off-hours activity']
  },
  {
    id: 'T1040',
    name: 'Network Sniffing',
    tactic: 'Collection',
    description: 'Adversaries may sniff network traffic to capture information passing through the network.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['Network device logs', 'Process monitoring', 'Network traffic'],
    defenses: ['Network segmentation', 'Encryption', 'Port security'],
    detections: ['Monitor interface promiscuous mode', 'Detect ARP spoofing', 'Analyze network taps']
  },

  // IMPACT
  {
    id: 'T1486',
    name: 'Data Encrypted for Impact',
    tactic: 'Impact',
    description: 'Adversaries may encrypt data on target systems to interrupt availability.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['File monitoring', 'Process monitoring', 'API monitoring'],
    defenses: ['Data backup', 'Behavioral prevention', 'Application control'],
    detections: ['Monitor mass file modification', 'Detect encryption APIs', 'Analyze file entropy changes']
  },
  {
    id: 'T1490',
    name: 'Inhibit System Recovery',
    tactic: 'Impact',
    description: 'Adversaries may delete or remove built-in operating system data and turn off services.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Process monitoring', 'Command monitoring', 'Service monitoring'],
    defenses: ['Backup systems', 'Recovery partition protection', 'Service tamper protection'],
    detections: ['Monitor shadow copy deletion', 'Detect backup disabling', 'Analyze recovery inhibition']
  },
  {
    id: 'T1491',
    name: 'Defacement',
    tactic: 'Impact',
    description: 'Adversaries may modify visual content available internally or externally.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['File monitoring', 'Web logs', 'Process monitoring'],
    defenses: ['File integrity monitoring', 'Backup systems', 'Web application firewalls'],
    detections: ['Monitor website modifications', 'Detect file changes', 'Analyze web content']
  },
  {
    id: 'T1496',
    name: 'Resource Hijacking',
    tactic: 'Impact',
    description: 'Adversaries may leverage compute resources to impact availability or for cryptocurrency mining.',
    platforms: ['Windows', 'Linux', 'macOS', 'Cloud'],
    dataSources: ['Process monitoring', 'Resource monitoring', 'Power monitoring'],
    defenses: ['Resource monitoring', 'Application control', 'Power policies'],
    detections: ['Monitor CPU/GPU usage', 'Detect cryptocurrency miners', 'Analyze resource consumption']
  },
  {
    id: 'T1499',
    name: 'Endpoint Denial of Service',
    tactic: 'Impact',
    description: 'Adversaries may perform endpoint denial of service to degrade or block availability.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['Process monitoring', 'System logs', 'Network logs'],
    defenses: ['Rate limiting', 'Resource controls', 'Traffic filtering'],
    detections: ['Monitor resource exhaustion', 'Detect process termination', 'Analyze system crashes']
  },
  {
    id: 'T1499.001',
    name: 'OS Exhaustion Flood',
    tactic: 'Impact',
    description: 'Adversaries may target the operating system to cause an exhaustion of resources.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Process monitoring', 'System logs', 'Resource monitoring'],
    defenses: ['Resource limits', 'Connection limits', 'Rate limiting'],
    detections: ['Monitor system resource usage', 'Detect fork bombs', 'Analyze handle exhaustion']
  },
  {
    id: 'T1529',
    name: 'System Shutdown/Reboot',
    tactic: 'Impact',
    description: 'Adversaries may shut down or reboot systems to disrupt access or aid in other malicious activities.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['System logs', 'Command monitoring', 'Process monitoring'],
    defenses: ['Remote shutdown restrictions', 'Privileged access management', 'MFA for administrative actions'],
    detections: ['Monitor shutdown commands', 'Detect unexpected reboots', 'Analyze system events']
  },
  {
    id: 'T1565',
    name: 'Data Manipulation',
    tactic: 'Impact',
    description: 'Adversaries may insert, delete, or manipulate data to manipulate external outcomes.',
    platforms: ['Windows', 'Linux', 'macOS', 'Network'],
    dataSources: ['File monitoring', 'Database logs', 'API monitoring'],
    defenses: ['File integrity monitoring', 'Database integrity checks', 'Transaction logging'],
    detections: ['Monitor data modifications', 'Detect integrity violations', 'Analyze data patterns']
  },
  {
    id: 'T1561',
    name: 'Disk Wipe',
    tactic: 'Impact',
    description: 'Adversaries may wipe or corrupt raw disk data to inhibit system recovery.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['Disk monitoring', 'Process monitoring', 'Command monitoring'],
    defenses: ['Disk encryption', 'Backup systems', 'Physical access controls'],
    detections: ['Monitor disk operations', 'Detect volume formatting', 'Analyze partition modifications']
  }
];

const tactics = [
  { id: 'initial-access', name: 'Initial Access', icon: Sword, color: 'text-red-400' },
  { id: 'execution', name: 'Execution', icon: Command, color: 'text-orange-400' },
  { id: 'persistence', name: 'Persistence', icon: Lock, color: 'text-yellow-400' },
  { id: 'privilege-escalation', name: 'Privilege Escalation', icon: Shield, color: 'text-green-400' },
  { id: 'defense-evasion', name: 'Defense Evasion', icon: Eye, color: 'text-cyan-400' },
  { id: 'credential-access', name: 'Credential Access', icon: Fingerprint, color: 'text-blue-400' },
  { id: 'discovery', name: 'Discovery', icon: FileSearch, color: 'text-purple-400' },
  { id: 'lateral-movement', name: 'Lateral Movement', icon: Radio, color: 'text-pink-400' },
  { id: 'collection', name: 'Collection', icon: Database, color: 'text-indigo-400' },
  { id: 'exfiltration', name: 'Exfiltration', icon: ExternalLink, color: 'text-rose-400' },
  { id: 'impact', name: 'Impact', icon: AlertTriangle, color: 'text-red-500' }
];

export default function MitreAttack() {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);
  const [selectedTechnique, setSelectedTechnique] = useState<Technique | null>(null);

  const filteredTechniques = techniques.filter((tech) => {
    const matchesSearch = tech.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         tech.id.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesTactic = !selectedTactic || tech.tactic.toLowerCase().replace(/\s+/g, '-') === selectedTactic;
    return matchesSearch && matchesTactic;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">MITRE ATT&CK Framework</h2>
          <p className="text-gray-400 mt-1">Threats and Techniques Mapping</p>
        </div>
        <a
          href="https://attack.mitre.org/"
          target="_blank"
          rel="noopener noreferrer"
          className="btn-secondary flex items-center gap-2"
        >
          <ExternalLink className="w-4 h-4" />
          Visit MITRE ATT&CK
        </a>
      </div>

      {/* Tactics Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        {tactics.map((tactic) => {
          const Icon = tactic.icon;
          return (
            <button
              key={tactic.id}
              onClick={() => setSelectedTactic(selectedTactic === tactic.id ? null : tactic.id)}
              className={`glass-card p-4 text-left transition-all hover:bg-white/5 ${
                selectedTactic === tactic.id ? 'ring-2 ring-cyan-400' : ''
              }`}
            >
              <Icon className={`w-6 h-6 ${tactic.color} mb-2`} />
              <p className="text-xs font-medium">{tactic.name}</p>
            </button>
          );
        })}
      </div>

      {/* Search */}
      <div className="flex gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search techniques by ID or name..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="input-field w-full pl-10"
          />
        </div>
        <button className="btn-secondary flex items-center gap-2">
          <Filter className="w-4 h-4" />
          Filter
        </button>
      </div>

      {/* Techniques Table */}
      <div className="glass-card overflow-hidden">
        <table className="data-table">
          <thead>
            <tr>
              <th>Technique ID</th>
              <th>Name</th>
              <th>Tactic</th>
              <th>Platforms</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {filteredTechniques.map((tech) => (
              <tr key={tech.id}>
                <td>
                  <span className="font-mono text-cyan-400">{tech.id}</span>
                </td>
                <td className="font-medium">{tech.name}</td>
                <td>{tech.tactic}</td>
                <td>
                  <div className="flex gap-1 flex-wrap">
                    {tech.platforms.map((platform) => (
                      <span key={platform} className="badge badge-info">
                        {platform}
                      </span>
                    ))}
                  </div>
                </td>
                <td>
                  <button
                    onClick={() => setSelectedTechnique(tech)}
                    className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                  >
                    Details
                    <ChevronRight className="w-4 h-4" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Technique Detail Modal */}
      {selectedTechnique && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="glass-card w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between p-6 border-b border-white/5">
              <div>
                <div className="flex items-center gap-3 mb-2">
                  <span className="font-mono text-cyan-400">{selectedTechnique.id}</span>
                  <span className="badge badge-info">{selectedTechnique.tactic}</span>
                </div>
                <h3 className="text-xl font-bold">{selectedTechnique.name}</h3>
              </div>
              <button
                onClick={() => setSelectedTechnique(null)}
                className="text-gray-400 hover:text-white"
              >
                <span className="sr-only">Close</span>
                <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <div className="p-6 space-y-6">
              <div>
                <h4 className="font-semibold mb-2 flex items-center gap-2">
                  <Info className="w-4 h-4 text-cyan-400" />
                  Description
                </h4>
                <p className="text-gray-300">{selectedTechnique.description}</p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h4 className="font-semibold mb-2">Data Sources</h4>
                  <ul className="space-y-1">
                    {selectedTechnique.dataSources.map((source) => (
                      <li key={source} className="text-sm text-gray-400 flex items-center gap-2">
                        <Database className="w-3 h-3" />
                        {source}
                      </li>
                    ))}
                  </ul>
                </div>
                <div>
                  <h4 className="font-semibold mb-2">Defenses</h4>
                  <ul className="space-y-1">
                    {selectedTechnique.defenses.map((defense) => (
                      <li key={defense} className="text-sm text-gray-400 flex items-center gap-2">
                        <Shield className="w-3 h-3" />
                        {defense}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              <div>
                <h4 className="font-semibold mb-2">Detection</h4>
                <ul className="space-y-2">
                  {selectedTechnique.detections.map((detection) => (
                    <li key={detection} className="text-sm text-gray-300 flex items-start gap-2">
                      <Target className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" />
                      {detection}
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 p-6 border-t border-white/5">
              <button
                onClick={() => setSelectedTechnique(null)}
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