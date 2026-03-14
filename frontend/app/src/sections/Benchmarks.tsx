import { useState } from 'react';
import {
  Shield,
  Search,
  ExternalLink,
  ChevronRight,
  Info,
  FileText,
  Lock,
  Server,
  Database,
  Clipboard,
  CheckCircle,
  Globe,
  Cloud,
  Terminal
} from 'lucide-react';

interface SecurityControl {
  id: string;
  controlNumber: string;
  name: string;
  framework: string;
  category: string;
  description: string;
  implementation: string;
  testing: string;
  priority: 'Critical' | 'High' | 'Medium' | 'Low';
  applicableSystems: string[];
  complianceMappings: {
    [key: string]: string;
  };
}

const securityControls: SecurityControl[] = [
  // NIST CYBERSECURITY FRAMEWORK (CSF)
  {
    id: 'nist-1',
    controlNumber: 'ID.AM-1',
    framework: 'NIST CSF',
    category: 'Identify',
    name: 'Physical Devices and Systems Inventory',
    description: 'The organization develops and maintains an inventory of physical devices and systems that compose its infrastructure.',
    implementation: 'Deploy automated asset discovery tools (NMAP, Lansweeper, or SCCM) to scan networks continuously. Maintain CMDB with device classification (critical, high, medium, low). Include IoT, OT, and mobile devices. Review quarterly.',
    testing: 'Verify 95% of network-connected assets are discovered within 24 hours of connection. Validate asset ownership attribution.',
    priority: 'Critical',
    applicableSystems: ['Windows', 'Linux', 'Network', 'Cloud', 'IoT'],
    complianceMappings: { 'ISO 27001': 'A.8.1.1', 'CIS': '1.1', 'PCI DSS': '2.4' }
  },
  {
    id: 'nist-2',
    controlNumber: 'ID.AM-2',
    framework: 'NIST CSF',
    category: 'Identify',
    name: 'Software Platform and Application Inventory',
    description: 'The organization inventories all software platforms and applications authorized to operate in the organization.',
    implementation: 'Implement software asset management (Flexera, ServiceNow SAM) with discovery agents. Maintain approved software lists (whitelisting). Catalog all SaaS applications using CASB. Version control and license management.',
    testing: 'Quarterly audits of installed software against authorized inventory. Detect unauthorized software within 4 hours.',
    priority: 'Critical',
    applicableSystems: ['Windows', 'Linux', 'macOS', 'SaaS'],
    complianceMappings: { 'ISO 27001': 'A.8.1.1', 'CIS': '2.1', 'PCI DSS': '2.4' }
  },
  {
    id: 'nist-3',
    controlNumber: 'PR.AC-1',
    framework: 'NIST CSF',
    category: 'Protect',
    name: 'Access Control Policies and Procedures',
    description: 'Policies and procedures are maintained and used to manage access to assets consistent with the organization’s risk management strategy.',
    implementation: 'Document and enforce identity and access management policy covering provisioning, de-provisioning, reviews (quarterly), and privileged access. Implement RBAC with least privilege. Use Identity Governance (SailPoint, Okta).',
    testing: 'Review access logs for terminated employees within 24 hours. Verify quarterly access reviews completion rate.',
    priority: 'Critical',
    applicableSystems: ['Windows', 'Linux', 'Cloud', 'Applications'],
    complianceMappings: { 'ISO 27001': 'A.9.1.1', 'CIS': '16.1', 'PCI DSS': '7.1' }
  },
  {
    id: 'nist-4',
    controlNumber: 'PR.AC-4',
    framework: 'NIST CSF',
    category: 'Protect',
    name: 'Remote Access Control',
    description: 'Access permissions and authorizations are managed, incorporating the principle of least privilege for remote access.',
    implementation: 'Enforce MFA for all remote access (VPN, RDP, SSH). Implement Zero Trust Network Access (ZTNA) replacing VPN where possible. Session recording for privileged remote access. Geofencing and time-based restrictions.',
    testing: 'Attempt unauthorized remote access and verify blocking. Review remote access logs weekly for anomalies.',
    priority: 'High',
    applicableSystems: ['Network', 'Windows', 'Linux', 'Cloud'],
    complianceMappings: { 'ISO 27001': 'A.9.4.2', 'CIS': '13.5', 'PCI DSS': '8.3' }
  },
  {
    id: 'nist-5',
    controlNumber: 'PR.DS-1',
    framework: 'NIST CSF',
    category: 'Protect',
    name: 'Data-at-Rest Protection',
    description: 'Data-at-rest is protected consistent with the organization’s risk strategy to protect confidentiality, integrity, and availability.',
    implementation: 'Deploy full disk encryption (BitLocker for Windows, FileVault for macOS, LUKS for Linux) on all endpoints. Database encryption (TDE). Key management via HSM or Cloud KMS. Validate encryption status via MDM/GPO.',
    testing: 'Attempt to access unencrypted drive on decommissioned device. Verify encryption compliance rates monthly.',
    priority: 'High',
    applicableSystems: ['Windows', 'Linux', 'macOS', 'Database'],
    complianceMappings: { 'ISO 27001': 'A.10.1.1', 'CIS': '10.1', 'PCI DSS': '3.4' }
  },
  {
    id: 'nist-6',
    controlNumber: 'PR.DS-2',
    framework: 'NIST CSF',
    category: 'Protect',
    name: 'Data-in-Transit Protection',
    description: 'Data-in-transit is protected consistent with the organization’s risk strategy to protect confidentiality, integrity, and availability.',
    implementation: 'Enforce TLS 1.2+ for all external connections. Internal network segmentation with IPsec/SSL where sensitive. Certificate pinning for mobile apps. Network-level DLP inspection for sensitive data flows.',
    testing: 'Packet capture analysis to verify no clear-text credentials. SSL/TLS scanning (Qualys SSL Labs) quarterly.',
    priority: 'High',
    applicableSystems: ['Network', 'Cloud', 'Applications'],
    complianceMappings: { 'ISO 27001': 'A.13.2.1', 'CIS': '14.2', 'PCI DSS': '4.1' }
  },
  {
    id: 'nist-7',
    controlNumber: 'PR.IP-9',
    framework: 'NIST CSF',
    category: 'Protect',
    name: 'Incident Response Plan',
    description: 'Response plans are developed, maintained, and tested to ensure timely response to detected cybersecurity events.',
    implementation: 'Maintain incident response plan with defined roles (CSIRT), communication trees, escalation matrix, and playbooks (phishing, malware, data breach). Tabletop exercises quarterly. Red team annually.',
    testing: 'Review IR plan updates within 24 hours of major infrastructure changes. Measure MTTD/MTTR monthly.',
    priority: 'Critical',
    applicableSystems: ['All'],
    complianceMappings: { 'ISO 27001': 'A.16.1.1', 'CIS': '19.1', 'PCI DSS': '12.10' }
  },
  {
    id: 'nist-8',
    controlNumber: 'DE.AE-1',
    framework: 'NIST CSF',
    category: 'Detect',
    name: 'Anomalies and Events Detection',
    description: 'A baseline of network operations and expected data flows is established and maintained.',
    implementation: 'Deploy SIEM (Splunk, Sentinel, QRadar) with UEBA. Baseline normal network traffic using NTA (Darktrace, Vectra). Baseline endpoint behavior using EDR. Alert on deviations >2 standard deviations.',
    testing: 'Simulate anomalous behavior and verify detection within 15 minutes. Tune false positives to <5%.',
    priority: 'High',
    applicableSystems: ['Network', 'Endpoint', 'Cloud'],
    complianceMappings: { 'ISO 27001': 'A.12.4.1', 'CIS': '8.1', 'PCI DSS': '10.6' }
  },
  {
    id: 'nist-9',
    controlNumber: 'RS.AN-1',
    framework: 'NIST CSF',
    category: 'Respond',
    name: 'Incident Analysis',
    description: 'Analysis is conducted to ensure adequate response and support recovery activities.',
    implementation: 'Forensic analysis procedures including memory dumps, disk imaging, and log correlation. Malware analysis sandbox. Chain of custody documentation. Timeline reconstruction.',
    testing: 'Quarterly forensic readiness drills. Validate log retention meets investigation needs (90 days hot, 1 year cold).',
    priority: 'High',
    applicableSystems: ['All'],
    complianceMappings: { 'ISO 27001': 'A.16.1.6', 'CIS': '19.2', 'PCI DSS': '12.10.4' }
  },
  {
    id: 'nist-10',
    controlNumber: 'RC.RP-1',
    framework: 'NIST CSF',
    category: 'Recover',
    name: 'Recovery Plan',
    description: 'Recovery processes and procedures are executed and maintained to ensure timely restoration of systems or assets affected by cybersecurity events.',
    implementation: 'Document recovery procedures for critical systems (RTO/RPO defined). Backup restoration tested monthly. Cyber insurance validation. Alternative communication methods identified.',
    testing: 'Full restoration drill quarterly. Validate backup integrity via test restores. Document lessons learned.',
    priority: 'High',
    applicableSystems: ['Infrastructure', 'Cloud', 'Database'],
    complianceMappings: { 'ISO 27001': 'A.17.1.1', 'CIS': '11.1', 'PCI DSS': '12.10.1' }
  },

  // ISO 27001 CONTROLS
  {
    id: 'iso-1',
    controlNumber: 'A.5.1',
    framework: 'ISO 27001',
    category: 'Organizational Controls',
    name: 'Policies for Information Security',
    description: 'Management direction and support for information security in accordance with business requirements, relevant laws and regulations.',
    implementation: 'Information Security Policy signed by CEO/CISO annually. Acceptable Use Policy, Password Policy, Remote Work Policy. Employee acknowledgment tracking. Policy review cycle (annual).',
    testing: 'Review policy version control. Verify employee acknowledgment records. Check policy exception approvals.',
    priority: 'Critical',
    applicableSystems: ['All'],
    complianceMappings: { 'NIST': 'ID.GV-1', 'SOC 2': 'CC1.1', 'GDPR': 'Article 32' }
  },
  {
    id: 'iso-2',
    controlNumber: 'A.9.4.5',
    framework: 'ISO 27001',
    category: 'Access Control',
    name: 'Secure Log-on Procedures',
    description: 'Secure log-on procedures are in place to control access to systems and applications.',
    implementation: 'Password complexity (16+ chars, MFA mandatory). Account lockout after 5 failed attempts. Last logon notification. Idle session timeout (15 minutes). Single Sign-On (SSO) with MFA.',
    testing: 'Brute force testing. Verify session timeouts. Check for shared account usage.',
    priority: 'Critical',
    applicableSystems: ['Windows', 'Linux', 'Applications', 'Cloud'],
    complianceMappings: { 'NIST': 'PR.AC-7', 'CIS': '16.2', 'PCI DSS': '8.2' }
  },
  {
    id: 'iso-3',
    controlNumber: 'A.12.3.1',
    framework: 'ISO 27001',
    category: 'Operations Security',
    name: 'Information Backup',
    description: 'Backup copies of information, software and system images are taken and tested regularly.',
    implementation: '3-2-1 backup strategy (3 copies, 2 media, 1 offsite). Encrypted backups. Immutable backup storage (WORM). Recovery tested monthly. Separate backup admin accounts.',
    testing: 'Restore random files monthly. Ransomware simulation to test backup integrity. Check backup encryption.',
    priority: 'High',
    applicableSystems: ['All'],
    complianceMappings: { 'NIST': 'PR.IP-4', 'CIS': '11.1', 'SOC 2': 'A1.2' }
  },
  {
    id: 'iso-4',
    controlNumber: 'A.13.1.1',
    framework: 'ISO 27001',
    category: 'Network Security',
    name: 'Network Controls',
    description: 'Networks and network services are secured to prevent unauthorized access.',
    implementation: 'Network segmentation (VLANs, micro-segmentation). Firewall rules deny-by-default. IDS/IPS on perimeter and critical segments. Network Access Control (NAC) for device authentication.',
    testing: 'Penetration testing of network segments. Verify firewall rule effectiveness. Scanner detection testing.',
    priority: 'Critical',
    applicableSystems: ['Network', 'Cloud'],
    complianceMappings: { 'NIST': 'PR.AC-5', 'CIS': '12.1', 'PCI DSS': '1.1' }
  },

  // CIS CONTROLS (Center for Internet Security)
  {
    id: 'cis-1',
    controlNumber: 'CIS 1',
    framework: 'CIS Controls',
    category: 'Inventory and Control',
    name: 'Inventory and Control of Enterprise Assets',
    description: 'Actively manage all hardware devices so only authorized devices access the network.',
    implementation: 'Automated asset discovery and inventory ( Lansweeper/Rapid7). DHCP logging with MAC address filtering. NAC deployment. Guest network isolation. BYOD policy enforcement.',
    testing: 'Connect unauthorized device and verify detection within 1 hour. Review asset inventory accuracy.',
    priority: 'Critical',
    applicableSystems: ['Network', 'Endpoint'],
    complianceMappings: { 'NIST': 'ID.AM-1', 'ISO 27001': 'A.8.1.1', 'PCI DSS': '2.4' }
  },
  {
    id: 'cis-2',
    controlNumber: 'CIS 2',
    framework: 'CIS Controls',
    category: 'Inventory and Control',
    name: 'Inventory and Control of Software Assets',
    description: 'Actively manage all software so only authorized software runs on systems.',
    implementation: 'Application whitelisting (AppLocker, WDAC, or Carbon Black). Software inventory tools. App store vetting process. Unauthorized software removal procedures.',
    testing: 'Attempt to execute unauthorized binary and verify blocking. Check software inventory completeness.',
    priority: 'Critical',
    applicableSystems: ['Windows', 'Linux', 'macOS'],
    complianceMappings: { 'NIST': 'ID.AM-2', 'ISO 27001': 'A.8.1.1', 'PCI DSS': '2.4' }
  },
  {
    id: 'cis-3',
    controlNumber: 'CIS 3',
    framework: 'CIS Controls',
    category: 'Data Protection',
    name: 'Data Protection',
    description: 'Establish processes to secure data-at-rest and data-in-transit.',
    implementation: 'Data classification (Public, Internal, Confidential, Restricted). DLP (Digital Guardian, Symantec DLP). Database activity monitoring (DAM). Secure file transfer (SFTP/SCP only).',
    testing: 'Attempt to exfiltrate sensitive data via email/web and verify blocking. Verify database encryption.',
    priority: 'Critical',
    applicableSystems: ['Database', 'Endpoint', 'Cloud', 'Network'],
    complianceMappings: { 'NIST': 'PR.DS-1/2', 'ISO 27001': 'A.10.1', 'GDPR': 'Article 32' }
  },
  {
    id: 'cis-4',
    controlNumber: 'CIS 4',
    framework: 'CIS Controls',
    category: 'Secure Configuration',
    name: 'Secure Configuration of Enterprise Assets and Software',
    description: 'Establish and maintain secure configuration of end-user devices and servers.',
    implementation: 'CIS Benchmarks implementation via GPO (Windows), Chef/Ansible (Linux), or MDM (macOS/iOS). Configuration drift detection (Tripwire, Puppet). Quarterly baseline reviews.',
    testing: 'CIS-CAT or similar scanning tools monthly. Remediation within 30 days of drift detection.',
    priority: 'High',
    applicableSystems: ['Windows', 'Linux', 'macOS', 'Network'],
    complianceMappings: { 'NIST': 'PR.IP-1', 'ISO 27001': 'A.12.1.2', 'PCI DSS': '2.2' }
  },
  {
    id: 'cis-5',
    controlNumber: 'CIS 5',
    framework: 'CIS Controls',
    category: 'Account Management',
    name: 'Account Management',
    description: 'Manage security and lifecycle of network accounts, local accounts, and privileged accounts.',
    implementation: 'Privileged Access Management (CyberArk, Delinea). Just-in-time (JIT) access. Service account governance. Local admin password solution (LAPS). Quarterly access reviews.',
    testing: 'Review privileged account usage logs. Verify service account passwords rotated every 90 days.',
    priority: 'Critical',
    applicableSystems: ['Windows', 'Linux', 'Cloud', 'Applications'],
    complianceMappings: { 'NIST': 'PR.AC-1', 'ISO 27001': 'A.9.2', 'PCI DSS': '7.1/8.1' }
  },
  {
    id: 'cis-6',
    controlNumber: 'CIS 6',
    framework: 'CIS Controls',
    category: 'Access Control',
    name: 'Access Control Management',
    description: 'Control access to critical assets using authentication and authorization.',
    implementation: 'Multi-factor authentication (MFA) everywhere (Conditional Access). Privileged access workstations (PAW). Password manager enterprise (1Password, LastPass). No default passwords.',
    testing: 'Verify MFA enforcement for all admin access. Check for default credentials using scanners.',
    priority: 'Critical',
    applicableSystems: ['All'],
    complianceMappings: { 'NIST': 'PR.AC-1/7', 'ISO 27001': 'A.9.4', 'PCI DSS': '8.3' }
  },
  {
    id: 'cis-7',
    controlNumber: 'CIS 7',
    framework: 'CIS Controls',
    category: 'Continuous Vulnerability Management',
    name: 'Continuous Vulnerability Management',
    description: 'Develop and maintain a plan to continuously assess and track vulnerabilities.',
    implementation: 'Vulnerability scanning (Qualys, Tenable, Rapid7) weekly. Patch management (SCCM, WSUS, Intune) with SLA (Critical: 24hrs, High: 7 days). Threat intelligence integration.',
    testing: 'Scan for known vulnerabilities and verify remediation SLA compliance. Emergency patch drill quarterly.',
    priority: 'High',
    applicableSystems: ['All'],
    complianceMappings: { 'NIST': 'ID.RA-1', 'ISO 27001': 'A.12.6.1', 'PCI DSS': '6.1' }
  },
  {
    id: 'cis-8',
    controlNumber: 'CIS 8',
    framework: 'CIS Controls',
    category: 'Audit Log Management',
    name: 'Audit Log Management',
    description: 'Collect, alert, and review audit logs to detect suspicious activity.',
    implementation: 'Centralized logging (SIEM) with 1 year retention. Critical system logging (authentication, privilege escalation, data access). Log integrity protection (WORM storage).',
    testing: 'Log injection testing. Verify log completeness (no gaps). Test alert generation for critical events.',
    priority: 'High',
    applicableSystems: ['All'],
    complianceMappings: { 'NIST': 'DE.AE-3', 'ISO 27001': 'A.12.4', 'PCI DSS': '10.1' }
  },

  // PCI DSS CONTROLS
  {
    id: 'pci-1',
    controlNumber: 'PCI DSS 1.1',
    framework: 'PCI DSS',
    category: 'Network Security',
    name: 'Install and Maintain a Firewall',
    description: 'Implement and maintain a firewall configuration to protect cardholder data.',
    implementation: 'Hardware firewalls at network perimeter. Host-based firewalls on endpoints. DMZ for public-facing systems. Firewall rule review every 6 months. Deny all by default.',
    testing: 'Quarterly firewall rule review. Penetration testing of firewall bypass attempts.',
    priority: 'Critical',
    applicableSystems: ['Network', 'CDE'],
    complianceMappings: { 'NIST': 'PR.AC-5', 'CIS': '12.1', 'ISO 27001': 'A.13.1.1' }
  },
  {
    id: 'pci-2',
    controlNumber: 'PCI DSS 2.1',
    framework: 'PCI DSS',
    category: 'System Security',
    name: 'Change Vendor-Supplied Defaults',
    description: 'Change vendor-supplied defaults and remove unnecessary default accounts.',
    implementation: 'Change default passwords before deploying systems. Remove default SNMP strings. Disable unnecessary default accounts (guest, admin). Automated scanning for default configs.',
    testing: 'Scan for default passwords quarterly. Verify no default accounts exist on production systems.',
    priority: 'Critical',
    applicableSystems: ['All'],
    complianceMappings: { 'NIST': 'PR.IP-1', 'CIS': '5.1', 'ISO 27001': 'A.12.5.1' }
  },
  {
    id: 'pci-3',
    controlNumber: 'PCI DSS 3.4',
    framework: 'PCI DSS',
    category: 'Data Protection',
    name: 'Render PAN Unreadable',
    description: 'Render Primary Account Numbers (PAN) unreadable anywhere it is stored.',
    implementation: 'Strong cryptography (AES-256) for stored PAN. Tokenization for primary systems. No storage of CVV/CVC. Key management procedures. HSM for key storage.',
    testing: 'Database scanning for unencrypted PAN. File system scans for cardholder data. Verify truncation/masking.',
    priority: 'Critical',
    applicableSystems: ['Database', 'Applications', 'Logs'],
    complianceMappings: { 'NIST': 'PR.DS-1', 'ISO 27001': 'A.10.1.2', 'CIS': '16.10' }
  },
  {
    id: 'pci-4',
    controlNumber: 'PCI DSS 8.3',
    framework: 'PCI DSS',
    category: 'Access Control',
    name: 'Multi-Factor Authentication',
    description: 'Implement multi-factor authentication for all remote access and administrative access to the CDE.',
    implementation: 'MFA for VPN, CDE access, and all admin interfaces. Hardware tokens or push notifications preferred. SMS as fallback only. Biometric + token for high-risk.',
    testing: 'Attempt login without MFA and verify blocking. Review MFA enrollment rates.',
    priority: 'Critical',
    applicableSystems: ['CDE', 'Network', 'Cloud'],
    complianceMappings: { 'NIST': 'PR.AC-7', 'CIS': '6.2', 'ISO 27001': 'A.9.4.2' }
  },

  // SOC 2 TRUST SERVICES CRITERIA
  {
    id: 'soc-1',
    controlNumber: 'CC6.1',
    framework: 'SOC 2',
    category: 'Security',
    name: 'Logical Access Security',
    description: 'Logical access security measures are implemented to protect against threats.',
    implementation: 'Role-based access control (RBAC) with quarterly reviews. Automated provisioning/de-provisioning (Okta/Azure AD). Emergency access procedures (break-glass accounts).',
    testing: 'Review terminated employee access revocation within 24 hours. Verify orphan account detection.',
    priority: 'High',
    applicableSystems: ['All'],
    complianceMappings: { 'NIST': 'PR.AC-1', 'ISO 27001': 'A.9.1', 'PCI DSS': '7.1' }
  },
  {
    id: 'soc-2',
    controlNumber: 'CC6.6',
    framework: 'SOC 2',
    category: 'Security',
    name: 'Security Infrastructure and Software',
    description: 'Security infrastructure and software are implemented to protect information assets.',
    implementation: 'EDR on all endpoints. Email security gateway (Proofpoint, Mimecast). Web proxy with malware protection. Intrusion detection/prevention systems.',
    testing: 'Malware simulation testing. Phishing simulation results review. Verify EDR coverage 100%.',
    priority: 'High',
    applicableSystems: ['Endpoint', 'Network', 'Email'],
    complianceMappings: { 'NIST': 'PR.PT-1', 'ISO 27001': 'A.12.2', 'CIS': '8.1' }
  },
  {
    id: 'soc-3',
    controlNumber: 'CC7.2',
    framework: 'SOC 2',
    category: 'Monitoring',
    name: 'System Monitoring',
    description: 'System monitoring is implemented to detect potential security breaches.',
    implementation: 'SIEM correlation rules for attack patterns. 24/7 SOC monitoring or MDR. Automated alerting (PagerDuty/ServiceNow integration). Threat hunting program.',
    testing: 'Red team exercise and measure detection time. Review alert quality (false positive rate).',
    priority: 'High',
    applicableSystems: ['All'],
    complianceMappings: { 'NIST': 'DE.AE-1', 'ISO 27001': 'A.12.4', 'CIS': '8.1' }
  },

  // CLOUD SECURITY (CSA CCM)
  {
    id: 'cloud-1',
    controlNumber: 'CCM AIS-01',
    framework: 'CSA CCM',
    category: 'Application Security',
    name: 'Application Security Lifecycle',
    description: 'Implement secure software development lifecycle (SDLC) for cloud applications.',
    implementation: 'SAST/DAST integration in CI/CD (SonarQube, Checkmarx). Dependency scanning (Snyk, OWASP Dependency-Check). Secure coding training for developers. Code review mandatory for production.',
    testing: 'Review security gates in deployment pipeline. Check for unpatched dependencies in production apps.',
    priority: 'High',
    applicableSystems: ['Cloud', 'Applications', 'SaaS'],
    complianceMappings: { 'NIST': 'PR.IP-2', 'ISO 27001': 'A.14.2', 'CIS': '18.1' }
  },
  {
    id: 'cloud-2',
    controlNumber: 'CCM CCC-01',
    framework: 'CSA CCM',
    category: 'Cloud Controls',
    name: 'Cloud Asset Management',
    description: 'Maintain inventory of cloud assets with security classification.',
    implementation: 'CSPM (Prisma Cloud, Microsoft Defender for Cloud) for multi-cloud asset inventory. Tagging strategy (Owner, Data Classification, Environment). Cloud resource lock policies.',
    testing: 'Verify all cloud resources tagged appropriately. Check for unapproved cloud services (shadow IT).',
    priority: 'High',
    applicableSystems: ['AWS', 'Azure', 'GCP'],
    complianceMappings: { 'NIST': 'ID.AM-1', 'CIS': '3.1', 'ISO 27001': 'A.8.1.1' }
  },
  {
    id: 'cloud-3',
    controlNumber: 'CCM DSI-01',
    framework: 'CSA CCM',
    category: 'Data Security',
    name: 'Data Encryption and Key Management',
    description: 'Implement encryption and key management for cloud data.',
    implementation: 'Cloud KMS for customer-managed keys (CMK). Automatic encryption at rest (S3, Azure Storage, Cloud Storage). TLS 1.2+ mandatory in transit. Key rotation every 90 days.',
    testing: 'Verify no unencrypted storage buckets. Check key rotation compliance. Test key revocation procedures.',
    priority: 'Critical',
    applicableSystems: ['Cloud', 'SaaS'],
    complianceMappings: { 'NIST': 'PR.DS-1', 'ISO 27001': 'A.10.1', 'PCI DSS': '3.4' }
  },
  {
    id: 'cloud-4',
    controlNumber: 'CCM IAM-01',
    framework: 'CSA CCM',
    category: 'Identity Management',
    name: 'Identity and Access Management',
    description: 'Implement secure identity and access management for cloud resources.',
    implementation: 'Cloud IAM with least privilege. No long-term access keys (use IAM roles). MFA enforcement for cloud console. Service account governance. PIM/PAM for privileged cloud access.',
    testing: 'Review IAM policies for over-permissions. Check for exposed access keys. Verify MFA on root/admin accounts.',
    priority: 'Critical',
    applicableSystems: ['AWS', 'Azure', 'GCP'],
    complianceMappings: { 'NIST': 'PR.AC-1', 'CIS': '6.1', 'ISO 27001': 'A.9.2' }
  },
  {
    id: 'cloud-5',
    controlNumber: 'CCM IVS-01',
    framework: 'CSA CCM',
    category: 'Infrastructure Security',
    name: 'Infrastructure and Virtualization Security',
    description: 'Secure cloud infrastructure and virtualization layers.',
    implementation: 'Container security (image scanning, runtime protection). Kubernetes RBAC and network policies. VM hardening (CIS benchmarks). Serverless function permissions (least privilege).',
    testing: 'Container image vulnerability scanning. Kubernetes penetration testing. Verify pod-to-pod segmentation.',
    priority: 'High',
    applicableSystems: ['Cloud', 'Kubernetes', 'Containers'],
    complianceMappings: { 'NIST': 'PR.IP-1', 'CIS': '5.1', 'ISO 27001': 'A.12.1' }
  },

  // GDPR TECHNICAL CONTROLS
  {
    id: 'gdpr-1',
    controlNumber: 'GDPR Art.32',
    framework: 'GDPR',
    category: 'Data Protection',
    name: 'Security of Processing',
    description: 'Implement appropriate technical and organizational measures to ensure security of personal data.',
    implementation: 'Encryption (at rest and transit). Pseudonymization capabilities. Resilience testing (backup/restore). Regular testing of technical measures (penetration testing).',
    testing: 'Penetration testing annually. Resilience testing (ransomware simulation). Privacy impact assessments (PIA/DPIA).',
    priority: 'Critical',
    applicableSystems: ['All'],
    complianceMappings: { 'ISO 27001': 'A.12.3', 'NIST': 'PR.DS-1', 'CIS': '3.1' }
  },
  {
    id: 'gdpr-2',
    controlNumber: 'GDPR Art.25',
    framework: 'GDPR',
    category: 'Privacy by Design',
    name: 'Data Protection by Design and Default',
    description: 'Implement data protection principles in processing activities by design and default.',
    implementation: 'Privacy Impact Assessments (PIA) for new systems. Data minimization configurations. Default opt-out for data sharing. Anonymization for analytics.',
    testing: 'Review system configurations for privacy settings. Verify data minimization in production databases.',
    priority: 'High',
    applicableSystems: ['Applications', 'Database'],
    complianceMappings: { 'ISO 27001': 'A.12.1', 'NIST': 'PR.IP-2', 'SOC 2': 'P1.1' }
  }
];

const frameworks = [
  { id: 'nist-csf', name: 'NIST CSF', icon: Shield, color: 'text-blue-400', count: 10 },
  { id: 'iso-27001', name: 'ISO 27001', icon: Lock, color: 'text-green-400', count: 4 },
  { id: 'cis-controls', name: 'CIS Controls', icon: Terminal, color: 'text-cyan-400', count: 8 },
  { id: 'pci-dss', name: 'PCI DSS', icon: CreditCard, color: 'text-red-400', count: 4 },
  { id: 'soc-2', name: 'SOC 2', icon: CheckCircle, color: 'text-purple-400', count: 3 },
  { id: 'csa-ccm', name: 'CSA CCM', icon: Cloud, color: 'text-orange-400', count: 5 },
  { id: 'gdpr', name: 'GDPR', icon: Globe, color: 'text-indigo-400', count: 2 }
];

// Fix missing import
import { CreditCard } from 'lucide-react';

export default function Benchmarks() {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null);
  const [selectedControl, setSelectedControl] = useState<SecurityControl | null>(null);
  const [copySuccess, setCopySuccess] = useState<string | null>(null);

  const filteredControls = securityControls.filter((control) => {
    const matchesSearch = control.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         control.controlNumber.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         control.description.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesFramework = !selectedFramework || control.framework.toLowerCase().replace(/\s+/g, '-') === selectedFramework;
    return matchesSearch && matchesFramework;
  });

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopySuccess(field);
    setTimeout(() => setCopySuccess(null), 2000);
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'Critical': return 'text-red-400 bg-red-400/10';
      case 'High': return 'text-orange-400 bg-orange-400/10';
      case 'Medium': return 'text-yellow-400 bg-yellow-400/10';
      case 'Low': return 'text-green-400 bg-green-400/10';
      default: return 'text-gray-400 bg-gray-400/10';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Security Controls Reference</h2>
          <p className="text-gray-400 mt-1">Comprehensive cybersecurity benchmarks and implementation guides</p>
        </div>
        <a
          href="https://csrc.nist.gov/publications/detail/white-paper/2018/04/16/cybersecurity-framework-v1-1/final"
          target="_blank"
          rel="noopener noreferrer"
          className="btn-secondary flex items-center gap-2"
        >
          <ExternalLink className="w-4 h-4" />
          Framework Resources
        </a>
      </div>

      {/* Frameworks Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
        {frameworks.map((framework) => {
          const Icon = framework.icon;
          return (
            <button
              key={framework.id}
              onClick={() => setSelectedFramework(selectedFramework === framework.id ? null : framework.id)}
              className={`glass-card p-4 text-left transition-all hover:bg-white/5 ${
                selectedFramework === framework.id ? 'ring-2 ring-cyan-400' : ''
              }`}
            >
              <Icon className={`w-6 h-6 ${framework.color} mb-2`} />
              <p className="text-xs font-medium">{framework.name}</p>
              <p className="text-xs text-gray-500 mt-1">{framework.count} controls</p>
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
            placeholder="Search controls by ID, name, or description..."
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

      {/* Controls Table */}
      <div className="glass-card overflow-hidden">
        <table className="data-table">
          <thead>
            <tr>
              <th>Control ID</th>
              <th>Framework</th>
              <th>Control Name</th>
              <th>Category</th>
              <th>Priority</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {filteredControls.map((control) => (
              <tr key={control.id}>
                <td>
                  <span className="font-mono text-cyan-400">{control.controlNumber}</span>
                </td>
                <td className="text-sm">{control.framework}</td>
                <td className="font-medium">{control.name}</td>
                <td className="text-sm text-gray-400">{control.category}</td>
                <td>
                  <span className={`badge ${getPriorityColor(control.priority)}`}>
                    {control.priority}
                  </span>
                </td>
                <td>
                  <button
                    onClick={() => setSelectedControl(control)}
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

      {/* Control Detail Modal */}
      {selectedControl && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="glass-card w-full max-w-3xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between p-6 border-b border-white/5">
              <div>
                <div className="flex items-center gap-3 mb-2">
                  <span className="font-mono text-cyan-400 text-lg">{selectedControl.controlNumber}</span>
                  <span className="badge badge-info">{selectedControl.framework}</span>
                  <span className={`badge ${getPriorityColor(selectedControl.priority)}`}>
                    {selectedControl.priority}
                  </span>
                </div>
                <h3 className="text-xl font-bold">{selectedControl.name}</h3>
              </div>
              <button
                onClick={() => setSelectedControl(null)}
                className="text-gray-400 hover:text-white"
              >
                <span className="sr-only">Close</span>
                <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <div className="p-6 space-y-6">
              {/* Description */}
              <div>
                <h4 className="font-semibold mb-2 flex items-center gap-2">
                  <Info className="w-4 h-4 text-cyan-400" />
                  Description
                </h4>
                <p className="text-gray-300">{selectedControl.description}</p>
              </div>

              {/* Implementation */}
              <div className="bg-white/5 rounded-lg p-4 border border-white/5">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="font-semibold flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-green-400" />
                    Implementation Guidance
                  </h4>
                  <button
                    onClick={() => copyToClipboard(selectedControl.implementation, 'implementation')}
                    className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                  >
                    <Clipboard className="w-3 h-3" />
                    {copySuccess === 'implementation' ? 'Copied!' : 'Copy'}
                  </button>
                </div>
                <p className="text-sm text-gray-300 leading-relaxed">{selectedControl.implementation}</p>
              </div>

              {/* Testing */}
              <div className="bg-white/5 rounded-lg p-4 border border-white/5">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="font-semibold flex items-center gap-2">
                    <CheckCircle className="w-4 h-4 text-yellow-400" />
                    Testing & Validation
                  </h4>
                  <button
                    onClick={() => copyToClipboard(selectedControl.testing, 'testing')}
                    className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                  >
                    <Clipboard className="w-3 h-3" />
                    {copySuccess === 'testing' ? 'Copied!' : 'Copy'}
                  </button>
                </div>
                <p className="text-sm text-gray-300 leading-relaxed">{selectedControl.testing}</p>
              </div>

              {/* Applicable Systems */}
              <div>
                <h4 className="font-semibold mb-2 flex items-center gap-2">
                  <Server className="w-4 h-4 text-purple-400" />
                  Applicable Systems
                </h4>
                <div className="flex gap-2 flex-wrap">
                  {selectedControl.applicableSystems.map((system) => (
                    <span key={system} className="badge badge-info text-xs">
                      {system}
                    </span>
                  ))}
                </div>
              </div>

              {/* Compliance Mappings */}
              <div>
                <h4 className="font-semibold mb-2 flex items-center gap-2">
                  <FileText className="w-4 h-4 text-orange-400" />
                  Cross-Framework Mappings
                </h4>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {Object.entries(selectedControl.complianceMappings).map(([framework, control]) => (
                    <div key={framework} className="bg-white/5 rounded p-2 border border-white/5">
                      <p className="text-xs text-gray-500">{framework}</p>
                      <p className="text-sm font-mono text-cyan-400">{control}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Control Number Copy */}
              <div className="flex items-center justify-between p-3 bg-cyan-900/20 rounded-lg border border-cyan-500/20">
                <div>
                  <p className="text-xs text-gray-400">Control Reference Number</p>
                  <p className="font-mono text-cyan-400">{selectedControl.controlNumber}</p>
                </div>
                <button
                  onClick={() => copyToClipboard(selectedControl.controlNumber, 'number')}
                  className="btn-secondary text-sm flex items-center gap-2"
                >
                  <Clipboard className="w-4 h-4" />
                  {copySuccess === 'number' ? 'Copied!' : 'Copy Control ID'}
                </button>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 p-6 border-t border-white/5">
              <button
                onClick={() => setSelectedControl(null)}
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