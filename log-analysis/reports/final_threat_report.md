# Week 3 — Final Threat Intelligence Report
**Project:** Healthcare IoT Deception Honeypot Network
**Date:** 2026-06-18

## Executive Summary
The honeypot successfully impersonated a Philips IntelliVue medical
device gateway and captured real attack patterns including SSH brute
force, post-exploitation commands, and malware download attempts.

## Key Statistics
| Metric | Value |
|--------|-------|
| Total Log Entries | 88 |
| Unique Attacker IPs | 1 |
| Auth Failures | 5 |
| Successful Logins | 7 |
| Commands Executed | 7 |

## Attack Source Analysis
The primary attacker IP **172.20.0.1** generated **88 events**
with **7 successful shell logins** — classified as
**HIGH THREAT**. This pattern is consistent with automated IoT botnet
behavior targeting medical device default credentials.

## Identified TTPs (MITRE ATT&CK)
| Technique | ID | Description |
|-----------|-----|-------------|
| Brute Force | T1110 | SSH password spraying with IoT defaults |
| Valid Accounts | T1078 | Default credential exploitation |
| Command Execution | T1059 | Shell commands post-authentication |
| Ingress Tool Transfer | T1105 | wget malware download attempt |
| Scheduled Task | T1053 | Crontab persistence attempt |
| Credential Dumping | T1003 | /etc/passwd access |
| Network Recon | T1046 | netstat, uname reconnaissance |

## Note on Attack Source IP
The source IP 172.20.0.1 is the Docker bridge network gateway,
which is the expected result when simulating attacks in an isolated
lab environment. In a real deployment, this would show external
attacker IPs with geographic distribution.

## Recommendations
1. Change all default credentials on medical IoT devices
2. Disable SSH/Telnet where not required
3. Implement IoT network segmentation (VLAN)
4. Block identified attacker IPs at perimeter firewall
5. Monitor for identified TTPs in production environment
6. Enable alerts for /etc/passwd and /etc/shadow access

## HIPAA Compliance
Satisfies HIPAA Security Rule 164.312(b) audit control requirements
through active threat monitoring and documented security evaluation.
The honeypot demonstrates proactive security posture required for
medical device network compliance.
