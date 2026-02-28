# Mini-SIEM-Analyzer
Python-based log analyzer that detects SSH brute force attacks. Analyzed 86,839 real log lines, found 352 brute force attacks from 1,260 unique IPs.

A Python-based log analysis tool that simulates core SIEM 
functionality — built as a SOC L1 portfolio project.

## 🎯 What It Does
- Parses real SSH authentication logs (auth.log)
- Detects brute force attacks (5+ failed logins from same IP)
- Identifies suspicious IPs that failed then succeeded
- Shows Top 10 attacking IPs
- Exports all findings to CSV report

## 📊 Results on Real Data
| Finding | Count |
|---|---|
| Log lines analyzed | 86,839 |
| Security events detected | 12,223 |
| Unique attacker IPs | 1,260 |
| Brute force alerts triggered | 352 |

## 🚀 How to Run
```bash
python siem_analyzer.py
```

## 📋 Sample Output
```
⚠️  ALERT: Possible Brute Force Attack
│  IP Address     : 220.99.93.50
│  Failed Attempts: 409
│  Usernames Tried: admin, root, guest, oracle
│  First Seen     : Dec 2 05:19:56
│  Last Seen      : Dec 2 08:53:03
```

## 🧠 Skills Demonstrated
- Log analysis and parsing
- Regex for IP and username extraction
- Brute force detection logic
- Python file handling
- CSV report generation
- Real SSH auth.log analysis

## 🛠 Tools Used
- Python 3.12
- Built-in libraries only (re, csv, datetime, collections)

## 📥 Log Source
Real SSH honeypot logs from secrepo.com (86,839 lines)
