# 🔐 Mini SIEM Log Analyzer

> A Python-based SSH log analysis tool that simulates core **SIEM (Security Information and Event Management)** functionality — built as a **SOC L1 Portfolio Project**. Analyzed **86,839 real log lines**, detected **352 brute force attacks** from **1,260 unique attacker IPs**.

---

## 🎯 What It Does

- 🔍 **Parses real SSH authentication logs** (`auth.log`) from a live honeypot
- 🚨 **Detects brute force attacks** — flags IPs with 5+ failed login attempts
- 🔴 **Identifies compromised accounts** — IPs that failed repeatedly then succeeded
- 📌 **Top 10 attacker IPs** ranked by failed login count
- 💾 **Exports full findings** to a structured CSV report

---

## 📊 Results on Real Data

| Finding | Count |
|---------|-------|
| Log lines analyzed | 86,839 |
| Security events detected | 12,223 |
| Unique attacker IPs | 1,260 |
| Brute force alerts triggered | 352 |

---

## 📁 Project Structure

```
Mini-SIEM-Analyzer/
│
├── siem_analyzer.py       ← Main analyzer script
│
├── logs/
│   └── auth_logs          ← Real SSH honeypot log file
│
└── report.csv             ← Auto-generated output report
```

---

## 🛠️ Tech Stack

| Tool | Purpose |
|------|---------|
| Python 3.12 | Core language |
| `re` | Regex parsing of log lines |
| `csv` | Structured report export |
| `datetime` | Timestamp handling |
| `collections` | defaultdict for IP aggregation |

> ✅ No external libraries required — runs on standard Python 3!

---

## ⚙️ How to Run

**1. Clone the repository**
```bash
git clone https://github.com/YOUR_USERNAME/Mini-SIEM-Analyzer.git
cd Mini-SIEM-Analyzer
```

**2. Make sure the log file is in the right place**
```
logs/auth_logs
```

**3. Run the analyzer**
```bash
python siem_analyzer.py
```

**4. Check your report**
```
report.csv
```

---

## 📋 Sample Output

```
🔐 Starting Mini SIEM Log Analyzer v2.0...
   Timestamp: 2026-02-28 22:54:32

✅ Log file loaded: logs/auth_logs
   Total lines read: 86,839

📋 SUMMARY
   Total Security Events: 12,223
   Failed Logins        : 11,847
   Successful Logins    : 15
   Suspicious DNS Events: 361
   Unique Attacker IPs  : 1,260
   Brute Force Alerts   : 352

🚨 BRUTE FORCE ALERT
  ┌─────────────────────────────────────────
  │  IP Address     : 220.99.93.50
  │  Failed Attempts: 409
  │  Usernames Tried: admin, root, guest, oracle
  │  First Seen     : Dec 2 05:19:56
  │  Last Seen      : Dec 2 08:53:03
  └─────────────────────────────────────────

🔴 HIGH RISK: IPs with FAILURES then SUCCESSES
   🔴 192.168.x.x        312 failures → 1 SUCCESS ← INVESTIGATE!
```

---

## 🔍 Detection Logic

### Brute Force Detection
An IP is flagged as a brute force attacker if it generates **5 or more failed login attempts**. The threshold is configurable via `BRUTE_FORCE_THRESHOLD` in the script.

### Compromised Account Detection
Any IP that has **at least one failed attempt followed by a successful login** is flagged as HIGH RISK and marked for investigation — this pattern strongly suggests a successful intrusion after credential guessing.

### Event Types Parsed

| Log Pattern | Event Type | Status |
|-------------|-----------|--------|
| `Failed password for ...` | Failed Password | FAILED |
| `Invalid user ... from ...` | Invalid User | FAILED |
| `Accepted password for ...` | Accepted Login | SUCCESS |
| `POSSIBLE BREAK-IN ATTEMPT` | Break-In (DNS) | SUSPICIOUS |

---

## 📥 Log Source

Real SSH honeypot logs sourced from **[secrepo.com](http://www.secrepo.com/)** — a public repository of real security data for research and learning.

---

## 🧠 Skills Demonstrated

- SSH log forensics and parsing
- Regex-based IP and username extraction
- Brute force attack pattern recognition
- Compromised account identification
- Python data aggregation with `defaultdict`
- CSV report generation
- Working with real-world security data

---

## 🎯 Use Cases

- SOC L1 analyst log triage simulation
- Brute force attack detection training
- Learning SIEM core concepts hands-on
- Portfolio demonstration for security analyst roles

---

## 👩‍💻 Author

**Swathi V**  
Cybersecurity Enthusiast | SOC L1 Aspirant  

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

---

> ⚠️ **Disclaimer:** The log files used are sourced from a public honeypot dataset intended for educational and research purposes only.
