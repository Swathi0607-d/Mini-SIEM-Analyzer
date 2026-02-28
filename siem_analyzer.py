"""
=============================================================
  🔐 MINI SIEM LOG ANALYZER — v2.0 (Real Log Edition)
  Built for: SOC L1 Portfolio Project
  Description: Analyzes real SSH auth logs to detect brute
               force attacks, suspicious IPs, and intrusions
=============================================================
"""

import re
import csv
import datetime
from collections import defaultdict

# ─────────────────────────────────────────────
# ⚙️  CONFIGURATION
# ─────────────────────────────────────────────
LOG_FILE = "logs/auth_logs"         # Real log from secrepo.com
REPORT_FILE = "report.csv"
BRUTE_FORCE_THRESHOLD = 5
SHOW_TOP_N = 10


# ─────────────────────────────────────────────
# 📂 STEP 1: Read Log File
# ─────────────────────────────────────────────
def read_log_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        print(f"\n✅ Log file loaded: {filepath}")
        print(f"   Total lines read: {len(lines):,}")
        return lines
    except FileNotFoundError:
        print(f"\n❌ ERROR: Log file not found at '{filepath}'")
        return []


# ─────────────────────────────────────────────
# 🔍 STEP 2: Parse Log Lines
# Handles REAL secrepo.com auth log format
# ─────────────────────────────────────────────
def parse_logs(lines):
    events = []

    p_failed  = re.compile(r'Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3})')
    p_invalid = re.compile(r'Invalid user (\S+) from (\d{1,3}(?:\.\d{1,3}){3})')
    p_success = re.compile(r'Accepted password for (\S+) from (\d{1,3}(?:\.\d{1,3}){3})')
    p_breakin = re.compile(r'POSSIBLE BREAK-IN ATTEMPT.*\[(\d{1,3}(?:\.\d{1,3}){3})\]')
    p_time    = re.compile(r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})')

    for line in lines:
        event = {}
        time_match = p_time.match(line)
        event['timestamp'] = time_match.group(1) if time_match else "Unknown"

        m = p_failed.search(line)
        if m:
            event.update({'user': m.group(1), 'ip': m.group(2), 'status': 'FAILED', 'type': 'Failed Password'})
            events.append(event); continue

        m = p_invalid.search(line)
        if m and 'input_userauth_request' not in line:
            event.update({'user': m.group(1), 'ip': m.group(2), 'status': 'FAILED', 'type': 'Invalid User'})
            events.append(event); continue

        m = p_success.search(line)
        if m:
            event.update({'user': m.group(1), 'ip': m.group(2), 'status': 'SUCCESS', 'type': 'Accepted Login'})
            events.append(event); continue

        m = p_breakin.search(line)
        if m:
            event.update({'user': 'unknown', 'ip': m.group(1), 'status': 'SUSPICIOUS', 'type': 'Possible Break-In (DNS)'})
            events.append(event); continue

    return events


# ─────────────────────────────────────────────
# 📊 STEP 3: Analyze Events
# ─────────────────────────────────────────────
def analyze_events(events):
    failed_by_ip      = defaultdict(int)
    failed_users_by_ip= defaultdict(set)
    success_by_ip     = defaultdict(int)
    suspicious_by_ip  = defaultdict(int)
    first_seen        = {}
    last_seen         = {}

    for event in events:
        ip = event.get('ip', 'unknown')
        ts = event.get('timestamp', '')
        if ip not in first_seen:
            first_seen[ip] = ts
        last_seen[ip] = ts

        if event['status'] == 'FAILED':
            failed_by_ip[ip] += 1
            failed_users_by_ip[ip].add(event.get('user', ''))
        elif event['status'] == 'SUCCESS':
            success_by_ip[ip] += 1
        elif event['status'] == 'SUSPICIOUS':
            suspicious_by_ip[ip] += 1

    return failed_by_ip, failed_users_by_ip, success_by_ip, suspicious_by_ip, first_seen, last_seen


# ─────────────────────────────────────────────
# 🚨 STEP 4: Detect Brute Force
# ─────────────────────────────────────────────
def detect_brute_force(failed_by_ip, failed_users_by_ip, first_seen, last_seen):
    alerts = []
    for ip, count in failed_by_ip.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            alerts.append({
                'ip': ip,
                'failed_attempts': count,
                'usernames_tried': ', '.join(list(failed_users_by_ip[ip])[:5]),
                'first_seen': first_seen.get(ip, 'N/A'),
                'last_seen':  last_seen.get(ip, 'N/A'),
            })
    alerts.sort(key=lambda x: x['failed_attempts'], reverse=True)
    return alerts


# ─────────────────────────────────────────────
# 🖨️  STEP 5: Print Report
# ─────────────────────────────────────────────
def print_report(events, failed_by_ip, success_by_ip, suspicious_by_ip, alerts):
    total_failed    = sum(1 for e in events if e['status'] == 'FAILED')
    total_success   = sum(1 for e in events if e['status'] == 'SUCCESS')
    total_suspicious= sum(1 for e in events if e['status'] == 'SUSPICIOUS')
    unique_ips      = len(set(e['ip'] for e in events))

    print("\n" + "="*60)
    print("       🔐 MINI SIEM LOG ANALYZER — REPORT")
    print("="*60)
    print(f"\n📋 SUMMARY")
    print(f"   Total Security Events: {len(events):,}")
    print(f"   Failed Logins        : {total_failed:,}")
    print(f"   Successful Logins    : {total_success:,}")
    print(f"   Suspicious DNS Events: {total_suspicious:,}")
    print(f"   Unique Attacker IPs  : {unique_ips:,}")
    print(f"   Brute Force Alerts   : {len(alerts):,}")

    print(f"\n📌 TOP {SHOW_TOP_N} IPs BY FAILED LOGINS")
    print(f"   {'IP Address':<20} {'Failed Attempts':>15}")
    print(f"   {'-'*20} {'-'*15}")
    top_ips = sorted(failed_by_ip.items(), key=lambda x: x[1], reverse=True)[:SHOW_TOP_N]
    for ip, count in top_ips:
        print(f"   {ip:<20} {count:>15,}")

    if alerts:
        print(f"\n🚨 BRUTE FORCE ALERTS (≥{BRUTE_FORCE_THRESHOLD} failed attempts)")
        print(f"   Showing top 10 of {len(alerts):,} total alerts")
        print("="*60)
        for alert in alerts[:10]:
            print(f"""
  ⚠️  ALERT: Possible Brute Force Attack
  ┌─────────────────────────────────────────
  │  IP Address     : {alert['ip']}
  │  Failed Attempts: {alert['failed_attempts']:,}
  │  Usernames Tried: {alert['usernames_tried']}
  │  First Seen     : {alert['first_seen']}
  │  Last Seen      : {alert['last_seen']}
  └─────────────────────────────────────────""")

    print(f"\n🔴 HIGH RISK: IPs with FAILURES then SUCCESSES")
    compromised = [(ip, failed_by_ip[ip], success_by_ip[ip])
                   for ip in failed_by_ip if success_by_ip.get(ip, 0) > 0]
    compromised.sort(key=lambda x: x[1], reverse=True)
    if compromised:
        for ip, fails, wins in compromised:
            print(f"   🔴 {ip:<20} {fails:>5} failures → {wins} SUCCESS(ES) ← INVESTIGATE!")
    else:
        print("   ✅ None found")

    print("\n" + "="*60)


# ─────────────────────────────────────────────
# 💾 STEP 6: Save CSV Report
# ─────────────────────────────────────────────
def save_csv_report(alerts, failed_by_ip, success_by_ip, suspicious_by_ip, first_seen, last_seen):
    with open(REPORT_FILE, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ['IP Address', 'Failed Attempts', 'Successful Logins',
                      'Suspicious DNS Events', 'Brute Force Alert', 'First Seen', 'Last Seen']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        all_ips = set(list(failed_by_ip) + list(success_by_ip) + list(suspicious_by_ip))
        for ip in all_ips:
            writer.writerow({
                'IP Address': ip,
                'Failed Attempts': failed_by_ip.get(ip, 0),
                'Successful Logins': success_by_ip.get(ip, 0),
                'Suspicious DNS Events': suspicious_by_ip.get(ip, 0),
                'Brute Force Alert': "YES ⚠️" if failed_by_ip.get(ip, 0) >= BRUTE_FORCE_THRESHOLD else "No",
                'First Seen': first_seen.get(ip, 'N/A'),
                'Last Seen':  last_seen.get(ip, 'N/A'),
            })
    print(f"\n💾 CSV report saved → {REPORT_FILE}")


# ─────────────────────────────────────────────
# 🚀 MAIN
# ─────────────────────────────────────────────
def main():
    print("\n🔐 Starting Mini SIEM Log Analyzer v2.0...")
    print(f"   Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    lines = read_log_file(LOG_FILE)
    if not lines: return

    print("\n⚙️  Parsing log lines...")
    events = parse_logs(lines)
    print(f"   Parsed {len(events):,} security events")

    print("\n📊 Analyzing events...")
    failed_by_ip, failed_users_by_ip, success_by_ip, suspicious_by_ip, first_seen, last_seen = analyze_events(events)
    alerts = detect_brute_force(failed_by_ip, failed_users_by_ip, first_seen, last_seen)

    print_report(events, failed_by_ip, success_by_ip, suspicious_by_ip, alerts)
    save_csv_report(alerts, failed_by_ip, success_by_ip, suspicious_by_ip, first_seen, last_seen)

    print("\n✅ Analysis complete!\n")


if __name__ == "__main__":
    main()