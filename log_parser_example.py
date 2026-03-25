#example from lab

#!/usr/bin/env python3
import re
import json
from collections import Counter
import matplotlib.pyplot as plt

"""
template of parsing logs:
def parse_<INSERT TYPE>_log(file_path):
    pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+).*<INSERT REGEX>' 
    events = []

    with open(file_path, 'r', errors='ignore') as f:
        for line in f:
            match = re.search(pattern, line) #include re.IGNORECASE if case-insensitive desired
            if match:
                events.append({
                    'timestamp': match.group(1),
                    'event_type': '<INSERT TYPE>'
                    <INSERT ANY OTHER IMPORTANT JSON DATA>
                })
    with open('<INSERT TYPE>.json', 'w') as f:
         json.dump(events, f, indent=2)
    return events
"""

def parse_auth_log(file_path):
    pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password.*from\s+([0-9.]+)' #failed SSH login attempts
    events = []

    with open(file_path, 'r', errors='ignore') as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                events.append({
                    'timestamp': match.group(1),
                    'source_ip': match.group(2),
                    'event_type': 'failed_login'
                })
    with open('auth_events.json', 'w') as f:
         json.dump(events, f, indent=2)
    return events

def parse_syslog(file_path):
    pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+).*?\b(error|failed|critical)\b' #system error/failure messages
    events = []

    with open(file_path, 'r', errors='ignore') as f:
        for line in f:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                events.append({
                    'timestamp': match.group(1),
                    'event_type': 'system_error'
                })
    with open('syslog_events.json', 'w') as f:
         json.dump(events, f, indent=2)
    return events

def validate_logs():
    print("[*] Validating log contents...")
    print("[*] auth_sample.log failed logins:",
          sum(1 for _ in open('auth_sample.log', errors='ignore') if 'Failed password' in _))

def visualise_data(auth_events, syslog_events):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    ip_aggregation = Counter(e['source_ip'] for e in auth_events)

    # Left chart: failed SSH logins by IP
    if ip_aggregation:
        ips, counts = zip(*ip_aggregation.most_common(10))
        ax1.barh(ips, counts, color='#3498db')
        ax1.set_title('Aggregated Failed SSH Logins by Source IP')
        ax1.set_xlabel('Attempts')
        ax1.invert_yaxis()
    else:
        ax1.text(0.5, 0.5, 'No failed logins', ha='center', va='center')
        ax1.set_axis_off()

    # Right chart: comparison of event types
    counts_list = [len(auth_events), len(syslog_events)]
    ax2.bar(
        ['Failed SSH Logins', 'System Errors'],
        counts_list,
        color=['#3498db', '#f39c12']
    )
    ax2.set_ylabel('Count')
    ax2.set_title('Event Volume Comparison')

    # Only set ylim if we have data
    if max(counts_list) > 0:
        ax2.set_ylim(0, max(counts_list) + 1)

    # Annotate bar values
    for i, v in enumerate(counts_list):
        ax2.text(i, v + 0.1, str(v), ha='center')

    plt.tight_layout()
    plt.savefig('log_analysis.png', dpi=150, bbox_inches='tight')
    plt.close(fig)
    print("[+] Visualisation saved as log_analysis.png")


validate_logs()

auth_events = parse_auth_log('auth_sample.log')
syslog_events = parse_syslog('syslog_sample.log')

print(f"[+] Parsed {len(auth_events)} failed SSH logins")
print(f"[+] Parsed {len(syslog_events)} system error events")

visualise_data(auth_events, syslog_events)
