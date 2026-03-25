#example from lab

#!/usr/bin/env python3
import pandas as pd
from datetime import datetime, timedelta
import json

def parse_logs(log_file):
    df = pd.read_csv(log_file)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df

def detect_brute_force(df, time_window=120, threshold=5, whitelist=None):
    """
    Args:
        df: DataFrame with parsed log events (given by previous function)
        time_window: Time window in seconds
        threshold: Minimum failed attempts to trigger alert
        whitelist: List of IPs to exclude from alerting
        
    Returns:
        List of alert dictionaries
    """
    
    if whitelist is None: #null check
        whitelist = []
    
    alerts = []
    
    failed_logins = df[
        (df['event_type'] == 'failed_login') & 
        (df['service'] == 'ssh')
    ].copy()
    
    if len(failed_logins) == 0:
        return alerts
    
    failed_logins = failed_logins.sort_values('timestamp')
    
    for source_ip, group in failed_logins.groupby('source_ip'):
        if source_ip in whitelist:
            continue

        events = group.sort_values('timestamp').to_dict('records')
        
        for i in range(len(events)):
            window_start = events[i]['timestamp']
            window_end = window_start + timedelta(seconds=time_window)
            
            events_in_window = [
                e for e in events[i:] 
                if e['timestamp'] <= window_end
            ]
            
            if len(events_in_window) >= threshold:
                alert = {
                    'alert_id': f"BF-{datetime.now().strftime('%Y%m%d%H%M%S')}-{source_ip.replace('.', '')}",
                    'alert_type': 'Brute Force Detected',
                    'severity': 'HIGH',
                    'source_ip': source_ip,
                    'timestamp': datetime.now().isoformat(),
                    'detection_window_start': window_start.isoformat(),
                    'detection_window_end': window_end.isoformat(),
                    'event_count': len(events_in_window),
                    'evidence': [e['timestamp'].isoformat() for e in events_in_window],
                    'usernames_targeted': list(set([e['username'] for e in events_in_window])),
                    'service': 'ssh'
                }
                alerts.append(alert)
                
                break
    
    return alerts

def calculate_alert_fidelity(alerts, known_attackers, known_legitimate):
    """
    Args:
        alerts: List of generated alerts
        known_attackers: List of actual attacker IPs
        known_legitimate: List of legitimate IPs that triggered alerts
        
    Returns:
        Dictionary with fidelity metrics
    """
    
    alerted_ips = [a['source_ip'] for a in alerts]
    
    true_positives = len([ip for ip in alerted_ips if ip in known_attackers])
    false_positives = len([ip for ip in alerted_ips if ip in known_legitimate])
    
    total_alerts = len(alerts)
    
    fidelity = {
        'total_alerts': total_alerts,
        'true_positives': true_positives,
        'false_positives': false_positives,
        'accuracy': (true_positives / total_alerts * 100) if total_alerts > 0 else 0,
        'false_positive_rate': (false_positives / total_alerts * 100) if total_alerts > 0 else 0
    }
    
    return fidelity

def save_alerts(alerts, output_file):
    with open(output_file, 'w') as f:
        json.dump(alerts, f, indent=2)
    print(f"[+] Alerts saved to {output_file}")

def display_alerts(alerts):
    if not alerts:
        print("\n[!] No alerts generated")
        return
    
    print("\n" + "="*60)
    print("GENERATED ALERTS")
    print("="*60)
    
    for i, alert in enumerate(alerts, 1):
        print(f"\nAlert #{i}")
        print(f"  ID: {alert['alert_id']}")
        print(f"  Type: {alert['alert_type']}")
        print(f"  Severity: {alert['severity']}")
        print(f"  Source IP: {alert['source_ip']}")
        print(f"  Event Count: {alert['event_count']}")
        print(f"  Usernames Targeted: {', '.join(alert['usernames_targeted'])}")
        print(f"  Detection Window: {alert['detection_window_start']} to {alert['detection_window_end']}")
        print(f"  Evidence (first 3 timestamps):")
        for ts in alert['evidence'][:3]:
            print(f"    - {ts}")

def display_fidelity(fidelity):
    """Display alert fidelity metrics"""
    print("\n" + "="*60)
    print("ALERT FIDELITY ANALYSIS")
    print("="*60)
    print(f"\nTotal Alerts: {fidelity['total_alerts']}")
    print(f"True Positives: {fidelity['true_positives']}")
    print(f"False Positives: {fidelity['false_positives']}")
    print(f"Accuracy: {fidelity['accuracy']:.1f}%")
    print(f"False Positive Rate: {fidelity['false_positive_rate']:.1f}%")

if __name__ == "__main__":
    print("="*60)
    print("SIEM CORRELATION ENGINE - SOLUTION")
    print("="*60)
    
    print("\n[+] Loading log data...")
    df = parse_logs('/lab4/data/sample_logs.csv')
    print(f"[+] Loaded {len(df)} events")
    
    print("\n[+] Running brute force detection (no whitelist)...")
    alerts_no_whitelist = detect_brute_force(df, time_window=120, threshold=5)
    display_alerts(alerts_no_whitelist)
    
    # Calculate fidelity (10.0.0.5 is monitoring server, should be false positive)
    known_attackers = ['192.168.1.100']
    known_legitimate = ['10.0.0.5']
    
    fidelity_before = calculate_alert_fidelity(
        alerts_no_whitelist, 
        known_attackers, 
        known_legitimate
    )
    display_fidelity(fidelity_before)
    
    print("\n" + "="*60)
    print("APPLYING WHITELIST (10.0.0.5 - monitoring server)")
    print("="*60)
    
    whitelist = ['10.0.0.5']
    alerts_with_whitelist = detect_brute_force(
        df, 
        time_window=120, 
        threshold=5, 
        whitelist=whitelist
    )
    
    display_alerts(alerts_with_whitelist)
    
    fidelity_after = calculate_alert_fidelity(
        alerts_with_whitelist, 
        known_attackers, 
        known_legitimate
    )
    display_fidelity(fidelity_after)
    
    save_alerts(alerts_with_whitelist, 'alerts.json')

    
    print("\n2. ALERT FIDELITY:")
    print(f"   - Before whitelist: {fidelity_before['accuracy']:.1f}% accuracy")
    print(f"   - After whitelist: {fidelity_after['accuracy']:.1f}% accuracy")

