import json
import sys
from dataclasses import dataclass
from typing import Any, Dict, List
from datetime import datetime

# ----------------------------
# Mock Threat Intel (replace later with Cortex)
# ----------------------------
MALICIOUS_IPS = {"185.100.87.10", "45.67.89.12"}
SUSPICIOUS_IPS = {"203.0.113.50", "103.21.244.0"}  # demo/test IPs ok for coursework

MALICIOUS_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f"  # EICAR test file MD5 (safe demo)
}
SUSPICIOUS_HASHES = set()


# ----------------------------
# Validation
# ----------------------------
def validate_alert(alert: Dict[str, Any]) -> List[str]:
    errors: List[str] = []

    def is_number(x: Any) -> bool:
        # bool is a subclass of int, so exclude it explicitly
        return isinstance(x, (int, float)) and not isinstance(x, bool)

    # failed_logins
    failed = alert.get("failed_logins", 0)
    if not is_number(failed) or failed < 0:
        errors.append("failed_logins must be a number >= 0")

    # traffic_multiplier
    tm = alert.get("traffic_multiplier", 1)
    if not is_number(tm) or tm < 0:
        errors.append("traffic_multiplier must be a number >= 0")

    # phishing_flag
    pf = alert.get("phishing_flag", False)
    if not isinstance(pf, bool):
        errors.append("phishing_flag must be true/false")

    # successful_login
    sl = alert.get("successful_login", False)
    if not isinstance(sl, bool):
        errors.append("successful_login must be true/false")

    # ip
    ip = alert.get("ip")
    if ip is not None and not isinstance(ip, str):
        errors.append("ip must be a string or null")

    # file_hash
    h = alert.get("file_hash")
    if h is not None:
        if not isinstance(h, str):
            errors.append("file_hash must be a string or null")
        else:
            hl = len(h.strip())
            if hl not in (32, 40, 64):  # MD5/SHA1/SHA256 lengths
                errors.append("file_hash should be MD5(32)/SHA1(40)/SHA256(64) length, or null")

    return errors


# ----------------------------
# Mock lookups
# ----------------------------
def ip_to_reputation(ip: str | None) -> str:
    if not ip:
        return "unknown"
    ip = ip.strip()
    if ip in MALICIOUS_IPS:
        return "malicious"
    if ip in SUSPICIOUS_IPS:
        return "suspicious"
    return "unknown"  # IMPORTANT: unknown stays unknown


def hash_to_verdict(file_hash: str | None) -> str:
    if not file_hash:
        return "unknown"
    h = file_hash.strip().lower()
    if h in MALICIOUS_HASHES:
        return "malicious"
    if h in SUSPICIOUS_HASHES:
        return "suspicious"
    return "unknown"


def severity_from_score(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


@dataclass
class Decision:
    category: str
    score: int
    reasons: List[str]


def decide_category(alert: Dict[str, Any]) -> Dict[str, Any]:
    # Inputs (with safe defaults)
    failed_logins = int(alert.get("failed_logins", 0) or 0)
    successful_login = bool(alert.get("successful_login", False))
    ip = alert.get("ip")
    file_hash = alert.get("file_hash")
    traffic_multiplier = float(alert.get("traffic_multiplier", 1) or 1)
    phishing_flag = bool(alert.get("phishing_flag", False))

    # Enrichment (mock)
    ip_rep = ip_to_reputation(ip)
    hash_verdict = hash_to_verdict(file_hash)

    decisions: List[Decision] = []

    # 1) Service Disruption (traffic multiplier only)
    sd_score = 0
    sd_reasons: List[str] = []
    if traffic_multiplier >= 3:
        sd_score = 40
        sd_reasons.append(f"traffic_multiplier >= 3 (got {traffic_multiplier})")
    if traffic_multiplier >= 10:
        sd_score = 70
        sd_reasons.append(f"traffic_multiplier >= 10 (got {traffic_multiplier})")
    if traffic_multiplier >= 20:
        sd_score = 90
        sd_reasons.append(f"traffic_multiplier >= 20 (got {traffic_multiplier})")
    if sd_score > 0:
        decisions.append(Decision("Service Disruption (DDoS/Bot Flooding)", sd_score, sd_reasons))

    # 2) Malware / Host Compromise (based on hash verdict)
    mw_score = 0
    mw_reasons: List[str] = []
    if hash_verdict == "malicious":
        mw_score = 85
        mw_reasons.append("hash_verdict == malicious")
    elif hash_verdict == "suspicious":
        mw_score = 55
        mw_reasons.append("hash_verdict == suspicious")
    if mw_score > 0:
        decisions.append(Decision("Malware / Host Compromise", mw_score, mw_reasons))

    # 3) Account Compromise (successful login + bad/suspicious IP)
    if successful_login and ip_rep in ("malicious", "suspicious"):
        ac_score = 75 if ip_rep == "malicious" else 60
        decisions.append(
            Decision(
                "Account Compromise",
                ac_score,
                ["successful_login == True", f"ip_reputation == {ip_rep}"],
            )
        )

    # 4) Credential Attack (failed login volume + IP rep boosts)
    ca_score = 0
    ca_reasons: List[str] = []
    if failed_logins >= 20:
        ca_score = 40
        ca_reasons.append(f"failed_logins >= 20 (got {failed_logins})")
    if failed_logins >= 50:
        ca_score = 65
        ca_reasons.append(f"failed_logins >= 50 (got {failed_logins})")
    if ca_score > 0:
        if ip_rep == "suspicious":
            ca_score += 10
            ca_reasons.append("ip_reputation == suspicious (boost)")
        elif ip_rep == "malicious":
            ca_score += 20
            ca_reasons.append("ip_reputation == malicious (boost)")
        decisions.append(
            Decision(
                "Credential Attack (SSH Brute Force / Bot Logins)",
                min(ca_score, 95),
                ca_reasons,
            )
        )

    # 5) Phishing / Social Engineering (simple flag)
    if phishing_flag:
        ph_score = 45
        ph_reasons = ["phishing_flag == True"]
        if ip_rep == "malicious":
            ph_score += 15
            ph_reasons.append("ip_reputation == malicious (boost)")
        decisions.append(Decision("Phishing / Social Engineering", min(ph_score, 95), ph_reasons))

    # If nothing matched, label as “Uncategorised / Needs Review”
    if not decisions:
        return {
            "category": "Uncategorised / Needs Review",
            "severity": "Low",
            "score": 0,
            "confidence": 10,
            "ip_reputation": ip_rep,
            "hash_verdict": hash_verdict,
            "reasons": ["No rules matched; requires analyst review"],
            "tags": ["needs-review"],
            "needs_human_review": True,
        }

    # Pick the best score; apply tie-break priority if needed
    priority = {
        "Malware / Host Compromise": 5,
        "Service Disruption (DDoS/Bot Flooding)": 4,
        "Account Compromise": 3,
        "Credential Attack (SSH Brute Force / Bot Logins)": 2,
        "Phishing / Social Engineering": 1,
    }

    decisions.sort(key=lambda d: (d.score, priority.get(d.category, 0)), reverse=True)
    top = decisions[0]
    runner_up_score = decisions[1].score if len(decisions) > 1 else 0

    # Confidence based on how clearly it “wins”
    gap = top.score - runner_up_score
    confidence = 60
    if gap >= 20:
        confidence = 80
    if gap >= 40:
        confidence = 90
    if top.score >= 85:
        confidence = max(confidence, 90)

    severity = severity_from_score(top.score)

    tag_map = {
        "Service Disruption (DDoS/Bot Flooding)": ["service-disruption", "ddos", "availability"],
        "Malware / Host Compromise": ["malware", "host-compromise"],
        "Account Compromise": ["account-compromise", "credential-access"],
        "Credential Attack (SSH Brute Force / Bot Logins)": ["credential-attack", "bruteforce", "ssh"],
        "Phishing / Social Engineering": ["phishing", "social-engineering"],
    }

    return {
        "category": top.category,
        "severity": severity,
        "score": top.score,
        "confidence": confidence,
        "ip_reputation": ip_rep,
        "hash_verdict": hash_verdict,
        "reasons": top.reasons,
        "tags": tag_map.get(top.category, []),
        "needs_human_review": confidence < 80,  # SOC-style guardrail
    }


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python categorisation.py <alert.json>")
        return 2

    input_path = sys.argv[1]

    try:
        with open(input_path, "r", encoding="utf-8") as f:
            alert = json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found: {input_path}")
        return 2
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {input_path}: {e}")
        return 2

    # Validate before categorising
    errors = validate_alert(alert)
    if errors:
        print("\nError: Alert failed validation:")
        for e in errors:
            print(f" - {e}")
        return 2

    result = decide_category(alert)

    # Print a nice summary
    print("\n=== Incident Categorisation Result ===")
    print(f"Category   : {result['category']}")
    print(f"Severity   : {result['severity']}")
    print(f"Score      : {result['score']}")
    print(f"Confidence : {result['confidence']}%")
    print(f"IP Rep     : {result['ip_reputation']}")
    print(f"Hash       : {result['hash_verdict']}")
    print(f"Review?    : {'YES' if result.get('needs_human_review') else 'NO'}")
    print("Reasons    :")
    for r in result["reasons"]:
        print(f" - {r}")
    if result.get("tags"):
        print(f"Tags       : {', '.join(result['tags'])}")

    # Save output JSON beside the input for evidence/screenshots
    out_path = input_path.replace(".json", "") + "_classified.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    # Write a lightweight audit log
    with open("runs.log", "a", encoding="utf-8") as log:
        log.write(
            f"{datetime.utcnow().isoformat()}Z | {input_path} | "
            f"{result['category']} | {result['severity']} | {result['confidence']}% | "
            f"review={result.get('needs_human_review', False)}\n"
        )

    print(f"\nSaved: {out_path}")
    print("Logged: runs.log\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())