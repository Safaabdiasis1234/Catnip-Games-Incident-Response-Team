"""
Closes the automation loop by reading Cortex analyser results and writing
them back to TheHive cases automatically.

FIX NOTE:
    TheHive 5 exposes Cortex jobs via the global /api/v1/query listJob endpoint.
    Per-observable job queries are not supported on this instance.
    This version fetches all jobs globally, then fetches each job's full report
    from Cortex directly using the cortexJobId, and matches results back to
    cases via their observables.

WHAT IT DOES (per case):
    1. Fetches all completed GameThreat jobs from TheHive's global job list
    2. For each job, retrieves the full report from Cortex by cortexJobId
    3. Matches jobs to cases by looking up which case owns the observable
    4. Updates case severity if the risk warrants escalation
    5. Applies structured enrichment tags (enriched:GameThreat, risk:High, etc.)
    6. Appends an audit comment with the full analysis summary
    7. Adds a review:needed tag if confidence is below the threshold

USAGE:
    python3 thehive_writeback.py

"""

import requests
import urllib3
from datetime import datetime, timezone

urllib3.disable_warnings()

# ── Configuration ─────────────────────────────────────────────────────────────

THEHIVE_URL = "http://192.168.56.200:9000"

CORTEX_URL  = "http://192.168.56.200:9001"

THEHIVE_KEY = "laG1qNbdu++svdO5huciNsBeh4CmQQG6"


# Cortex API key — generate at: Cortex → Organisation → API Keys

CORTEX_KEY  = "69kRMu2dDqjJeI1JUvS1ycII63l1VjQN"


# Confidence below this threshold → add review:needed tag

LOW_CONFIDENCE_THRESHOLD = 70


# Risk level → TheHive severity (1=Low, 2=Medium, 3=High, 4=Critical)

RISK_SEVERITY_MAP = {

    "High":   4,

    "Medium": 3,

    "Low":    2,

}

# ─────────────────────────────────────────────────────────────────────────────


THEHIVE_HEADERS = {

    "Authorization": f"Bearer {THEHIVE_KEY}",

    "Content-Type":  "application/json"

}


CORTEX_HEADERS = {

    "Authorization": f"Bearer {CORTEX_KEY}",

    "Content-Type":  "application/json"

}



# ── TheHive API helpers ───────────────────────────────────────────────────────


def get_all_cases():

    """Fetches all cases from TheHive."""

    response = requests.post(

        f"{THEHIVE_URL}/api/v1/query",

        headers=THEHIVE_HEADERS,

        json={"query": [{"_name": "listCase"}]},

        verify=False, timeout=10

    )

    return response.json() if response.status_code == 200 else []



def get_case_observables(case_id):

    """Fetches all observables attached to a specific case."""

    response = requests.post(

        f"{THEHIVE_URL}/api/v1/query",

        headers=THEHIVE_HEADERS,

        json={"query": [

            {"_name": "getCase", "idOrName": case_id},

            {"_name": "observables"}

        ]},

        verify=False, timeout=10

    )

    return response.json() if response.status_code == 200 else []



def get_all_gamethreat_jobs():

    """

    Fetches all completed GameThreat jobs from TheHive's global job list.

    This is the correct approach for TheHive 5 — jobs are stored globally

    and linked back to observables via the job metadata.

    """

    response = requests.post(

        f"{THEHIVE_URL}/api/v1/query",

        headers=THEHIVE_HEADERS,

        json={"query": [{"_name": "listJob"}]},

        verify=False, timeout=10

    )

    if response.status_code != 200:

        print(f"[!] Failed to fetch jobs: {response.status_code}")

        return []


    all_jobs = response.json()


    # Filter to only successful GameThreat jobs

    gamethreat_jobs = [

        j for j in all_jobs

        if "GameThreat" in j.get("analyzerName", "")

        and j.get("status") == "Success"

    ]


    print(f"[→] Found {len(gamethreat_jobs)} completed GameThreat job(s)")

    return gamethreat_jobs



def get_cortex_job_report(cortex_job_id):

    """

    Fetches the full analysis report from Cortex using the cortexJobId.

    Tries the /report endpoint first, then falls back to the job itself.

    """

    response = requests.get(

        f"{CORTEX_URL}/api/job/{cortex_job_id}/report",

        headers=CORTEX_HEADERS,

        verify=False, timeout=10

    )

    if response.status_code == 200:

        return response.json()


    # Fallback: fetch the job object which may contain the report inline

    response = requests.get(

        f"{CORTEX_URL}/api/job/{cortex_job_id}",

        headers=CORTEX_HEADERS,

        verify=False, timeout=10

    )

    if response.status_code == 200:

        job_data = response.json()

        return job_data.get("report") or job_data

    return None



def get_job_observable_data(thehive_job_id):

    """

    Fetches the observable associated with a specific TheHive job.

    Used to match the job result back to the case that owns the observable.

    """

    response = requests.post(

        f"{THEHIVE_URL}/api/v1/query",

        headers=THEHIVE_HEADERS,

        json={"query": [

            {"_name": "getJob", "idOrName": thehive_job_id},

            {"_name": "observable"}

        ]},

        verify=False, timeout=10

    )

    if response.status_code == 200:

        result = response.json()

        if isinstance(result, list) and result:

            return result[0]

        return result

    return None



def update_case_severity(case_id, new_severity, current_severity):

    """Updates case severity — only escalates, never downgrades."""

    if new_severity <= current_severity:

        return False

    response = requests.patch(

        f"{THEHIVE_URL}/api/v1/case/{case_id}",

        headers=THEHIVE_HEADERS,

        json={"severity": new_severity},

        verify=False, timeout=10

    )

    return response.status_code in [200, 201]



def add_tags_to_case(case_id, new_tags, existing_tags):

    """Adds new tags to a case, merging with existing tags."""

    merged = list(set(existing_tags + new_tags))

    response = requests.patch(

        f"{THEHIVE_URL}/api/v1/case/{case_id}",

        headers=THEHIVE_HEADERS,

        json={"tags": merged},

        verify=False, timeout=10

    )

    return response.status_code in [200, 201]



def add_case_comment(case_id, comment_text):

    """Adds an audit comment to the case documenting automated actions."""

    response = requests.post(

        f"{THEHIVE_URL}/api/v1/case/{case_id}/comment",

        headers=THEHIVE_HEADERS,

        json={"message": comment_text},

        verify=False, timeout=10

    )

    return response.status_code in [200, 201]



# ── Report parsing ────────────────────────────────────────────────────────────


def parse_gamethreat_report(report):

    """

    Extracts findings from a GameThreat analyser report.

    Handles multiple possible report structures returned by Cortex.


    Standard GameThreat report structure (from game_threat.py):

    {

        "full": {

            "found": bool,

            "risk_level": "High/Medium/Low",

            "confidence": 0-100,

            "reason": "...",

            "tags": [...],

            "recommendations": [...]

        }

    }

    """

    if not report:

        return None


    # Try standard Cortex report structure: report["full"]

    full = report.get("full", {})


    # Fallback: report IS the full dict directly

    if not full and "risk_level" in report:

        full = report


    # Fallback: nested under report["report"]["full"]

    if not full:

        nested = report.get("report", {})

        full = nested.get("full", nested)


    if not full:

        return None


    return {

        "found":           full.get("found", False),

        "risk_level":      full.get("risk_level", "Low"),

        "confidence":      full.get("confidence", 0),

        "reason":          full.get("reason") or "No reason provided",

        "tags":            full.get("tags", []),

        "recommendations": full.get("recommendations", []),

        "observable":      full.get("observable", "unknown"),

        "data_type":       full.get("data_type", "unknown"),

        "abuseipdb":       full.get("abuseipdb"),

    }



def build_enrichment_tags(findings):

    """Builds structured enrichment tags based on analyser findings."""

    tags = ["enriched:GameThreat"]

    if findings["found"]:

        tags.append(f"risk:{findings['risk_level']}")

        tags.append("ioc:confirmed")

        for threat_tag in findings["tags"]:

            tags.append(f"threat:{threat_tag}")

        if findings["confidence"] < LOW_CONFIDENCE_THRESHOLD:

            tags.append("review:needed")

    else:

        tags.append("risk:Low")

        tags.append("ioc:not-found")

    return tags



def build_audit_comment(findings, observable_value):

    """Builds the markdown audit comment documenting automated actions."""

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [

        f"**[AUTOMATED — GameThreat Writeback] {ts}**\n",

        f"**Observable:** `{observable_value}` ({findings['data_type']})",

        f"**Result:** {'FOUND IN BLOCKLIST' if findings['found'] else 'Not in blocklist'}",

        f"**Risk level:** {findings['risk_level']}",

        f"**Confidence:** {findings['confidence']}%",

    ]

    if findings["reason"] and findings["reason"] != "No reason provided":

        lines.append(f"**Reason:** {findings['reason']}")

    if findings["recommendations"]:

        lines.append("\n**Recommendations:**")

        for rec in findings["recommendations"]:

            lines.append(f"- {rec}")

    if findings.get("abuseipdb"):

        ab = findings["abuseipdb"]

        lines.append(

            f"\n**AbuseIPDB:** score {ab.get('abuseConfidenceScore', 0)}/100 "

            f"| ISP: {ab.get('isp', 'unknown')} "

            f"| Country: {ab.get('countryCode', 'unknown')}"

        )

    lines.append("\n**Automated actions taken:**")

    if findings["found"]:

        lines.append(f"- Severity escalated based on {findings['risk_level']} risk finding")

        lines.append(f"- Tags applied: enriched:GameThreat, risk:{findings['risk_level']}, ioc:confirmed")

        for t in findings["tags"]:

            lines.append(f"- Threat tag propagated: threat:{t}")

        if findings["confidence"] < LOW_CONFIDENCE_THRESHOLD:

            lines.append(f"- review:needed tag added — confidence {findings['confidence']}% below {LOW_CONFIDENCE_THRESHOLD}% threshold")

    else:

        lines.append("- No escalation — observable not in internal blocklist")

        lines.append("- Suggestion: submit to VirusTotal or Shodan for further enrichment")

    return "\n".join(lines)



# ── Main execution ────────────────────────────────────────────────────────────


def main():

    print("=" * 65)

    print("  CATNIP GAMES SOC — CORTEX WRITEBACK ENGINE")

    print("=" * 65)

    print("  Reading Cortex job results and updating TheHive cases...\n")


    # Step 1: Get all completed GameThreat jobs

    gamethreat_jobs = get_all_gamethreat_jobs()

    if not gamethreat_jobs:

        print("[!] No completed GameThreat jobs found.")

        print("    Trigger the GameThreat analyser in TheHive first:")

        print("    → Open a case → Observables → click analyser icon → GameThreat → Run")

        return


    # Step 2: Build observable → case lookup map

    print("[→] Loading cases and observables...\n")

    cases = get_all_cases()

    if not cases:

        print("[!] No cases found.")

        return


    obs_to_case = {}

    for case in cases:

        for obs in get_case_observables(case.get("_id")):

            obs_value = obs.get("data", "").lower().strip()

            if obs_value:

                obs_to_case[obs_value] = (case, obs)


    # Step 3: Process each GameThreat job

    total_updated   = 0

    total_escalated = 0

    total_flagged   = 0

    processed_cases = set()


    for job in gamethreat_jobs:

        thehive_job_id = job.get("_id")

        cortex_job_id  = job.get("cortexJobId")


        print(f"[→] Job: {thehive_job_id} | Cortex ID: {cortex_job_id}")


        # Get the observable this job ran on

        obs_object = get_job_observable_data(thehive_job_id)

        obs_value  = obs_object.get("data", "unknown") if isinstance(obs_object, dict) else "unknown"

        print(f"    [~] Observable: {obs_value}")


        # Match observable to a case

        case_match = obs_to_case.get(obs_value.lower().strip())

        if not case_match:

            print(f"    [!] Observable not matched to any current case\n")

            continue


        case, obs      = case_match

        case_id        = case.get("_id")

        case_number    = case.get("number")

        case_title     = case.get("title")

        case_tags      = case.get("tags", [])

        case_severity  = case.get("severity", 2)

        severity_labels = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


        print(f"    [~] Case #{case_number}: {case_title}")


        if case_id in processed_cases:

            print(f"    [~] Already updated this run — skipping\n")

            continue


        # Fetch the full report from Cortex

        report   = get_cortex_job_report(cortex_job_id)

        findings = parse_gamethreat_report(report)


        if not findings:

            print(f"    [!] Could not parse Cortex report — applying basic tag only")

            add_tags_to_case(case_id, ["enriched:GameThreat", "cortex:analysed"], case_tags)

            print(f"    [+] Basic enrichment tag applied\n")

            processed_cases.add(case_id)

            total_updated += 1

            continue


        print(f"    [✓] Risk: {findings['risk_level']} | Confidence: {findings['confidence']}% | Found: {findings['found']}")


        # Update severity

        new_severity = RISK_SEVERITY_MAP.get(findings["risk_level"], 2)

        if update_case_severity(case_id, new_severity, case_severity):

            print(f"    [+] Severity: {severity_labels.get(case_severity)} → {severity_labels.get(new_severity)}")

            total_escalated += 1

        else:

            print(f"    [~] Severity unchanged ({severity_labels.get(case_severity)})")


        # Apply enrichment tags

        enrichment_tags = build_enrichment_tags(findings)

        if add_tags_to_case(case_id, enrichment_tags, case_tags):

            print(f"    [+] Tags: {', '.join(enrichment_tags)}")


        # Add audit comment

        if add_case_comment(case_id, build_audit_comment(findings, obs_value)):

            print(f"    [+] Audit comment added")


        if findings["confidence"] < LOW_CONFIDENCE_THRESHOLD:

            print(f"    [⚠] Low confidence — review:needed applied")

            total_flagged += 1


        processed_cases.add(case_id)

        total_updated += 1

        print()


    print("=" * 65)

    print(f"  Writeback complete.")

    print(f"  Cases updated:   {total_updated}")

    print(f"  Escalated:       {total_escalated}")

    print(f"  Flagged review:  {total_flagged}")

    print("  Refresh TheHive to verify case changes.")

    print("=" * 65)



if __name__ == "__main__":

    main()
