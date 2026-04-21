"""
Generates realistic test cases in TheHive 5 for the Catnip Games SOC demo.
Each case represents a real-world security incident that could occur at a
gaming company. Cases are tagged so the TheHive dashboard charts populate
automatically with category and severity breakdowns.

HOW IT WORKS:
  1. Deletes any existing matching cases to avoid duplicates
  2. Creates each case with realistic metadata, tags, and descriptions
  3. Adds IOC observables (IPs, hashes, URLs) to each case
  4. Prints a summary table confirming everything was created

USAGE:
    python3 generate_cases.py

"""

import requests
import json
import time
from datetime import datetime, timedelta


# ── Configuration ─────────────────────────────────────────────────────────────

# TheHive URL and API key for authentication

# API key is generated from TheHive under Profile → API Key

THEHIVE_URL = "http://192.168.56.200:9000"

API_KEY     = "laG1qNbdu++svdO5huciNsBeh4CmQQG6"

# ─────────────────────────────────────────────────────────────────────────────


# Standard request headers required for all TheHive 5 API calls

HEADERS = {

    "Authorization": f"Bearer {API_KEY}",

    "Content-Type":  "application/json"

}


def days_ago_ms(days: int) -> int:

    """

    Converts a number of days into a Unix timestamp in milliseconds.

    TheHive 5 requires all date fields in milliseconds.

    Used to spread cases across the past 30 days so the timeline

    charts on the dashboard look realistic rather than all appearing

    on the same day.

    """

    dt = datetime.utcnow() - timedelta(days=days)

    return int(dt.timestamp() * 1000)


# ── Case Definitions ──────────────────────────────────────────────────────────

# Each entry represents one realistic security incident at Catnip Games.

# The category: tags are critical — they drive the dashboard donut charts

# and are also used by add_tasks.py and tag_based_ttps.py to automatically

# assign the correct tasks and MITRE ATT&CK TTPs to each case.

#

# Severity levels: 1=Low, 2=Medium, 3=High, 4=Critical

# TLP levels: 1=GREEN, 2=AMBER, 3=AMBER+STRICT, 4=RED

# PAP levels: 1=GREEN, 2=AMBER, 3=RED

TEST_CASES = [

    {

        "title": "Suspicious login attempts on player accounts",

        "description": (

            "Multiple failed login attempts detected across 15 player accounts "

            "within a 10-minute window. Source IPs originate from three different "

            "countries. Possible credential stuffing attack using leaked credentials."

        ),

        "severity": 3,

        "tags":     ["category:Credential_Attack", "severity:High", "source:IDS"],

        "tlp":      2,

        "pap":      2,

        "status":   "New",

        "startDate": days_ago_ms(28),

        "observables": [

            {"dataType": "ip",    "data": "185.220.101.45", "message": "Source IP — credential stuffing origin"},

            {"dataType": "ip",    "data": "45.142.212.100", "message": "Source IP — credential stuffing origin"},

            {"dataType": "other", "data": "player_gx99",    "message": "Targeted player account"},

        ]

    },

    {

        "title": "Bot activity detected in matchmaking service",

        "description": (

            "Automated bot behaviour identified in the matchmaking queue. "

            "Bots are exploiting game logic to manipulate match outcomes. "

            "Approx 200 bot accounts flagged by anomaly detection."

        ),

        "severity": 2,

        "tags":     ["category:Bot_Attack", "severity:Medium", "source:GameLogs"],

        "tlp":      2,

        "pap":      2,

        "status":   "New",

        "startDate": days_ago_ms(21),

        "observables": [

            {"dataType": "ip",    "data": "91.108.4.200",   "message": "Bot controller IP"},

            {"dataType": "other", "data": "bot_farm_acct1", "message": "Flagged bot account"},

            {"dataType": "other", "data": "bot_farm_acct2", "message": "Flagged bot account"},

        ]

    },

    {

        "title": "Social engineering attempt targeting support staff",

        "description": (

            "A support team member received a convincing phishing email impersonating "

            "a senior developer, requesting access credentials for the player database. "

            "Email headers indicate spoofed internal domain."

        ),

        "severity": 3,

        "tags":     ["category:Social_Engineering", "severity:High", "source:Email"],

        "tlp":      3,

        "pap":      1,

        "status":   "New",

        "startDate": days_ago_ms(18),

        "observables": [

            {"dataType": "mail",   "data": "dev-noreply@catnip-games.support", "message": "Spoofed sender address"},

            {"dataType": "domain", "data": "catnip-games.support",             "message": "Attacker-controlled lookalike domain"},

            {"dataType": "ip",     "data": "192.0.2.55",                       "message": "Mail server origin IP"},

        ]

    },

    {

        "title": "Unauthorised API access attempt on player data endpoint",

        "description": (

            "Repeated unauthorised requests to the /api/v1/players endpoint detected. "

            "Requests include malformed JWT tokens. Possible attempt to bypass "

            "authentication and exfiltrate player profile data."

        ),

        "severity": 4,

        "tags":     ["category:Unauthorised_Access", "severity:Critical", "source:WAF"],

        "tlp":      3,

        "pap":      1,

        "status":   "New",

        "startDate": days_ago_ms(14),

        "observables": [

            {"dataType": "ip",  "data": "198.51.100.77",                        "message": "WAF blocked source IP"},

            {"dataType": "url", "data": "http://192.168.56.200/api/v1/players", "message": "Targeted endpoint"},

        ]

    },

    {

        "title": "Malware detected on game server node GS-07",

        "description": (

            "Endpoint detection flagged a suspicious process on game server GS-07. "

            "Process is attempting outbound connections to a known C2 IP address. "

            "Server has been isolated pending investigation."

        ),

        "severity": 4,

        "tags":     ["category:Malware", "severity:Critical", "source:EDR"],

        "tlp":      3,

        "pap":      1,

        "status":   "New",

        "startDate": days_ago_ms(9),

        "observables": [

            {"dataType": "ip",   "data": "203.0.113.99",                              "message": "C2 server IP"},

            {"dataType": "hash", "data": "d41d8cd98f00b204e9800998ecf8427e",          "message": "MD5 hash of suspicious binary"},

            {"dataType": "hash", "data": "da39a3ee5e6b4b0d3255bfef95601890afd80709", "message": "SHA1 hash of suspicious binary"},

        ]

    },

    {

        "title": "Unusual data transfer volume from matchmaking DB",

        "description": (

            "Database monitoring detected an unusually large outbound data transfer "

            "from the matchmaking database at 03:15 UTC. Transfer volume 10x above "

            "baseline. Possible data exfiltration attempt."

        ),

        "severity": 3,

        "tags":     ["category:Data_Exfiltration", "severity:High", "source:SIEM"],

        "tlp":      2,

        "pap":      2,

        "status":   "New",

        "startDate": days_ago_ms(3),

        "observables": [

            {"dataType": "ip",    "data": "198.51.100.200",   "message": "Destination IP for exfiltrated data"},

            {"dataType": "other", "data": "matchmaking-db-01", "message": "Source database host"},

        ]

    },

]



def delete_existing_cases() -> None:

    """

    Finds and deletes any existing cases whose titles match our test cases.

    This ensures the script can be re-run cleanly without creating duplicates.

    Essential for demo preparation — run this before every demonstration

    to reset the environment to a clean known state.

    """

    titles = [c["title"] for c in TEST_CASES]

    print("[~] Checking for existing cases to clean up...")

    url = f"{THEHIVE_URL}/api/v1/query"

    payload = {

        "query": [

            {"_name": "listCase"},

            {"_name": "page", "from": 0, "to": 50}

        ]

    }

    try:

        response = requests.post(url, headers=HEADERS, json=payload, timeout=10)

        if response.status_code != 200:

            print(f"  [!] Could not fetch cases: {response.status_code}")

            return

        cases = response.json()

        deleted = 0

        for case in cases:

            if case.get("title") in titles:

                case_id = case.get("_id")

                del_url = f"{THEHIVE_URL}/api/v1/case/{case_id}"

                del_response = requests.delete(del_url, headers=HEADERS, timeout=10)

                if del_response.status_code in (200, 204):

                    print(f"  [-] Deleted: '{case['title']}'")

                    deleted += 1

                else:

                    print(f"  [!] Could not delete '{case['title']}': {del_response.status_code}")

        if deleted == 0:

            print("  [~] No existing matching cases found.")

        else:

            print(f"  [~] Cleaned up {deleted} existing case(s).\n")

    except requests.exceptions.ConnectionError:

        print(f"  [!] Connection error during cleanup.")



def create_case(case: dict):

    """

    Creates a single case in TheHive using the REST API.

    Returns the internal TheHive case ID (_id) on success, or None on failure.

    The case ID is needed immediately after creation to attach observables.

    """

    url = f"{THEHIVE_URL}/api/v1/case"

    payload = {

        "title":       case["title"],

        "description": case["description"],

        "severity":    case["severity"],

        "tags":        case["tags"],

        "tlp":         case["tlp"],

        "pap":         case["pap"],

        "status":      case["status"],

        "startDate":   case["startDate"],

    }

    try:

        response = requests.post(url, headers=HEADERS, json=payload, timeout=10)

        if response.status_code in (200, 201):

            return response.json().get("_id", "unknown")

        else:

            print(f"  [!] Failed: {response.status_code}: {response.text}")

            return None

    except requests.exceptions.ConnectionError:

        print(f"  [!] Connection error — is TheHive running at {THEHIVE_URL}?")

        return None

    except requests.exceptions.Timeout:

        print(f"  [!] Request timed out.")

        return None



def add_observables(case_id: str, observables: list) -> int:

    """

    Adds IOCs (Indicators of Compromise) to a case as observables.

    Observables are the technical evidence attached to an incident:

    IP addresses, file hashes, URLs, email addresses, domain names.

    These observables can be sent directly to Cortex analysers from

    within TheHive to enrich the investigation with threat intelligence.

    Returns the count of successfully added observables.

    """

    success_count = 0

    for obs in observables:

        url = f"{THEHIVE_URL}/api/v1/case/{case_id}/observable"

        payload = {

            "dataType": obs["dataType"],  # ip, hash, url, domain, mail, other

            "data":     obs["data"],      # The actual IOC value

            "message":  obs["message"],   # Human-readable description

            "tlp":      2,                # TLP:AMBER — handle with care

            "ioc":      True,             # Flag as confirmed indicator of compromise

            "sighted":  True,             # Confirm this IOC has been observed in the wild

        }

        try:

            response = requests.post(url, headers=HEADERS, json=payload, timeout=10)

            if response.status_code in (200, 201):

                success_count += 1

            else:

                print(f"  [!] Observable failed ({obs['data']}): {response.status_code}")

        except Exception as e:

            print(f"  [!] Observable error: {e}")

    return success_count



def print_summary(results: list) -> None:

    """

    Prints a formatted summary table of all cases created in this run.

    Shows case number, creation status, IOC count, and title.

    """

    print("\n" + "="*70)

    print("  CATNIP GAMES SOC — CASE GENERATION SUMMARY")

    print("="*70)

    print(f"  {'#':<4} {'Status':<12} {'IOCs':<8} {'Title'}")

    print("-"*70)

    for i, r in enumerate(results, 1):

        status = "✓ Created" if r["id"] else "✗ Failed"

        iocs   = str(r["observables"]) if r["id"] else "-"

        title  = r["title"][:45] + "..." if len(r["title"]) > 45 else r["title"]

        print(f"  {i:<4} {status:<12} {iocs:<8} {title}")

    print("="*70)

    created = sum(1 for r in results if r["id"])

    print(f"\n  Total created: {created}/{len(results)} cases")

    print("  Refresh your TheHive dashboard to see updated charts.\n")



def main():

    """

    Main execution function. Runs the full case generation workflow:

    1. Clean up any existing matching cases

    2. Create each case with its tags and metadata

    3. Add IOC observables to each case

    4. Print the summary table

    """

    print(f"\nConnecting to TheHive at {THEHIVE_URL}")

    print(f"Generating {len(TEST_CASES)} cases with observables...\n")


    # Step 1: Remove old cases to ensure a clean demo environment

    delete_existing_cases()


    results = []


    # Step 2: Create each case and attach its observables

    for case in TEST_CASES:

        print(f"[→] Creating: '{case['title']}'")

        case_id = create_case(case)

        obs_count = 0

        if case_id:

            print(f"  [+] Case created → ID: {case_id}")

            obs_count = add_observables(case_id, case["observables"])

            print(f"  [+] IOCs added: {obs_count}/{len(case['observables'])}")

        results.append({

            "title":       case["title"],

            "id":          case_id,

            "observables": obs_count,

        })

        # Brief pause to avoid overwhelming the TheHive API

        time.sleep(0.5)


    # Step 3: Print the final summary

    print_summary(results)



if __name__ == "__main__":

    main()
