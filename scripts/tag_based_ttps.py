"""
Automatically adds MITRE ATT&CK TTPs (Tactics, Techniques and Procedures)
to TheHive cases based on their category tags. This maps each incident
type to the real-world attack techniques used by threat actors in that
category, providing richer context for investigators and analysts.

  TTPs are standardised identifiers from the MITRE ATT&CK framework that
  describe HOW attackers operate. For example T1110 is Brute Force,
  T1566 is Phishing. Adding TTPs to cases helps analysts understand the
  attack method and look up known mitigations from the ATT&CK knowledge base.

HOW IT WORKS:
  1. Fetches all cases from TheHive
  2. Reads the category tag on each case
  3. Looks up the correct MITRE ATT&CK TTPs for that category
  4. Adds the TTPs to the case via the TheHive procedures API

USAGE:
    python3 tag_based_ttps.py

SUPPORTED CATEGORIES AND THEIR TTPs:
    category:Credential_Attack    → T1110, T1078, T1589
    category:Bot_Attack           → T1496, T1059, T1499
    category:Social_Engineering   → T1566, T1598, T1534
    category:Unauthorised_Access  → T1190, T1083, T1530
    category:Malware              → T1059, T1055, T1486
    category:Data_Exfiltration    → T1041, T1048, T1005
"""

import requests
import urllib3

# Suppress SSL warnings — the lab environment uses self-signed certificates

urllib3.disable_warnings()


# ── Configuration ─────────────────────────────────────────────────────────────

THEHIVE_URL = "http://192.168.56.200:9000"

API_KEY = "laG1qNbdu++svdO5huciNsBeh4CmQQG6"

# ─────────────────────────────────────────────────────────────────────────────


# Standard headers required for all TheHive API requests

headers = {

    "Authorization": f"Bearer {API_KEY}",

    "Content-Type": "application/json"

}


# ── Tag to TTP Mapping ────────────────────────────────────────────────────────

# Maps each incident category tag to its relevant MITRE ATT&CK technique IDs.

# The occurDate field is required by TheHive 5 when adding a TTP procedure.

# TTPs are selected based on the most common techniques used by threat actors

# in each incident category as defined in the MITRE ATT&CK framework.

TAG_TTP_MAPPING = {


    # Credential Attack TTPs

    # T1110 = Brute Force — repeated login attempts to guess credentials

    # T1078 = Valid Accounts — using stolen legitimate credentials

    # T1589 = Gather Victim Identity Information — harvesting account data

    "category:credential_attack": [

        {"patternId": "T1110", "occurDate": "2026-04-13T12:00:00Z"},

        {"patternId": "T1078", "occurDate": "2026-04-13T12:00:00Z"},

        {"patternId": "T1589", "occurDate": "2026-04-13T12:00:00Z"},

    ],


    # Bot Attack TTPs

    # T1496 = Resource Hijacking — bots consuming game resources

    # T1059 = Command and Scripting Interpreter — automated bot scripts

    # T1499 = Endpoint Denial of Service — bots overwhelming matchmaking

    "category:bot_attack": [

        {"patternId": "T1496", "occurDate": "2026-04-13T12:00:00Z"},

        {"patternId": "T1059", "occurDate": "2026-04-13T12:00:00Z"},

        {"patternId": "T1499", "occurDate": "2026-04-13T12:00:00Z"},

    ],


    # Social Engineering TTPs

    # T1566 = Phishing — deceptive emails targeting staff

    # T1598 = Spearphishing for Information — targeted info gathering

    # T1534 = Internal Spearphishing — impersonating internal staff

    "category:social_engineering": [

        {"patternId": "T1566", "occurDate": "2026-04-13T12:00:00Z"},

        {"patternId": "T1598", "occurDate": "2026-04-13T12:00:00Z"},

        {"patternId": "T1534", "occurDate": "2026-04-13T12:00:00Z"},

    ],


    # Unauthorised Access TTPs

    # T1190 = Exploit Public Facing Application — attacking the player API

    # T1083 = File and Directory Discovery — probing endpoints

    # T1530 = Data from Cloud Storage — accessing player data stores

    "category:unauthorised_access": [

        {"patternId": "T1190", "occurDate": "2026-04-13T12:00:00Z"},

        {"patternId": "T1083", "occurDate": "2026-04-13T12:00:00Z"},

        {"patternId": "T1530", "occurDate": "2026-04-13T12:00:00Z"},

    ],


    # Malware TTPs

    # T1059 = Command and Scripting Interpreter — malware execution

    # T1055 = Process Injection — malware hiding in legitimate processes

    # T1486 = Data Encrypted for Impact — ransomware style encryption

    "category:malware": [

        {"patternId": "T1059", "occurDate": "2026-04-13T12:00:00Z"},

        {"patternId": "T1055", "occurDate": "2026-04-13T12:00:00Z"},

        {"patternId": "T1486", "occurDate": "2026-04-13T12:00:00Z"},

    ],


    # Data Exfiltration TTPs

    # T1041 = Exfiltration Over C2 Channel — data sent via command channel

    # T1048 = Exfiltration Over Alternative Protocol — using non-standard ports

    # T1005 = Data from Local System — collecting data from the database server

    "category:data_exfiltration": [

        {"patternId": "T1041", "occurDate": "2026-04-13T12:00:00Z"},

        {"patternId": "T1048", "occurDate": "2026-04-13T12:00:00Z"},

        {"patternId": "T1005", "occurDate": "2026-04-13T12:00:00Z"},

    ],

}



def get_all_cases():

    """

    Fetches all cases from TheHive using the query API.

    Returns a list of case objects, or an empty list if the request fails.

    No status filter is applied so all cases are processed regardless

    of whether they are New, In Progress, or Closed.

    """

    response = requests.post(

        f"{THEHIVE_URL}/api/v1/query",

        headers=headers,

        json={"query": [{"_name": "listCase"}]},

        verify=False

    )

    if response.status_code == 200:

        return response.json()

    else:

        print(f"[!] Failed to fetch cases: {response.status_code} - {response.text}")

        return []



def get_ttps_for_case(tags):

    """

    Looks up the correct TTPs for a case based on its category tags.

    Normalises each tag to lowercase with spaces removed before matching

    to handle formatting variations like 'category: Bot_Attack' vs

    'category:Bot_Attack'. Returns a deduplicated list of TTP objects.

    """

    ttps = []

    for tag in tags:

        # Normalise the tag for consistent matching

        tag_lower = tag.lower().strip().replace(" ", "")

        if tag_lower in TAG_TTP_MAPPING:

            ttps.extend(TAG_TTP_MAPPING[tag_lower])


    # Remove duplicate TTPs — a case could theoretically match multiple

    # category tags and end up with the same TTP added twice

    seen = set()

    unique_ttps = []

    for ttp in ttps:

        if ttp["patternId"] not in seen:

            seen.add(ttp["patternId"])

            unique_ttps.append(ttp)

    return unique_ttps



def add_ttp_to_case(case_id, ttp):

    """

    Adds a single MITRE ATT&CK TTP to a case via the TheHive procedures API.

    The procedure endpoint accepts a patternId (ATT&CK technique ID) and

    an occurDate (when the technique was observed in this incident).

    Returns True if successful, False otherwise.

    """

    response = requests.post(

        f"{THEHIVE_URL}/api/v1/case/{case_id}/procedure",

        headers=headers,

        json=ttp,

        verify=False

    )

    return response.status_code in [200, 201]



# ── Main execution ────────────────────────────────────────────────────────────

print("=" * 60)

print("CATNIP GAMES SOC - TAG BASED TTP INJECTION")

print("=" * 60)


# Step 1: Fetch all cases from TheHive

cases = get_all_cases()

total_added = 0


if not cases:

    print("[!] No cases found or failed to connect to TheHive")

else:

    print(f"[→] Found {len(cases)} cases\n")


    # Step 2: Process each case

    for case in cases:

        case_id     = case.get("_id")

        case_number = case.get("number")

        case_title  = case.get("title")

        case_tags   = case.get("tags", [])


        print(f"[→] Case #{case_number}: {case_title}")

        print(f"    Tags: {case_tags}")


        # Step 3: Look up TTPs for this case based on its category tag

        ttps = get_ttps_for_case(case_tags)

        if not ttps:

            print(f"    [!] No matching TTPs found for tags\n")

            continue


        # Step 4: Add each TTP to the case

        success_count = 0

        for ttp in ttps:

            if add_ttp_to_case(case_id, ttp):

                print(f"    [+] Added TTP: {ttp['patternId']}")

                success_count += 1

                total_added += 1

            else:

                print(f"    [!] Failed: {ttp['patternId']}")


        print(f"    [✓] {success_count}/{len(ttps)} TTPs added\n")


# Ensure total_added is always defined even if no cases were processed

total_added = total_added if 'total_added' in dir() else 0

print("=" * 60)

print(f"Complete! Total TTPs added: {total_added}")

print("Refresh TheHive to verify.")

print("=" * 60)
