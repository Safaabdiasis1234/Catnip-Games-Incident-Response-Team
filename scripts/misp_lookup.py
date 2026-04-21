#!/usr/bin/env python3

"""
Enriches TheHive cases by checking their observables against MISP
(Malware Information Sharing Platform) threat intelligence.

    MISP is a community-driven threat intelligence platform. When an IP or
    domain appears in a TheHive case, this script checks whether that IOC
    has been seen in any MISP threat events — either from your local MISP
    instance or from connected community feeds.

WHAT IT DOES (per case):
    1. Fetches all cases from TheHive
    2. For each observable (IP, domain, hash, URL), queries MISP
    3. If MISP has a matching event, extracts threat context
    4. Adds a misp:hit tag to the case and a timeline comment with details
    5. If no match, adds a misp:clean tag to confirm the check was done

USAGE:
    python3 misp_lookup.py

NOTES:
    - MISP uses a self-signed cert in the lab — SSL verification is disabled
    - The MISP API key is found at: MISP → My Profile → Auth key
    - Default MISP credentials: admin@admin.test / admin
"""

import requests
import urllib3
import json
from datetime import datetime, timezone


# Suppress SSL warnings — MISP uses a self-signed cert in the lab

urllib3.disable_warnings()


# ── Configuration ─────────────────────────────────────────────────────────────

THEHIVE_URL = "http://192.168.56.200:9000"

MISP_URL    = "https://192.168.56.200"       # MISP runs on HTTPS port 443


THEHIVE_KEY = "laG1qNbdu++svdO5huciNsBeh4CmQQG6"


# MISP API key — get from MISP: top-right menu → My Profile → Auth key

# Replace with your actual MISP auth key

MISP_KEY    = "TLgXcwTG6vD32BKP3yIxJkC5dLqT2JW3mwIjzdKv"

# ─────────────────────────────────────────────────────────────────────────────


THEHIVE_HEADERS = {

    "Authorization": f"Bearer {THEHIVE_KEY}",

    "Content-Type":  "application/json"

}


MISP_HEADERS = {

    "Authorization": MISP_KEY,

    "Accept":        "application/json",

    "Content-Type":  "application/json"

}


# Map TheHive observable dataTypes to MISP attribute types

# MISP uses different naming conventions for the same IOC types

DATATYPE_TO_MISP = {

    "ip":     ["ip-dst", "ip-src", "ip-dst|port"],

    "domain": ["domain", "hostname"],

    "url":    ["url"],

    "hash":   ["md5", "sha1", "sha256", "sha512"],

    "mail":   ["email-src", "email-dst"],

}



# ── MISP API helpers ──────────────────────────────────────────────────────────


def search_misp_for_value(value, data_type):

    """

    Searches MISP for any events containing a specific IOC value.


    MISP's /attributes/restSearch endpoint accepts a 'value' parameter

    and returns all matching attributes across all events in the instance.


    Returns a list of matching MISP attribute objects, or empty list if none.

    """

    misp_types = DATATYPE_TO_MISP.get(data_type, [])


    # Search by value first (works across all attribute types)

    payload = {

        "returnFormat": "json",

        "value":        value,

        "limit":        10,

        "page":         1,

    }


    # If we know the specific MISP types, add them to narrow the search

    if misp_types:

        payload["type"] = misp_types


    try:

        response = requests.post(

            f"{MISP_URL}/attributes/restSearch",

            headers=MISP_HEADERS,

            json=payload,

            verify=False,

            timeout=15

        )

        if response.status_code == 200:

            data = response.json()

            return data.get("response", {}).get("Attribute", [])

        else:

            print(f"        [!] MISP search failed: {response.status_code}")

            return []

    except requests.exceptions.ConnectionError:

        print(f"        [!] Cannot connect to MISP at {MISP_URL}")

        return []

    except requests.exceptions.Timeout:

        print(f"        [!] MISP request timed out")

        return []



def get_misp_event_details(event_id):

    """

    Fetches full details for a specific MISP event by ID.

    Returns event metadata including threat level, distribution, and tags.

    """

    try:

        response = requests.get(

            f"{MISP_URL}/events/{event_id}",

            headers=MISP_HEADERS,

            verify=False,

            timeout=10

        )

        if response.status_code == 200:

            return response.json().get("Event", {})

        return {}

    except Exception:

        return {}



def get_misp_status():

    """

    Checks if MISP is reachable and returns version info.

    Used at startup to confirm connectivity before processing cases.

    """

    try:

        response = requests.get(

            f"{MISP_URL}/servers/getVersion",

            headers=MISP_HEADERS,

            verify=False,

            timeout=5

        )

        if response.status_code == 200:

            return response.json()

        return None

    except Exception:

        return None



# ── TheHive API helpers ───────────────────────────────────────────────────────


def get_all_cases():

    """Fetches all cases from TheHive."""

    response = requests.post(

        f"{THEHIVE_URL}/api/v1/query",

        headers=THEHIVE_HEADERS,

        json={"query": [{"_name": "listCase"}]},

        verify=False,

        timeout=10

    )

    if response.status_code == 200:

        return response.json()

    print(f"[!] Failed to fetch cases: {response.status_code}")

    return []



def get_case_observables(case_id):

    """Fetches all observables attached to a case."""

    response = requests.post(

        f"{THEHIVE_URL}/api/v1/query",

        headers=THEHIVE_HEADERS,

        json={

            "query": [

                {"_name": "getCase", "idOrName": case_id},

                {"_name": "observables"}

            ]

        },

        verify=False,

        timeout=10

    )

    if response.status_code == 200:

        return response.json()

    return []



def add_tags_to_case(case_id, new_tags, existing_tags):

    """Adds tags to a case, preserving all existing tags."""

    merged = list(set(existing_tags + new_tags))

    response = requests.patch(

        f"{THEHIVE_URL}/api/v1/case/{case_id}",

        headers=THEHIVE_HEADERS,

        json={"tags": merged},

        verify=False,

        timeout=10

    )

    return response.status_code in [200, 201]



def add_case_comment(case_id, comment_text):

    """Adds a comment to the case documenting the MISP lookup results."""

    response = requests.post(

        f"{THEHIVE_URL}/api/v1/case/{case_id}/comment",

        headers=THEHIVE_HEADERS,

        json={"message": comment_text},

        verify=False,

        timeout=10

    )

    return response.status_code in [200, 201]



# ── Result formatting ─────────────────────────────────────────────────────────


def format_misp_findings(observable_value, attributes):

    """

    Formats MISP search results into a human-readable comment for TheHive.

    Groups matches by MISP event and shows threat level and context.

    """

    threat_levels = {1: "High", 2: "Medium", 3: "Low", 4: "Undefined"}


    lines = [

        f"[MISP INTELLIGENCE LOOKUP — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}]",

        f"Observable: {observable_value}",

        f"MISP matches found: {len(attributes)}",

        ""

    ]


    # Group attributes by event ID for cleaner output

    events_seen = {}

    for attr in attributes:

        event_id = attr.get("event_id")

        if event_id not in events_seen:

            events_seen[event_id] = []

        events_seen[event_id].append(attr)


    for event_id, attrs in events_seen.items():

        # Try to get full event details for richer context

        event_details = get_misp_event_details(event_id)

        threat_level_id = int(event_details.get("threat_level_id", 4))

        threat_label    = threat_levels.get(threat_level_id, "Unknown")

        event_info      = event_details.get("info", f"Event {event_id}")

        event_date      = event_details.get("date", "unknown date")

        event_tags      = [t.get("name") for t in event_details.get("Tag", [])]


        lines.append(f"  MISP Event #{event_id}: {event_info}")

        lines.append(f"  Threat level: {threat_label} | Date: {event_date}")


        if event_tags:

            lines.append(f"  Tags: {', '.join(event_tags)}")


        for attr in attrs[:3]:   # Show up to 3 matching attributes per event

            lines.append(f"    → Attribute type: {attr.get('type')} | Category: {attr.get('category')}")

            if attr.get("comment"):

                lines.append(f"      Comment: {attr['comment']}")

        lines.append("")


    lines.append("This observable has been seen in MISP threat intelligence.")

    lines.append("Consider sharing updated IOC context back to MISP if new findings emerge.")


    return "\n".join(lines)



# ── Main execution ────────────────────────────────────────────────────────────


def main():

    print("=" * 65)

    print("  CATNIP GAMES SOC — MISP INTELLIGENCE LOOKUP")

    print("=" * 65)


    # Check MISP connectivity before processing

    misp_status = get_misp_status()

    if misp_status:

        print(f"[✓] MISP connected — version {misp_status.get('version', 'unknown')}\n")

    else:

        print("[!] Cannot connect to MISP. Check:")

        print(f"    URL:     {MISP_URL}")

        print("    API key: set MISP_KEY in script configuration")

        print("    Is MISP running? Check with: sudo docker compose ps\n")

        print("[~] Continuing in offline mode — will show connection errors per case\n")


    cases = get_all_cases()

    if not cases:

        print("[!] No cases found. Run generate_cases.py first.")

        return


    print(f"[→] Checking {len(cases)} cases against MISP\n")


    total_hits    = 0

    total_checked = 0


    for case in cases:

        case_id     = case.get("_id")

        case_number = case.get("number")

        case_title  = case.get("title")

        case_tags   = case.get("tags", [])


        print(f"[→] Case #{case_number}: {case_title}")


        observables = get_case_observables(case_id)

        if not observables:

            print(f"    [~] No observables — skipping\n")

            continue


        case_hits       = 0

        all_hit_details = []


        for obs in observables:

            obs_value = obs.get("data", "")

            obs_type  = obs.get("dataType", "")


            # Only search MISP for types it can match

            if obs_type not in DATATYPE_TO_MISP:

                continue


            print(f"    [~] MISP lookup: {obs_value} ({obs_type})")

            total_checked += 1


            attributes = search_misp_for_value(obs_value, obs_type)


            if attributes:

                print(f"        [!] MISP HIT — {len(attributes)} matching attribute(s)")

                case_hits   += 1

                total_hits  += 1

                hit_comment  = format_misp_findings(obs_value, attributes)

                all_hit_details.append(hit_comment)

            else:

                print(f"        [~] No MISP match")


        # Apply tags and comments based on results

        new_tags = []


        if case_hits > 0:

            new_tags.append("misp:hit")

            new_tags.append(f"misp:events:{case_hits}")

            print(f"    [+] {case_hits} MISP hit(s) found")


            # Add a combined comment with all hit details

            combined_comment = f"MISP lookup completed — {case_hits} hit(s) found\n\n"

            combined_comment += "\n\n---\n\n".join(all_hit_details)

            if add_case_comment(case_id, combined_comment):

                print(f"    [+] MISP intelligence comment added to case")

        else:

            new_tags.append("misp:clean")

            print(f"    [~] No MISP matches — misp:clean tag applied")


        # Always add the checked tag so we know MISP lookup ran on this case

        new_tags.append("misp:checked")


        if add_tags_to_case(case_id, new_tags, case_tags):

            print(f"    [+] Tags applied: {', '.join(new_tags)}")


        print()


    # ── Summary ───────────────────────────────────────────────────────────────

    print("=" * 65)

    print(f"  MISP lookup complete.")

    print(f"  Observables checked: {total_checked}")

    print(f"  MISP hits:           {total_hits}")

    print("  Refresh TheHive to see misp: tags on cases.")

    print("=" * 65)



if __name__ == "__main__":

    main()
