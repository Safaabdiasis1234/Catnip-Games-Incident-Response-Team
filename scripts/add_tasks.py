"""

Automatically adds investigation tasks to TheHive cases based on their
category tags. This eliminates the need to manually create tasks for
every new case — the correct tasks are assigned automatically based
on what type of incident the case represents.

HOW IT WORKS:
  1. Fetches all cases from TheHive
  2. Reads the category tag on each case
  3. Looks up the correct task list for that category
  4. Adds the tasks to the case — skipping any that already exist
     to prevent duplicates if the script is run multiple times

USAGE:
    python3 add_tasks.py

SUPPORTED CATEGORY TAGS:
    category:Credential_Attack    → 7 tasks
    category:Bot_Attack           → 7 tasks
    category:Social_Engineering   → 8 tasks
    category:Unauthorised_Access  → 9 tasks
    category:Malware              → 10 tasks
    category:Data_Exfiltration    → 11 tasks
    credential-stuffing           → 11 tasks (legacy tag for Case #1)

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


# ── Tag to Task Mapping ───────────────────────────────────────────────────────

# This dictionary is the core of the automation.

# Each key is a category tag (lowercased for matching).

# Each value is the list of tasks that should be created for that incident type.

# This approach means tasks are driven by incident category rather than

# being hardcoded to specific case IDs — making it fully scalable.

# Any future case with one of these tags will automatically get the right tasks.

TAG_TASK_MAPPING = {


    # Credential attack tasks — covers brute force and suspicious login incidents

    "category:credential_attack": [

        {"title": "Verify alert source and confirm suspicious IPs", "description": "Review the IDS alert that triggered this case. Confirm the source IPs attempting logins, check timestamps, and verify the alert is not a false positive before proceeding.", "status": "Waiting", "group": "default"},

        {"title": "Investigate affected player accounts", "description": "Identify which player accounts were targeted. Check for any successful logins, unusual session activity, or account changes such as email or password modifications since the suspicious activity began.", "status": "Waiting", "group": "default"},

        {"title": "Correlate IOCs in MISP", "description": "Export the suspicious IP addresses and any other IOCs to MISP. Check against existing threat intelligence feeds for known credential stuffing or brute force campaigns targeting gaming platforms.", "status": "Waiting", "group": "default"},

        {"title": "Run Cortex analyser on suspicious IPs", "description": "Add the suspicious IPs as observables and run the SOCEnrichment analyser via Cortex. Review the analysis report for risk level, confidence score, and any recommendations returned.", "status": "Waiting", "group": "default"},

        {"title": "Block suspicious IPs at perimeter firewall", "description": "Add all confirmed malicious IPs to the edge firewall and WAF block list. Document which IPs were blocked, the time of action, and the firewall rule reference number.", "status": "Waiting", "group": "default"},

        {"title": "Notify affected players and reset credentials", "description": "Contact any players whose accounts showed successful unauthorised access. Force a password reset, invalidate active sessions, and send a security notification email advising them to enable two-factor authentication.", "status": "Waiting", "group": "default"},

        {"title": "Post-incident review and close case", "description": "Document findings, actions taken, and timeline of the incident. Record lessons learned, update the playbook if needed, and close the case with a summary note confirming all containment steps were completed.", "status": "Waiting", "group": "default"},

    ],


    # Bot attack tasks — covers automated bots exploiting game services

    "category:bot_attack": [

        {"title": "Confirm bot activity and identify affected services", "description": "Review game logs that triggered the alert. Confirm the bot activity is genuine and identify which game services are affected. Document the scale of the activity.", "status": "Waiting", "group": "default"},

        {"title": "Identify bot source IPs and account patterns", "description": "Extract all source IPs and player account IDs associated with the bot activity. Look for patterns such as identical request timing, impossible game scores, or accounts created in bulk from the same IP range.", "status": "Waiting", "group": "default"},

        {"title": "Run Cortex analyser on suspicious IPs", "description": "Add identified bot IPs as observables and run the SOCEnrichment analyser via Cortex. Review the analysis report for risk level, confidence score, and recommendations returned.", "status": "Waiting", "group": "default"},

        {"title": "Correlate IOCs in MISP", "description": "Export the bot IPs and any associated account IOCs to MISP. Check against existing threat intelligence for known bot networks or gaming platform abuse campaigns.", "status": "Waiting", "group": "default"},

        {"title": "Block bot IPs and suspend associated accounts", "description": "Add all confirmed bot IPs to the WAF and firewall block list. Suspend player accounts confirmed to be bot-operated. Document all IPs blocked and accounts suspended with timestamps.", "status": "Waiting", "group": "default"},

        {"title": "Implement rate limiting and CAPTCHA on affected endpoints", "description": "Work with the development team to apply rate limiting on the affected matchmaking or game API endpoints. Recommend CAPTCHA or challenge responses where bot activity was concentrated.", "status": "Waiting", "group": "default"},

        {"title": "Post-incident review and close case", "description": "Document full timeline of the bot activity, actions taken, and platform hardening steps completed. Record lessons learned and update the bot attack playbook.", "status": "Waiting", "group": "default"},

    ],


    # Social engineering tasks — covers phishing and pretexting targeting staff

    "category:social_engineering": [

        {"title": "Confirm social engineering attempt and identify target", "description": "Review the email or communication that triggered this case. Confirm it is a genuine social engineering attempt and not a false positive. Identify which staff member was targeted.", "status": "Waiting", "group": "default"},

        {"title": "Preserve and analyse malicious communication", "description": "Preserve a copy of the phishing email or message as evidence. Extract all IOCs including sender email address, reply-to address, embedded URLs, and any attachment hashes for further analysis.", "status": "Waiting", "group": "default"},

        {"title": "Run Cortex analyser on extracted IOCs", "description": "Add extracted URLs, email addresses, and file hashes as observables and run the SOCEnrichment analyser via Cortex. Review the analysis report for risk level and any known malicious infrastructure matches.", "status": "Waiting", "group": "default"},

        {"title": "Correlate IOCs in MISP", "description": "Export all extracted IOCs to MISP. Check against existing threat intelligence for known phishing campaigns or threat actors known to target gaming companies.", "status": "Waiting", "group": "default"},

        {"title": "Assess if social engineering attempt was successful", "description": "Interview the targeted staff member to determine if any credentials, sensitive information, or system access was provided to the attacker. Check access logs for suspicious activity.", "status": "Waiting", "group": "default"},

        {"title": "Contain and remediate if compromise confirmed", "description": "If the attempt was successful, immediately reset the affected staff members credentials, revoke active sessions, and review what data or systems may have been accessed.", "status": "Waiting", "group": "default"},

        {"title": "Notify staff and issue security awareness reminder", "description": "Notify all support staff of the social engineering attempt. Issue a security awareness reminder covering how to identify and report phishing and pretexting attempts.", "status": "Waiting", "group": "default"},

        {"title": "Post-incident review and close case", "description": "Document the full timeline of the social engineering attempt, staff response, and any remediation steps taken. Update the playbook and close the case with a full summary note.", "status": "Waiting", "group": "default"},

    ],


    # Unauthorised access tasks — covers WAF detections and API abuse

    "category:unauthorised_access": [

        {"title": "Confirm unauthorised access attempt and identify endpoint", "description": "Review the WAF alert that triggered this case. Confirm the unauthorised access attempt is genuine and identify exactly which player data API endpoint was targeted.", "status": "Waiting", "group": "default"},

        {"title": "Identify source IPs and attack pattern", "description": "Extract all source IPs involved in the unauthorised access attempt. Determine if this is a targeted attack, automated scanning, or API key abuse.", "status": "Waiting", "group": "default"},

        {"title": "Run Cortex analyser on suspicious IPs and URLs", "description": "Add all source IPs and targeted URLs as observables and run the SOCEnrichment analyser via Cortex. Review the analysis report for risk level and recommendations.", "status": "Waiting", "group": "default"},

        {"title": "Correlate IOCs in MISP", "description": "Export all source IPs, URLs, and any API keys involved to MISP. Check against existing threat intelligence for known API abuse campaigns.", "status": "Waiting", "group": "default"},

        {"title": "Assess if player data was successfully accessed", "description": "Analyse API gateway and database logs to determine if any player data was successfully retrieved during the attack. Identify the number of player records potentially exposed.", "status": "Waiting", "group": "default"},

        {"title": "Block attacker IPs and rotate compromised API keys", "description": "Add all confirmed attacker IPs to the WAF and firewall block list immediately. If any API keys were abused or exposed, rotate them immediately.", "status": "Waiting", "group": "default"},

        {"title": "Assess data breach notification requirement", "description": "If player data was confirmed to have been accessed, assess whether this constitutes a reportable data breach under GDPR. Escalate to SOC manager and legal team immediately if notification is required.", "status": "Waiting", "group": "default"},

        {"title": "Harden API security on affected endpoints", "description": "Work with the development team to implement additional controls on the affected endpoints including stricter authentication, rate limiting, and input validation.", "status": "Waiting", "group": "default"},

        {"title": "Post-incident review and close case", "description": "Document the full timeline of the unauthorised access attempt, data exposure assessment, and containment actions. Update the API security playbook and close the case.", "status": "Waiting", "group": "default"},

    ],


    # Malware tasks — covers EDR detections on game server infrastructure

    "category:malware": [

        {"title": "Confirm malware detection and identify affected server", "description": "Review the EDR alert that triggered this case. Confirm the detection is genuine and identify the affected game server node and malware family if known.", "status": "Waiting", "group": "default"},

        {"title": "Isolate affected server from network", "description": "Immediately isolate the affected game server node from the rest of the network to prevent lateral movement. Document the time of isolation and any services affected.", "status": "Waiting", "group": "default"},

        {"title": "Collect and preserve forensic evidence", "description": "Collect a full memory dump and disk image of the affected server before any remediation. Preserve all relevant logs including EDR telemetry and network connection history.", "status": "Waiting", "group": "default"},

        {"title": "Analyse malware sample and extract IOCs", "description": "Submit the malware sample to the SOCEnrichment analyser via Cortex. Extract all IOCs including file hashes, C2 IP addresses, malicious domains, and persistence mechanisms.", "status": "Waiting", "group": "default"},

        {"title": "Run Cortex analyser on extracted IOCs", "description": "Add all extracted IOCs as observables and run the SOCEnrichment analyser via Cortex. Review the analysis report for risk level and any known threat actor attribution.", "status": "Waiting", "group": "default"},

        {"title": "Correlate IOCs in MISP", "description": "Export all extracted IOCs to MISP. Check against existing threat intelligence for known malware families or threat actors targeting gaming platforms.", "status": "Waiting", "group": "default"},

        {"title": "Scan all other servers for indicators of compromise", "description": "Using the extracted IOCs, scan all other game server nodes across both data centres for signs of the same malware or lateral movement.", "status": "Waiting", "group": "default"},

        {"title": "Eradicate malware and restore affected server", "description": "Eradicate the malware from the affected server once forensic evidence is collected. Rebuild from a known clean backup if full eradication cannot be confirmed.", "status": "Waiting", "group": "default"},

        {"title": "Patch vulnerability used for initial access", "description": "Identify how the malware gained initial access to the server. Work with the infrastructure team to patch the exploited vulnerability across all affected systems.", "status": "Waiting", "group": "default"},

        {"title": "Post-incident review and close case", "description": "Document the full timeline of the malware infection, forensic findings, and containment steps. Update the malware response playbook with new IOCs and lessons learned.", "status": "Waiting", "group": "default"},

    ],


    # Credential stuffing tasks — specific to matchmaking API attacks

    # Uses the legacy tag format from manually created cases

    "credential-stuffing": [

        {"title": "Confirm credential stuffing attack and identify scale", "description": "Review the IDS alert that triggered this case. Confirm the attack is genuine credential stuffing and not legitimate login traffic. Identify the volume of attempts, the time window, and whether any attempts were successful.", "status": "Waiting", "group": "default"},

        {"title": "Extract all attacker IPs and user agents", "description": "Extract all source IPs and user agent strings involved in the credential stuffing attack. Look for patterns such as rotating IPs, headless browser signatures, or known credential stuffing tool fingerprints like Sentry MBA or SNIPR.", "status": "Waiting", "group": "default"},

        {"title": "Run Cortex analyser on attacker IPs", "description": "Add all identified attacker IPs as observables and run the SOCEnrichment analyser via Cortex. Review the analysis report for risk level, confidence score, and any known credential stuffing infrastructure or botnet attribution.", "status": "Waiting", "group": "default"},

        {"title": "Identify successfully compromised accounts", "description": "Cross-reference the attacker IP requests against successful authentication logs. Identify every player account that was successfully logged into during the attack window. These accounts must be treated as fully compromised.", "status": "Waiting", "group": "default"},

        {"title": "Correlate IOCs in MISP", "description": "Export all attacker IPs, user agents, and any credential stuffing tool indicators to MISP. Check against existing threat intelligence for known credential stuffing campaigns targeting gaming platforms.", "status": "Waiting", "group": "default"},

        {"title": "Block attacker IPs at perimeter", "description": "Add all confirmed attacker IPs to the edge firewall and WAF block list immediately. Implement IP reputation blocking if available. Document all IPs blocked with timestamps and firewall rule references.", "status": "Waiting", "group": "default"},

        {"title": "Force reset all compromised player accounts", "description": "Immediately invalidate all active sessions for every account identified as successfully compromised. Force a password reset and flag the accounts for enhanced monitoring.", "status": "Waiting", "group": "default"},

        {"title": "Implement rate limiting on matchmaking API authentication", "description": "Work with the development team to implement strict rate limiting on the matchmaking API authentication endpoint. Recommend CAPTCHA, device fingerprinting, or multi-factor authentication.", "status": "Waiting", "group": "default"},

        {"title": "Notify affected players", "description": "Send security notification emails to all players whose accounts were successfully compromised. Advise them to change passwords, enable two-factor authentication, and check for unauthorised in-game purchases.", "status": "Waiting", "group": "default"},

        {"title": "Check for credential database exposure", "description": "Investigate whether the credentials used in the attack came from a known data breach or dark web leak. Check HaveIBeenPwned or internal breach monitoring for leaked Catnip Games player credentials.", "status": "Waiting", "group": "default"},

        {"title": "Post-incident review and close case", "description": "Document the full timeline of the credential stuffing attack, accounts compromised, containment actions, and API hardening steps. Update the credential stuffing playbook and close the case.", "status": "Waiting", "group": "default"},

    ],


    # Data exfiltration tasks — covers unusual outbound transfers detected by SIEM

    "category:data_exfiltration": [

        {"title": "Confirm unusual data transfer and identify source", "description": "Review the SIEM alert that triggered this case. Confirm the unusual data transfer is genuine and not a scheduled backup. Identify the source system, destination IP, and transfer volume.", "status": "Waiting", "group": "default"},

        {"title": "Identify what data was transferred", "description": "Analyse database query logs and network traffic to determine exactly what data was transferred. Identify the database tables involved and whether sensitive player information was included.", "status": "Waiting", "group": "default"},

        {"title": "Identify the exfiltration method and attacker infrastructure", "description": "Determine how the data was exfiltrated and identify the destination IP addresses and any intermediate infrastructure used in the transfer.", "status": "Waiting", "group": "default"},

        {"title": "Run Cortex analyser on destination IPs and domains", "description": "Add all destination IPs and domains as observables and run the SOCEnrichment analyser via Cortex. Review the analysis report for risk level and known malicious infrastructure.", "status": "Waiting", "group": "default"},

        {"title": "Correlate IOCs in MISP", "description": "Export all destination IPs, domains, and compromised account IOCs to MISP. Check against existing threat intelligence for known data exfiltration infrastructure.", "status": "Waiting", "group": "default"},

        {"title": "Contain the exfiltration immediately", "description": "Block all identified destination IPs and domains at the firewall immediately. Revoke access for any compromised service accounts involved in the transfer.", "status": "Waiting", "group": "default"},

        {"title": "Assess full scope of data exposure", "description": "Conduct a thorough review of all database access logs. Determine the full scope of data exposed including exact record counts, data types, and affected player accounts.", "status": "Waiting", "group": "default"},

        {"title": "Assess GDPR and data breach notification requirement", "description": "Determine whether this constitutes a reportable data breach under GDPR. If personal data of EU players was involved, a 72-hour notification window may apply. Escalate immediately.", "status": "Waiting", "group": "default"},

        {"title": "Notify affected players if required", "description": "If player personal data was confirmed to have been exfiltrated, prepare and send breach notification communications to affected players.", "status": "Waiting", "group": "default"},

        {"title": "Harden database and network security controls", "description": "Implement additional controls to prevent recurrence including database activity monitoring, stricter service account permissions, and enhanced SIEM rules.", "status": "Waiting", "group": "default"},

        {"title": "Post-incident review and close case", "description": "Document the full timeline of the data exfiltration, scope of data exposed, containment actions, and regulatory notifications. Update the playbook and close the case.", "status": "Waiting", "group": "default"},

    ],

}



def get_all_cases():

    """

    Fetches all cases from TheHive using the query API.

    Returns a list of case objects, or an empty list if the request fails.

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



def get_existing_tasks(case_id):

    """

    Fetches the titles of all tasks already attached to a case.

    Used to check for duplicates before adding new tasks —

    if a task title already exists on the case it will be skipped.

    This makes the script safe to run multiple times without creating

    duplicate tasks.

    """

    response = requests.post(

        f"{THEHIVE_URL}/api/v1/query",

        headers=headers,

        json={"query": [{"_name": "listTask"}, {"_name": "filter", "_field": "_parent", "_value": case_id}]},

        verify=False

    )

    if response.status_code == 200:

        return [t.get("title") for t in response.json()]

    return []



def get_tasks_for_case(tags):

    """

    Looks up the correct task list for a case based on its tags.

    Iterates through all tags on the case, normalises them to lowercase

    with spaces removed, then checks against the TAG_TASK_MAPPING dictionary.

    Returns the first matching task list found, or an empty list if no

    category tag matches any entry in the mapping.

    """

    for tag in tags:

        # Normalise tag: lowercase, strip whitespace, remove spaces

        # This handles variations like "category: Bot_Attack" vs "category:Bot_Attack"

        tag_lower = tag.lower().strip().replace(" ", "")

        if tag_lower in TAG_TASK_MAPPING:

            return TAG_TASK_MAPPING[tag_lower]

    return []



def add_task_to_case(case_id, task):

    """

    Adds a single task to a case via the TheHive API.

    Returns True if successful, False otherwise.

    """

    response = requests.post(

        f"{THEHIVE_URL}/api/v1/case/{case_id}/task",

        headers=headers,

        json=task,

        verify=False

    )

    return response.status_code in [200, 201]



# ── Main execution ────────────────────────────────────────────────────────────

print("=" * 60)

print("CATNIP GAMES SOC - TAG BASED TASK INJECTION")

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

        case_id    = case.get("_id")

        case_number = case.get("number")

        case_title  = case.get("title")

        case_tags   = case.get("tags", [])


        print(f"[→] Case #{case_number}: {case_title}")

        print(f"    Tags: {case_tags}")


        # Step 3: Look up the correct tasks for this case's category tag

        tasks = get_tasks_for_case(case_tags)

        if not tasks:

            print(f"    [!] No matching tasks found for tags\n")

            continue


        # Step 4: Get tasks already on this case to avoid duplicates

        existing = get_existing_tasks(case_id)

        success_count = 0

        skipped = 0


        # Step 5: Add each task, skipping any that already exist

        for task in tasks:

            if task['title'] in existing:

                skipped += 1

                continue

            if add_task_to_case(case_id, task):

                print(f"    [+] Added task: {task['title']}")

                success_count += 1

                total_added += 1

            else:

                print(f"    [!] Failed: {task['title']}")


        if skipped > 0:

            print(f"    [~] Skipped {skipped} duplicate tasks")

        print(f"    [✓] {success_count} new tasks added\n")


print("=" * 60)

print(f"Complete! Total tasks added: {total_added}")

print("Refresh TheHive to verify.")

print("=" * 60)
