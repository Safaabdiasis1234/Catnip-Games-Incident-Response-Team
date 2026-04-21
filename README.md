# Catnip-Games-Incident-Response-Team
Cybersecurity Operations

## Tools & Technologies
TheHive incident management, MISP threat intelligence, Cortex analysers, Elasticsearch log management, Docker/container orchestration, Linux system administration, Git version control, Automation frameworks

## Abilities
Incident handling and triage, Process documentation, Alert correlation analysis, Metric development, Team coordination, Technical writing, Training development, Time management
 
## Tasks:
- [705] Manage security monitoring for situational awareness
- [824] Recognise and report security violations
- [852] Supervise protective/corrective measures for incidents
- [707] Manage threat analysis and threat information production

## Technology Stack
- TheHive for case management
- MISP for threat intelligence
- Cortex for automation
- Elasticsearch for logging
- Python for custom integrations
- Git for version control

## File Structure
~/catnip-soc/: home directory
- docker-compose.yml: Docker Compose configuration for TheHive 5, Cortex, MISP, Elasticsearch, Cassandra, MinIO, MySQL, and Redis
- run_demo.sh: generate new incidents, inject tasks, and automate example categorisation
- analyzers/
- - GameThreat_1_0: GameThreat analyser container, which checks IPs, domains, and URLs against an internal Catnip Games threat blocklist
**game_threat.py: analyser script
- - CatnipVT_1_0: CatnipVT analyser container, which uses the VirusTotal v3 API and handles hashes, IPs, domains, and URLs
**catnip_vt.py: analyser script
- cortex/
- - application.conf: Cortex configuration file (not provided)
- - logs/
- scripts/
- - add_tasks.py: maps each of the six incident categories to an ordered investigation task list
- - generate_cases.py: creates six Catnip Games security incidents
- - misp_lookup.py: queries MISP’s /attributes/restSearch endpoint for every observable on every case
- - tag_based_ttps.py: maps categories to MITRE ATT&CK technique IDs
- - thehive_writeback.py: closes the automation loop by reading completed Cortex results and writing them back to TheHive cases automatically

## Roles
- Baris: Infrastructure, Deployment, Analysers (configuring a Hive-Cortex-MISP environemnt, creating custom analysers in Cortex)
- Sawsan: Playbook, Investigation Procedures (creating a complete incident response playbook for each scenario covered)
- Safa: Case Generation, Writeback Engine (testing the framework with generated incidents and implementing an automated writeback for Cortex results)
- Rhaishah: Task Injection, MITRE ATT&CK, MISP Integration (programming three scripts to automate case assignment, map techniques, and check against MISP database
- Anay: SCRUM Master, GitHub, Documentation

## Set Up : see Implementation_Configuration_Guide.md
