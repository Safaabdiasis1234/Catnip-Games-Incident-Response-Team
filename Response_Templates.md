# Active (template for live incidents, attacks, or activity such as botting or social engineering attempts)
## Purpose and scope: (def objectives and extent of application)
Objectives:
- Outline the severity levels of various active threats (i.e. malware, botting, phishing)
- Develop standardised regulatory framework of i) documenting these threats, ii) responding and countering the damage, and iii) reviewing and improving security protocol
- Constructing communication pathways and regulation for collaboration between different teams and responsible threat management
Extent:
- Reactionary to live security challenges
## Roles and responsibilities: (def who is responsible for each aspect)
- Security Operations Team
  - SOC Manager
  - Analysts
## Incident response phases: 
### Prepartion: (readiness measures)
- Deployed MISP, Cortex, Elasticsearch
- Team training on tools and regulations
### Detection & Analysis: (+ triage workflows)
- Automated logging on common MISP events
- Python scripting and Cortex dashboard for visual alert systems, to be monitored and categorised by SOT Analysts
- Critical to be handled immediately. High to be handled as soon as possible. Mediums and Lows can be triaged, but after a period of XX time, to be reassessed on severity. 
### Containment, eradication, recovery: (management and resoration)
- SOC Manager assigns Analysts tasks and cases via TheHive.
- Strategies to be taken specifically in response to type of attack
### Post-Incident: (review, improvements)
- SOC Manager hosts a review with Analysts involved, going through incident documentation and timeline
- Improvements to process to be implemented. Patch update if needed
## Communication Protocols: (internal and external communication paths, regulatory reporting requirements, escalation measures)
- Internal: Analysts standarise alert systems and incident logging. Analysts categorise threats to report to TheHive, SOC Manager monitors TheHive to assign cases. Critical and High threats are reported immediately to SOC Manager, via in-person or phone at XXXXX. SOC Manager will relay tasks.
- External: During resolution or post-incident, Analysts may confirm necessary communication to other teams or the playerbase. SOC Manager will commuicate with other team managers. SOC Manager and Analysts will report to PR Team for communication to playerbase.
## Severity Levels: (+ response times)
- Critical: Must be handled immediately, else drastic data breach, game corruption, or similar consequences will occur.
- High: Must be handled as soon as possible. Defined as exploited game mechanics, bot activity, social engineering attempts
- Medium: Handled as soon as possible. Defined as general suspicious activity, or activity that has potential to escalate.
- Low: Handled whenever possible. Defined as average, mildly suspicious activity.
## Documention & Reporting: (regulation on what needs to be reported, how to document timelines)
- Categorise threats based on MISP events.
- Timestamps on each phase
- Will be specified based on threat

# For Incident in particular
## Detection & Trigger
- trigger conditions (dependent on python scripts)
- how/where to view the conditions (directions for the Analysts)
## Inital Triage 
- verify the incident
- inital check for severity
- scope out observables and information to populate a TheHive case
- decision tree on containment, eradication, recovery
## Severity Classification
- list out the levels of severity (critical, high, medium, low)
- list out what actions to take dependent on level
## Containment
- immediate actions that contain the incident and prevent escalation
## Investigation
- what sort of review, investigative measures can be taken
- any specific information needed to log or identified
## Eradication
- policies and actions that neutralize and prevent the incident
## Recovery
- fix damage caused by incident
- any future monitoring actions
- any confirmation of following actions
## Post-incident Review 
- take stock on any lasting damage
- improve on any protocol
