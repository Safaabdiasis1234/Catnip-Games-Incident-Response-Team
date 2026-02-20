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

# Passive (template for resolving in-place security risks such as potential password compromises or data leaks)
## Purpose and scope: (def objectives and extent of application)
Objectives:
- Outline the severity levels of various passive threats (i.e. unexploited bugs, compromised passwords, unsecure data points)
- Develop standardised regulatory framework of i) documenting these weaknesses, ii) resolving the issues, and iii) reviewing and improving security protocol
- Constructing communication pathways and regulation for collaboration between different teams and responsible threat response
Extent:
- Maintaining existing security
## Roles and responsibilities: (def who is responsible for each aspect)
- Security Operations Team
  - SOC Manager
  - Analysts
## Incident response phases: 
### Prepartion: (readiness measures)
- Deployed MISP, Cortex, Elasticsearch
- Patch testing
- Team training on tools and regulations
### Detection & Analysis: (+ triage workflows)
- Automated logging on common MISP events
- Python scripting and Cortex dashboard for visual alert systems, to be monitored and categorised by SOT Analysts
- Critical to be handled immediately. High to be handled as soon as possible. Mediums and Lows can be triaged, but after a period of XX time, to be reassessed on severity. 
### Containment, eradication, recovery: (management and resoration)
- SOC Manager assigns Analysts tasks and cases via TheHive. SOC Manager may feel the need to communicate and escalate the task to PR, GameDev, or other such teams
- Strategies to be taken specifically in response to type of weakness
### Post-Incident: (review, improvements)
- SOC Manager hosts a review with members involved, going through incident documentation and timeline
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
