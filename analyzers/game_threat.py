#!/usr/bin/env python3

"""
GameThreat Analyser v1.0 — Catnip Games SOC
Checks IPs/domains/URLs against an internal blocklist.
Optionally enriches with AbuseIPDB if an API key is configured.
"""

import ipaddress
from datetime import datetime
from cortexutils.analyzer import Analyzer

# ---------------------------------------------------------------------------

# Internal threat intelligence
# Replace these dicts with a real DB query, Redis lookup, or API call

# ---------------------------------------------------------------------------

KNOWN_BAD_IPS = {

    "185.220.101.45": {

        "reason": "Tor exit node — confirmed bot credential-stuffing traffic",

        "first_seen": "2024-03-10",

        "tags": ["tor", "bot", "credential-stuffing"],

        "confidence": 95,

    },

    "194.165.16.11": {

        "reason": "Bulletproof hosting — multiple bot campaigns",

        "first_seen": "2024-02-28",

        "tags": ["bulletproof-hosting", "bot"],

        "confidence": 88,

    },

    "195.208.1.101": {

        "reason": "Account takeover — impossible travel logins",

        "first_seen": "2024-03-15",

        "tags": ["ato", "impossible-travel"],

        "confidence": 72,

    },

}


KNOWN_BAD_DOMAINS = {

    "cheat-engine-api.xyz": {

        "reason": "Cheat distribution domain",

        "first_seen": "2024-01-15",

        "tags": ["cheats", "exploit"],

        "confidence": 91,

    },

    "bot-lobby.net": {

        "reason": "Bot lobby coordination domain",

        "first_seen": "2024-02-01",

        "tags": ["bot", "matchmaking-abuse"],

        "confidence": 85,

    },

}



def risk_level(confidence, tags):

    high_risk = {"credential-stuffing", "ato", "exploit"}

    if confidence >= 90 or any(t in high_risk for t in tags):

        return "High"

    elif confidence >= 60:

        return "Medium"

    return "Low"



class GameThreatAnalyzer(Analyzer):


    def summary(self, raw):

        level_map = {"High": "malicious", "Medium": "suspicious", "Low": "info"}

        taxonomies = []


        if raw.get("found"):

            risk = raw.get("risk_level", "Low")

            taxonomies.append(self.build_taxonomy(

                level=level_map.get(risk, "info"),

                namespace="GameThreat",

                predicate="Risk",

                value=risk,

            ))

            taxonomies.append(self.build_taxonomy(

                level=level_map.get(risk, "info"),

                namespace="GameThreat",

                predicate="Confidence",

                value=f"{raw.get('confidence', 0)}%",

            ))

        else:

            taxonomies.append(self.build_taxonomy(

                level="safe",

                namespace="GameThreat",

                predicate="Risk",

                value="Not in blocklist",

            ))


        if raw.get("abuseipdb"):

            score = raw["abuseipdb"].get("abuseConfidenceScore", 0)

            taxonomies.append(self.build_taxonomy(

                level="malicious" if score > 80 else "suspicious" if score > 25 else "safe",

                namespace="AbuseIPDB",

                predicate="Score",

                value=f"{score}/100",

            ))


        return {"taxonomies": taxonomies}


    def run(self):

        data = self.get_data()

        dtype = self.data_type


        result = {

            "observable": data,

            "data_type": dtype,

            "checked_at": datetime.utcnow().isoformat() + "Z",

            "found": False,

            "risk_level": "Low",

            "confidence": 0,

            "reason": None,

            "tags": [],

            "recommendations": [],

        }


        # --- Internal blocklist lookup ---

        if dtype == "ip":

            match = KNOWN_BAD_IPS.get(data)

            if match:

                result.update({

                    "found": True,

                    "confidence": match["confidence"],

                    "reason": match["reason"],

                    "tags": match["tags"],

                    "first_seen": match["first_seen"],

                    "risk_level": risk_level(match["confidence"], match["tags"]),

                })

            try:

                if ipaddress.ip_address(data).is_private:

                    result["notes"] = "Private/RFC-1918 address"

            except ValueError:

                pass


            # Optional AbuseIPDB enrichment

            api_key = self.get_param("config.abuseipdb_key", None)

            if api_key and not result.get("notes"):

                try:

                    import requests

                    resp = requests.get(

                        "https://api.abuseipdb.com/api/v2/check",

                        headers={"Key": api_key, "Accept": "application/json"},

                        params={"ipAddress": data, "maxAgeInDays": 90},

                        timeout=10,

                    )

                    if resp.status_code == 200:

                        ab = resp.json().get("data", {})

                        result["abuseipdb"] = {

                            "abuseConfidenceScore": ab.get("abuseConfidenceScore", 0),

                            "countryCode": ab.get("countryCode"),

                            "isp": ab.get("isp"),

                            "totalReports": ab.get("totalReports", 0),

                        }

                        if ab.get("abuseConfidenceScore", 0) > 80 and not result["found"]:

                            result.update({

                                "found": True,

                                "risk_level": "High",

                                "reason": f"AbuseIPDB score: {ab['abuseConfidenceScore']}/100",

                                "confidence": ab["abuseConfidenceScore"],

                            })

                except Exception as e:

                    result["abuseipdb_error"] = str(e)


        elif dtype == "domain":

            match = KNOWN_BAD_DOMAINS.get(data)

            if match:

                result.update({

                    "found": True,

                    "confidence": match["confidence"],

                    "reason": match["reason"],

                    "tags": match["tags"],

                    "first_seen": match["first_seen"],

                    "risk_level": risk_level(match["confidence"], match["tags"]),

                })


        elif dtype == "url":

            domain = data.replace("https://", "").replace("http://", "").split("/")[0]

            result["extracted_domain"] = domain

            match = KNOWN_BAD_DOMAINS.get(domain)

            if match:

                result.update({

                    "found": True,

                    "confidence": match["confidence"],

                    "reason": match["reason"],

                    "tags": match["tags"],

                    "risk_level": risk_level(match["confidence"], match["tags"]),

                })


        # Recommendations

        if result["found"]:

            if result["risk_level"] == "High":

                result["recommendations"] = [

                    "Block immediately at perimeter firewall and WAF",

                    "Review all player accounts that connected from this source",

                    "Export to MISP for community sharing",

                ]

            else:

                result["recommendations"] = [

                    "Monitor traffic from this source",

                    "Correlate with other observables in the case",

                ]

        else:

            result["recommendations"] = [

                "Not in internal blocklist — consider VirusTotal or Shodan",

            ]


        self.report(result)



if __name__ == "__main__":

    GameThreatAnalyzer().run()
