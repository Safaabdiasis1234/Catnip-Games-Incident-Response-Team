#!/usr/bin/env python3

"""
CatnipVT Analyser v1.0 — Catnip Games SOC
Enriches observables using the VirusTotal v3 API.

Supports: file hashes (MD5, SHA1, SHA256), IP addresses, domains, and URLs.

USAGE:
    Trigger from TheHive → Observables tab → analyser icon → CatnipVT

CONFIGURATION:
    Add your VirusTotal API key in Cortex:
    Analysers → CatnipVT → Configuration → vt_api_key
    Free API key: https://www.virustotal.com/gui/join-us

"""


import base64

from datetime import datetime, timezone

from cortexutils.analyzer import Analyzer


try:

    import requests

except ImportError:

    requests = None


THRESHOLD_HIGH   = 5

THRESHOLD_MEDIUM = 1



class CatnipVTAnalyzer(Analyzer):


    def get_vt_api_key(self):

        return self.get_param("config.vt_api_key", None)


    def vt_request(self, endpoint):

        api_key = self.get_vt_api_key()

        if not api_key:

            return None, "No VirusTotal API key configured. Add vt_api_key in Cortex analyser settings."

        try:

            response = requests.get(

                f"https://www.virustotal.com/api/v3/{endpoint}",

                headers={

                    "x-apikey": api_key,

                    "Accept": "application/json",

                },

                timeout=30,

            )

            if response.status_code == 200:

                return response.json(), None

            elif response.status_code == 404:

                return None, "not_found"

            elif response.status_code == 401:

                return None, "Invalid VirusTotal API key — check configuration in Cortex."

            elif response.status_code == 429:

                return None, "VirusTotal API rate limit reached. Free tier allows 4 requests/minute."

            else:

                return None, f"VirusTotal API error: HTTP {response.status_code}"

        except requests.exceptions.Timeout:

            return None, "VirusTotal request timed out after 30 seconds."

        except requests.exceptions.ConnectionError:

            return None, "Could not connect to VirusTotal API — check network connectivity."

        except Exception as e:

            return None, f"Unexpected error: {str(e)}"


    def determine_risk(self, malicious, suspicious, total):

        if total == 0:

            return "Unknown", 0

        confirmed = malicious

        possible  = malicious + suspicious

        if confirmed >= THRESHOLD_HIGH:

            risk  = "High"

            score = min(100, int((confirmed / max(total, 1)) * 100))

        elif possible >= THRESHOLD_MEDIUM:

            risk  = "Medium"

            score = min(75, int((possible / max(total, 1)) * 100))

        else:

            risk  = "Low"

            score = 0

        return risk, score


    def extract_threat_names(self, analysis_results, limit=8):

        names = []

        generic_terms = {"generic", "heuristic", "suspicious", "malware", "trojan",

                         "unwanted", "potentially", "riskware", "unsafe"}

        for engine, result in analysis_results.items():

            if result.get("category") in ("malicious", "suspicious"):

                name = result.get("result", "")

                if name and not any(g in name.lower() for g in generic_terms):

                    names.append(name)

        seen   = set()

        unique = []

        for n in names:

            if n not in seen:

                seen.addNo

                unique.appendNo

        return unique[:limit]


    def analyse_hash(self, file_hash):

        data, error = self.vt_request(f"files/{file_hash}")

        if error == "not_found":

            return {

                "found": False,

                "risk_level": "Unknown",

                "confidence": 0,

                "message": "Hash not found in VirusTotal database. File may be novel/unseen.",

                "recommendations": [

                    "Submit the file to VirusTotal for analysis if safe to do so",

                    "Treat as suspicious — absence of detection does not confirm safety",

                    "Continue investigation using behavioural analysis",

                ]

            }

        if error:

            return {"error": error, "found": False, "risk_level": "Unknown", "confidence": 0}


        attributes = data.get("data", {}).get("attributes", {})

        stats      = attributes.get("last_analysis_stats", {})

        malicious  = stats.get("malicious", 0)

        suspicious = stats.get("suspicious", 0)

        undetected = stats.get("undetected", 0)

        total      = malicious + suspicious + undetected + stats.get("harmless", 0)

        risk, confidence = self.determine_risk(malicious, suspicious, total)

        found            = malicious > 0 or suspicious > 0

        analysis_results = attributes.get("last_analysis_results", {})

        threat_names     = self.extract_threat_names(analysis_results)

        file_type        = attributes.get("type_description", "unknown")

        file_size        = attributes.get("size", 0)

        first_seen       = attributes.get("first_submission_date")

        last_seen        = attributes.get("last_analysis_date")

        meaningful_name  = attributes.get("meaningful_name", "")

        first_seen_str   = datetime.fromtimestamp(first_seen, tz=timezone.utc).strftime("%Y-%m-%d") if first_seen else "unknown"

        last_seen_str    = datetime.fromtimestamp(last_seen, tz=timezone.utc).strftime("%Y-%m-%d") if last_seen else "unknown"


        result = {

            "found":            found,

            "risk_level":       risk,

            "confidence":       confidence,

            "detection":        f"{malicious}/{total} engines",

            "malicious":        malicious,

            "suspicious":       suspicious,

            "undetected":       undetected,

            "total_engines":    total,

            "threat_names":     threat_names,

            "file_type":        file_type,

            "file_size_bytes":  file_size,

            "meaningful_name":  meaningful_name,

            "first_seen":       first_seen_str,

            "last_seen":        last_seen_str,

            "vt_link":          f"https://www.virustotal.com/gui/file/{file_hash}",

        }

        if risk == "High":

            result["recommendations"] = [

                f"File confirmed malicious by {malicious} AV engines — treat as active threat",

                "Isolate any system where this file was found immediately",

                "Cross-reference threat names against MITRE ATT&CK for known TTPs",

                "Export hash to MISP for community sharing",

                "Review process execution logs for this binary on all game servers",

            ]

        elif risk == "Medium":

            result["recommendations"] = [

                f"File flagged as suspicious by {suspicious} engines — investigate further",

                "Do not execute on any production system",

                "Submit to sandbox for behavioural analysis",

                "Correlate with other observables in the case",

            ]

        else:

            result["recommendations"] = [

                "No detections on VirusTotal — file may be clean or novel",

                "Absence of detection does not confirm safety for novel malware",

                "Consider sandbox analysis if the file origin is untrusted",

            ]

        return result


    def analyse_ip(self, ip):

        data, error = self.vt_request(f"ip_addresses/{ip}")

        if error:

            return {"error": error, "found": False, "risk_level": "Unknown", "confidence": 0}


        attributes = data.get("data", {}).get("attributes", {})

        stats      = attributes.get("last_analysis_stats", {})

        malicious  = stats.get("malicious", 0)

        suspicious = stats.get("suspicious", 0)

        total      = sum(stats.values())

        risk, confidence = self.determine_risk(malicious, suspicious, total)

        found      = malicious > 0 or suspicious > 0

        country    = attributes.get("country", "unknown")

        asn        = attributes.get("asn", "unknown")

        as_owner   = attributes.get("as_owner", "unknown")

        rep_score  = attributes.get("reputation", 0)


        result = {

            "found":              found,

            "risk_level":         risk,

            "confidence":         confidence,

            "detection":          f"{malicious}/{total} engines",

            "malicious":          malicious,

            "suspicious":         suspicious,

            "country":            country,

            "asn":                asn,

            "as_owner":           as_owner,

            "reputation_score":   rep_score,

            "vt_link":            f"https://www.virustotal.com/gui/ip-address/{ip}",

        }

        if risk == "High":

            result["recommendations"] = [

                f"IP flagged malicious by {malicious} engines — block at perimeter firewall",

                "Review all player account sessions originating from this IP",

                "Export to MISP for community sharing",

                "Cross-reference with GameThreat internal blocklist results",

            ]

        elif risk == "Medium":

            result["recommendations"] = [

                "IP flagged suspicious — monitor and correlate with other case observables",

                "Check for unusual login patterns from this IP in authentication logs",

            ]

        else:

            result["recommendations"] = [

                "IP not flagged on VirusTotal — check GameThreat internal blocklist results",

                "Consider Shodan lookup for open port and service information",

            ]

        return result


    def analyse_domain(self, domain):

        data, error = self.vt_request(f"domains/{domain}")

        if error == "not_found":

            return {

                "found": False,

                "risk_level": "Unknown",

                "confidence": 0,

                "message": "Domain not found in VirusTotal database.",

                "recommendations": ["Domain has no VirusTotal history — may be newly registered"]

            }

        if error:

            return {"error": error, "found": False, "risk_level": "Unknown", "confidence": 0}


        attributes   = data.get("data", {}).get("attributes", {})

        stats        = attributes.get("last_analysis_stats", {})

        malicious    = stats.get("malicious", 0)

        suspicious   = stats.get("suspicious", 0)

        total        = sum(stats.values())

        risk, confidence = self.determine_risk(malicious, suspicious, total)

        found        = malicious > 0 or suspicious > 0

        registrar    = attributes.get("registrar", "unknown")

        creation_date = attributes.get("creation_date")

        rep_score    = attributes.get("reputation", 0)

        categories   = attributes.get("categories", {})

        cat_values   = list(set(categories.values()))[:5] if categories else []

        creation_str = datetime.fromtimestamp(creation_date, tz=timezone.utc).strftime("%Y-%m-%d") if creation_date else "unknown"


        result = {

            "found":              found,

            "risk_level":         risk,

            "confidence":         confidence,

            "detection":          f"{malicious}/{total} engines",

            "malicious":          malicious,

            "suspicious":         suspicious,

            "registrar":          registrar,

            "creation_date":      creation_str,

            "reputation_score":   rep_score,

            "categories":         cat_values,

            "vt_link":            f"https://www.virustotal.com/gui/domain/{domain}",

        }

        if risk == "High":

            result["recommendations"] = [

                f"Domain confirmed malicious by {malicious} engines — block at DNS and proxy",

                "Check if any staff or player traffic has reached this domain",

                "Export to MISP for community sharing",

            ]

        elif risk == "Medium":

            result["recommendations"] = [

                "Domain flagged suspicious — investigate registrant and hosting details",

                "Check for lookalike characteristics against legitimate Catnip Games domains",

            ]

        else:

            result["recommendations"] = [

                "Domain not flagged on VirusTotal",

                "Check GameThreat internal blocklist for gaming-specific intelligence",

            ]

        return result


    def analyse_url(self, url):

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        data, error = self.vt_request(f"urls/{url_id}")

        if error == "not_found":

            return {

                "found": False,

                "risk_level": "Unknown",

                "confidence": 0,

                "message": "URL not found in VirusTotal database.",

                "recommendations": ["URL has no scan history — submit for analysis if safe to do so"]

            }

        if error:

            return {"error": error, "found": False, "risk_level": "Unknown", "confidence": 0}


        attributes = data.get("data", {}).get("attributes", {})

        stats      = attributes.get("last_analysis_stats", {})

        malicious  = stats.get("malicious", 0)

        suspicious = stats.get("suspicious", 0)

        total      = sum(stats.values())

        risk, confidence = self.determine_risk(malicious, suspicious, total)

        found      = malicious > 0 or suspicious > 0

        final_url  = attributes.get("last_final_url", url)

        title      = attributes.get("title", "")

        rep_score  = attributes.get("reputation", 0)


        result = {

            "found":            found,

            "risk_level":       risk,

            "confidence":       confidence,

            "detection":        f"{malicious}/{total} engines",

            "malicious":        malicious,

            "suspicious":       suspicious,

            "final_url":        final_url,

            "page_title":       title,

            "reputation_score": rep_score,

            "vt_link":          f"https://www.virustotal.com/gui/url/{url_id}",

        }

        if risk == "High":

            result["recommendations"] = [

                f"URL confirmed malicious by {malicious} engines — block at proxy and WAF",

                "Check access logs for any staff or system that reached this URL",

                "Export to MISP for community sharing",

            ]

        elif risk == "Medium":

            result["recommendations"] = [

                "URL flagged suspicious — check if it is reachable and what it serves",

                "Review web proxy logs for any internal access to this URL",

            ]

        else:

            result["recommendations"] = [

                "URL not flagged on VirusTotal",

                "Verify the URL is expected given the case context",

            ]

        return result


    def summary(self, raw):

        taxonomies = []

        level_map  = {"High": "malicious", "Medium": "suspicious", "Low": "safe", "Unknown": "info"}


        if raw.get("error"):

            taxonomies.append(self.build_taxonomy(

                level="info",

                namespace="CatnipVT",

                predicate="Error",

                value=raw["error"][:50],

            ))

            return {"taxonomies": taxonomies}


        risk  = raw.get("risk_level", "Unknown")

        level = level_map.get(risk, "info")


        if raw.get("found"):

            taxonomies.append(self.build_taxonomy(

                level=level,

                namespace="CatnipVT",

                predicate="Verdict",

                value=risk,

            ))

            if raw.get("detection"):

                taxonomies.append(self.build_taxonomy(

                    level=level,

                    namespace="CatnipVT",

                    predicate="Detections",

                    value=raw["detection"],

                ))

            if raw.get("threat_names"):

                taxonomies.append(self.build_taxonomy(

                    level=level,

                    namespace="CatnipVT",

                    predicate="ThreatFamily",

                    value=raw["threat_names"][0],

                ))

        else:

            taxonomies.append(self.build_taxonomy(

                level="safe",

                namespace="CatnipVT",

                predicate="Verdict",

                value="Clean" if raw.get("risk_level") == "Low" else "Not found",

            ))

        return {"taxonomies": taxonomies}


    def run(self):

        if not requests:

            self.error("requests library not available — check analyser Docker image")

            return


        data  = self.get_data()

        dtype = self.data_type


        base_result = {

            "observable": data,

            "data_type":  dtype,

            "checked_at": datetime.utcnow().isoformat() + "Z",

            "analyser":   "CatnipVT v1.0",

            "source":     "VirusTotal v3 API",

        }


        if not self.get_vt_api_key():

            self.report({

                **base_result,

                "error":      "No VirusTotal API key configured",

                "found":      False,

                "risk_level": "Unknown",

                "confidence": 0,

                "recommendations": [

                    "Add your VirusTotal API key in Cortex: Analysers → CatnipVT → Configuration → vt_api_key",

                    "Free API key available at: https://www.virustotal.com/gui/join-us",

                ]

            })

            return


        if dtype == "hash":

            analysis = self.analyse_hash(data)

        elif dtype == "ip":

            analysis = self.analyse_ip(data)

        elif dtype == "domain":

            analysis = self.analyse_domain(data)

        elif dtype == "url":

            analysis = self.analyse_url(data)

        else:

            self.error(f"Unsupported data type: {dtype}. CatnipVT supports: hash, ip, domain, url")

            return


        self.report({**base_result, **analysis})



if __name__ == "__main__":

    CatnipVTAnalyzer().run()
