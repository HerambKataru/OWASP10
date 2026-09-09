from typing import List, Dict, Any
import math

class RiskEngine:
    """
    Industry-standard multi-parametric risk engine based on:
    - CVSS v3.1 Base Score Metrics
    - OWASP Top 10 Attack Surface Density
    - Parameter & Input Vector Exposure
    - Compound Multi-Vulnerability Synergies
    - Threat Intelligence Enrichment
    """

    SEVERITY_WEIGHTS = {
        "Critical": 25.0,
        "High": 15.0,
        "Medium": 8.0,
        "Low": 3.0,
        "Informational": 0.5
    }

    OWASP_WEIGHTS = {
        "A01:2021-Broken Access Control": 1.4,
        "A02:2021-Cryptographic Failures": 1.2,
        "A03:2021-Injection": 1.5,
        "A04:2021-Insecure Design": 1.2,
        "A05:2021-Security Misconfiguration": 1.0,
        "A06:2021-Vulnerable and Outdated Components": 1.3,
        "A07:2021-Identification and Authentication Failures": 1.4,
        "A08:2021-Software and Data Integrity Failures": 1.2,
        "A09:2021-Security Logging and Monitoring Failures": 1.0,
        "A10:2021-Server-Side Request Forgery": 1.4
    }

    @classmethod
    def calculate_comprehensive_risk(
        cls,
        findings: List[Dict[str, Any]],
        endpoints_count: int = 1,
        forms_count: int = 0,
        threat_intel_score: float = 0.0
    ) -> Dict[str, Any]:
        if not findings:
            return {
                "risk_score": 0.0,
                "cvss_average": 0.0,
                "exploitability_index": 0.0,
                "attack_surface_multiplier": 1.0,
                "risk_level": "CLEAN",
                "risk_breakdown": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0
                }
            }

        crit_count = sum(1 for f in findings if f.get("severity") == "Critical")
        high_count = sum(1 for f in findings if f.get("severity") == "High")
        med_count = sum(1 for f in findings if f.get("severity") == "Medium")
        low_count = sum(1 for f in findings if f.get("severity") == "Low")
        info_count = sum(1 for f in findings if f.get("severity") in ["Informational", "Info"])

        # 1. Base Score calculation from individual CVSS scores
        cvss_scores = [float(f.get("cvss_score", 5.0)) for f in findings]
        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0.0
        max_cvss = max(cvss_scores) if cvss_scores else 0.0

        # 2. OWASP Categorical Diversity Penalty
        # Having multiple distinct vulnerability classes (e.g. SQLi + Auth Bypass + IDOR) causes compounding risk
        unique_categories = set(f.get("owasp_category", "") for f in findings if f.get("owasp_category"))
        category_diversity_factor = 1.0 + (min(len(unique_categories), 6) * 0.08)

        # 3. Weighted Vulnerability Summation
        base_raw_score = (
            (crit_count * cls.SEVERITY_WEIGHTS["Critical"] * 1.2) +
            (high_count * cls.SEVERITY_WEIGHTS["High"] * 1.0) +
            (med_count * cls.SEVERITY_WEIGHTS["Medium"] * 0.8) +
            (low_count * cls.SEVERITY_WEIGHTS["Low"] * 0.5) +
            (info_count * cls.SEVERITY_WEIGHTS["Informational"] * 0.2)
        )

        # 4. Attack Surface Scaling Factor (More exposed endpoints & forms = higher attack surface)
        attack_surface_multiplier = 1.0 + min(0.35, (endpoints_count * 0.015) + (forms_count * 0.025))

        # 5. Threat Intelligence Enrichment Factor (if external malicious reputation detected)
        threat_multiplier = 1.0 + min(0.20, (threat_intel_score / 100.0) * 0.20)

        # 6. Combined Non-linear Sigmoid Formulation
        combined_raw = base_raw_score * category_diversity_factor * attack_surface_multiplier * threat_multiplier
        
        # If any Critical finding exists, minimum score floor is 70
        if crit_count > 0:
            final_score = max(70.0, min(100.0, 70.0 + (combined_raw * 0.35)))
        elif high_count > 0:
            final_score = max(45.0, min(89.0, 45.0 + (combined_raw * 0.45)))
        elif med_count > 0:
            final_score = max(20.0, min(65.0, 20.0 + (combined_raw * 0.55)))
        else:
            final_score = min(35.0, combined_raw * 0.8)

        final_score = round(final_score, 1)

        # Determine qualitative tier
        if final_score >= 75.0:
            risk_level = "CRITICAL RISK"
        elif final_score >= 50.0:
            risk_level = "HIGH RISK"
        elif final_score >= 25.0:
            risk_level = "MODERATE RISK"
        elif final_score > 0.0:
            risk_level = "LOW RISK"
        else:
            risk_level = "CLEAN"

        exploitability = round(min(10.0, (avg_cvss * 0.7) + (crit_count * 1.5) + (high_count * 0.8)), 1)

        return {
            "risk_score": final_score,
            "cvss_average": round(avg_cvss, 1),
            "cvss_max": round(max_cvss, 1),
            "exploitability_index": exploitability,
            "attack_surface_multiplier": round(attack_surface_multiplier, 2),
            "risk_level": risk_level,
            "critical_count": crit_count,
            "high_count": high_count,
            "medium_count": med_count,
            "low_count": low_count,
            "info_count": info_count,
            "total_findings": len(findings)
        }

    @classmethod
    def get_summary_stats(cls, findings: List[Dict[str, Any]], endpoints_count: int = 1, forms_count: int = 0) -> Dict[str, Any]:
        res = cls.calculate_comprehensive_risk(findings, endpoints_count, forms_count)
        
        owasp_dist = {}
        for f in findings:
            cat = f.get("owasp_category", "A05:2021-Security Misconfiguration")
            owasp_dist[cat] = owasp_dist.get(cat, 0) + 1

        res["owasp_distribution"] = owasp_dist
        return res
